package app

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/miekg/dns"
	"github.com/teliso/DNSentry/internal/dnsname"
)

type LocalRecord struct {
	Domain string `json:"domain" yaml:"domain"`
	Type   string `json:"type" yaml:"type"`
	Value  string `json:"value" yaml:"value"`
	TTL    uint32 `json:"ttl" yaml:"ttl"`
}

type localRecordSnapshot struct {
	records map[string][]dns.RR
	// ptr holds reverse records derived from local A/AAAA records, keyed by
	// the normalized reverse name (e.g. "10.1.168.192.in-addr.arpa").
	ptr map[string][]dns.RR
}

func validateLocalRecords(records []LocalRecord) error {
	seen := make(map[string]struct{}, len(records))
	for index := range records {
		record := &records[index]
		record.Domain = dnsname.Normalize(record.Domain)
		record.Type = strings.ToUpper(strings.TrimSpace(record.Type))
		record.Value = strings.TrimSpace(record.Value)
		if !dnsname.Valid(record.Domain) {
			return fmt.Errorf("invalid local_records[%d] domain", index)
		}
		if record.TTL == 0 {
			record.TTL = 300
		}
		if record.TTL > 86400 {
			return fmt.Errorf("local_records[%d] ttl is too large", index)
		}
		key := record.Domain + "\x00" + record.Type + "\x00" + record.Value
		if _, exists := seen[key]; exists {
			return fmt.Errorf("duplicate local_records[%d]", index)
		}
		seen[key] = struct{}{}
		switch record.Type {
		case "A":
			if ip := net.ParseIP(record.Value); ip == nil || ip.To4() == nil {
				return fmt.Errorf("local_records[%d] value must be an IPv4 address", index)
			}
		case "AAAA":
			if ip := net.ParseIP(record.Value); ip == nil || ip.To4() != nil || ip.To16() == nil {
				return fmt.Errorf("local_records[%d] value must be an IPv6 address", index)
			}
		case "CNAME":
			if !dnsname.Valid(dnsname.Normalize(record.Value)) {
				return fmt.Errorf("local_records[%d] value must be a domain", index)
			}
		case "TXT":
			if record.Value == "" {
				return fmt.Errorf("local_records[%d] TXT value must not be empty", index)
			}
		default:
			return fmt.Errorf("local_records[%d] unsupported type %q: use A, AAAA, CNAME, or TXT", index, record.Type)
		}
	}
	return nil
}

func buildLocalRecordSnapshot(records []LocalRecord) *localRecordSnapshot {
	snapshot := &localRecordSnapshot{records: make(map[string][]dns.RR), ptr: make(map[string][]dns.RR)}
	for _, record := range records {
		name := dns.Fqdn(record.Domain)
		header := dns.RR_Header{Name: name, Class: dns.ClassINET, Ttl: record.TTL}
		var rr dns.RR
		switch record.Type {
		case "A":
			rr = &dns.A{Hdr: dns.RR_Header{Rrtype: dns.TypeA, Name: header.Name, Class: header.Class, Ttl: header.Ttl}, A: net.ParseIP(record.Value).To4()}
		case "AAAA":
			rr = &dns.AAAA{Hdr: dns.RR_Header{Rrtype: dns.TypeAAAA, Name: header.Name, Class: header.Class, Ttl: header.Ttl}, AAAA: net.ParseIP(record.Value).To16()}
		case "CNAME":
			rr = &dns.CNAME{Hdr: dns.RR_Header{Rrtype: dns.TypeCNAME, Name: header.Name, Class: header.Class, Ttl: header.Ttl}, Target: dns.Fqdn(record.Value)}
		case "TXT":
			rr = &dns.TXT{Hdr: dns.RR_Header{Rrtype: dns.TypeTXT, Name: header.Name, Class: header.Class, Ttl: header.Ttl}, Txt: []string{record.Value}}
		}
		if rr != nil {
			key := record.Domain + "\x00" + record.Type
			snapshot.records[key] = append(snapshot.records[key], rr)
		}
		if record.Type == "A" || record.Type == "AAAA" {
			if reverse, err := dns.ReverseAddr(record.Value); err == nil {
				snapshot.ptr[dnsname.Normalize(reverse)] = append(snapshot.ptr[dnsname.Normalize(reverse)], &dns.PTR{
					Hdr: dns.RR_Header{Name: reverse, Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: record.TTL},
					Ptr: name,
				})
			}
		}
	}
	return snapshot
}

func (s *DNSServer) setLocalRecords(records []LocalRecord) {
	snapshot := buildLocalRecordSnapshot(records)
	s.localRecords.Store(snapshot)
}

// localRecordResponse answers from local records, from PTR records derived
// from them, and — when privateReverse is set — with NXDOMAIN for reverse
// lookups of private address ranges that no route handles, so they are
// neither sent to a public resolver nor leak internal addressing.
func (s *DNSServer) localRecordResponse(request *dns.Msg, question dns.Question, privateReverse bool) (*dns.Msg, bool) {
	snapshot := s.localRecords.Load()
	name := dnsname.Normalize(question.Name)
	var records []dns.RR
	if snapshot != nil {
		if question.Qtype == dns.TypePTR {
			records = snapshot.ptr[name]
		} else {
			records = snapshot.records[name+"\x00"+dns.TypeToString[question.Qtype]]
		}
	}
	if len(records) == 0 {
		if privateReverse && isPrivateReverseName(name) && s.routes.Load().lookup(name) == nil {
			response := new(dns.Msg)
			response.SetReply(request)
			response.Authoritative = true
			response.RecursionAvailable = true
			response.Rcode = dns.RcodeNameError
			return response, true
		}
		return nil, false
	}
	response := new(dns.Msg)
	response.SetReply(request)
	response.Authoritative = true
	response.RecursionAvailable = true
	response.Answer = make([]dns.RR, 0, len(records))
	for _, record := range records {
		response.Answer = append(response.Answer, dns.Copy(record))
	}
	return response, true
}

// isPrivateReverseName reports whether name (normalized, without trailing dot)
// lies in a reverse zone of loopback, link-local or private addresses.
func isPrivateReverseName(name string) bool {
	switch {
	case strings.HasSuffix(name, ".in-addr.arpa"):
		labels := strings.Split(strings.TrimSuffix(name, ".in-addr.arpa"), ".")
		if len(labels) > 4 {
			return false
		}
		octets := make([]int, len(labels))
		for index, label := range labels {
			value, err := strconv.Atoi(label)
			if err != nil || value < 0 || value > 255 {
				return false
			}
			octets[len(labels)-1-index] = value
		}
		first := octets[0]
		if first == 10 || first == 127 {
			return true
		}
		if len(octets) < 2 {
			return false
		}
		second := octets[1]
		return (first == 172 && second >= 16 && second <= 31) || (first == 192 && second == 168) || (first == 169 && second == 254)
	case strings.HasSuffix(name, ".ip6.arpa"):
		labels := strings.Split(strings.TrimSuffix(name, ".ip6.arpa"), ".")
		if len(labels) > 32 {
			return false
		}
		nibbles := make([]byte, len(labels))
		for index, label := range labels {
			if len(label) != 1 || strings.IndexByte("0123456789abcdef", label[0]) < 0 {
				return false
			}
			value, _ := strconv.ParseUint(label, 16, 8)
			nibbles[len(labels)-1-index] = byte(value)
		}
		if len(nibbles) == 32 { // ::1
			loopback := nibbles[31] == 1
			for _, nibble := range nibbles[:31] {
				loopback = loopback && nibble == 0
			}
			if loopback {
				return true
			}
		}
		if len(nibbles) < 2 {
			return false
		}
		first := nibbles[0]<<4 | nibbles[1]
		if first == 0xfc || first == 0xfd { // fc00::/7
			return true
		}
		return first == 0xfe && len(nibbles) >= 3 && nibbles[2] >= 8 && nibbles[2] <= 0xb // fe80::/10
	}
	return false
}

func localRecordsEqual(left, right []LocalRecord) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
