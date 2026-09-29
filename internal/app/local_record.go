package app

import (
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/miekg/dns"
)

type LocalRecord struct {
	Domain string `json:"domain" yaml:"domain"`
	Type   string `json:"type" yaml:"type"`
	Value  string `json:"value" yaml:"value"`
	TTL    uint32 `json:"ttl" yaml:"ttl"`
}

type localRecordSnapshot struct {
	records map[string][]dns.RR
}

func validateLocalRecords(records []LocalRecord) error {
	seen := make(map[string]struct{}, len(records))
	for index := range records {
		record := &records[index]
		record.Domain = normalizeDomain(record.Domain)
		record.Type = strings.ToUpper(strings.TrimSpace(record.Type))
		record.Value = strings.TrimSpace(record.Value)
		if !validDomain(record.Domain) {
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
			if !validDomain(normalizeDomain(record.Value)) {
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
	snapshot := &localRecordSnapshot{records: make(map[string][]dns.RR)}
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
	}
	return snapshot
}

func (s *DNSServer) setLocalRecords(records []LocalRecord) {
	snapshot := buildLocalRecordSnapshot(records)
	s.localRecords.Store(snapshot)
}

func (s *DNSServer) localRecordResponse(request *dns.Msg, question dns.Question) (*dns.Msg, bool) {
	snapshot := s.localRecords.Load()
	if snapshot == nil {
		return nil, false
	}
	key := normalizeDomain(question.Name) + "\x00" + dns.TypeToString[question.Qtype]
	records := snapshot.records[key]
	if len(records) == 0 {
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

func sortLocalRecords(records []LocalRecord) {
	sort.Slice(records, func(left, right int) bool {
		if records[left].Domain != records[right].Domain {
			return records[left].Domain < records[right].Domain
		}
		if records[left].Type != records[right].Type {
			return records[left].Type < records[right].Type
		}
		return records[left].Value < records[right].Value
	})
}
