package app

import (
	"context"
	"crypto/ecdsa"
	"net"
	"testing"
	"time"

	"github.com/0xERR0R/blocky/model"
	blockydnssec "github.com/0xERR0R/blocky/resolver/dnssec"
	"github.com/miekg/dns"
)

type dnssecTestResolver struct {
	resolve func(*model.Request) (*model.Response, error)
}

func (r dnssecTestResolver) Resolve(_ context.Context, request *model.Request) (*model.Response, error) {
	return r.resolve(request)
}

func newTestSignedKey(t *testing.T, zone string) (*dns.DNSKEY, *ecdsa.PrivateKey, string) {
	t.Helper()
	key := &dns.DNSKEY{Hdr: dns.RR_Header{Name: dns.Fqdn(zone), Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600}, Flags: 257, Protocol: 3, Algorithm: dns.ECDSAP256SHA256}
	privateKey, err := key.Generate(256)
	if err != nil {
		t.Fatal(err)
	}
	return key, privateKey.(*ecdsa.PrivateKey), key.String()
}

func signTestRRSet(t *testing.T, rrset []dns.RR, covered uint16, key *dns.DNSKEY, privateKey *ecdsa.PrivateKey, signer string) *dns.RRSIG {
	t.Helper()
	signature := &dns.RRSIG{
		Hdr:         dns.RR_Header{Name: rrset[0].Header().Name, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: rrset[0].Header().Ttl},
		TypeCovered: covered,
		Algorithm:   key.Algorithm,
		Labels:      uint8(dns.CountLabel(rrset[0].Header().Name)),
		OrigTtl:     rrset[0].Header().Ttl,
		Expiration:  uint32(time.Now().Add(time.Hour).Unix()),
		Inception:   uint32(time.Now().Add(-time.Hour).Unix()),
		KeyTag:      key.KeyTag(),
		SignerName:  dns.Fqdn(signer),
	}
	if err := signature.Sign(privateKey, rrset); err != nil {
		t.Fatal(err)
	}
	return signature
}

func TestDNSSECValidatorReportsRealSecureInsecureAndBogusResults(t *testing.T) {
	parentKey, parentPrivate, anchor := newTestSignedKey(t, "example.")
	parentKeySignature := signTestRRSet(t, []dns.RR{parentKey}, dns.TypeDNSKEY, parentKey, parentPrivate, "example.")
	childKey, childPrivate, _ := newTestSignedKey(t, "signed.example.")
	childKeySignature := signTestRRSet(t, []dns.RR{childKey}, dns.TypeDNSKEY, childKey, childPrivate, "signed.example.")
	childDS := childKey.ToDS(dns.SHA256)
	childDSSignature := signTestRRSet(t, []dns.RR{childDS}, dns.TypeDS, parentKey, parentPrivate, "example.")

	resolver := dnssecTestResolver{resolve: func(request *model.Request) (*model.Response, error) {
		question := request.Req.Question[0]
		switch {
		case question.Qtype == dns.TypeDNSKEY && dns.Fqdn(question.Name) == "example.":
			return &model.Response{Res: &dns.Msg{Answer: []dns.RR{parentKey, parentKeySignature}}}, nil
		case question.Qtype == dns.TypeDNSKEY && dns.Fqdn(question.Name) == "signed.example.":
			return &model.Response{Res: &dns.Msg{Answer: []dns.RR{childKey, childKeySignature}}}, nil
		case question.Qtype == dns.TypeDS && dns.Fqdn(question.Name) == "signed.example.":
			return &model.Response{Res: &dns.Msg{Answer: []dns.RR{childDS, childDSSignature}}}, nil
		default:
			return &model.Response{Res: &dns.Msg{MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess}}}, nil
		}
	}}

	question := dns.Question{Name: "host.signed.example.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	answer := &dns.A{Hdr: dns.RR_Header{Name: question.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: net.ParseIP("192.0.2.1")}
	answerSignature := signTestRRSet(t, []dns.RR{answer}, dns.TypeA, childKey, childPrivate, "signed.example.")

	secureValidator, err := NewDNSSECValidator(context.Background(), []string{anchor}, resolver)
	if err != nil {
		t.Fatal(err)
	}
	secureResult := secureValidator.Validate(context.Background(), &dns.Msg{Answer: []dns.RR{answer, answerSignature}}, question)
	secureValidator.Close()
	if secureResult != blockydnssec.ValidationResultSecure {
		t.Fatalf("expected a real signed chain to be Secure, got %s", secureResult)
	}
	if stats := secureValidator.Stats(); stats.Secure != 1 || stats.Insecure != 0 || stats.Bogus != 0 || stats.Indeterminate != 0 {
		t.Fatalf("unexpected secure stats: %#v", stats)
	}

	insecureKey, insecurePrivate, insecureAnchor := newTestSignedKey(t, "example.")
	insecureKeySignature := signTestRRSet(t, []dns.RR{insecureKey}, dns.TypeDNSKEY, insecureKey, insecurePrivate, "example.")
	insecureNSEC := &dns.NSEC{
		Hdr:        dns.RR_Header{Name: "unsigned.example.", Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 300},
		NextDomain: "\\000.unsigned.example.",
		TypeBitMap: []uint16{dns.TypeNS, dns.TypeRRSIG, dns.TypeNSEC},
	}
	insecureNSECSignature := signTestRRSet(t, []dns.RR{insecureNSEC}, dns.TypeNSEC, insecureKey, insecurePrivate, "example.")
	insecureResolver := dnssecTestResolver{resolve: func(request *model.Request) (*model.Response, error) {
		question := request.Req.Question[0]
		switch {
		case question.Qtype == dns.TypeDS && dns.Fqdn(question.Name) == "unsigned.example.":
			return &model.Response{Res: &dns.Msg{Ns: []dns.RR{insecureNSEC, insecureNSECSignature}}}, nil
		case question.Qtype == dns.TypeDNSKEY && dns.Fqdn(question.Name) == "example.":
			return &model.Response{Res: &dns.Msg{Answer: []dns.RR{insecureKey, insecureKeySignature}}}, nil
		default:
			return &model.Response{Res: &dns.Msg{}}, nil
		}
	}}
	insecureValidator, err := NewDNSSECValidator(context.Background(), []string{insecureAnchor}, insecureResolver)
	if err != nil {
		t.Fatal(err)
	}
	insecureResult := insecureValidator.Validate(context.Background(), &dns.Msg{MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess}}, dns.Question{Name: "unsigned.example.", Qtype: dns.TypeA, Qclass: dns.ClassINET})
	insecureValidator.Close()
	if insecureResult != blockydnssec.ValidationResultInsecure {
		t.Fatalf("expected an authenticated unsigned delegation to be Insecure, got %s", insecureResult)
	}

	forgedAnswer := &dns.A{Hdr: answer.Hdr, A: append(net.IP(nil), answer.A...)}
	forgedAnswer.A = net.ParseIP("203.0.113.66")
	bogusValidator, err := NewDNSSECValidator(context.Background(), []string{anchor}, resolver)
	if err != nil {
		t.Fatal(err)
	}
	bogusResult := bogusValidator.Validate(context.Background(), &dns.Msg{Answer: []dns.RR{forgedAnswer, answerSignature}}, question)
	bogusValidator.Close()
	if bogusResult != blockydnssec.ValidationResultBogus {
		t.Fatalf("expected a tampered signed response to be Bogus, got %s", bogusResult)
	}
}

func TestDNSSECConfigInitializesTrustAnchorsAndRoundTrips(t *testing.T) {
	_, _, anchor := newTestSignedKey(t, "example.")
	config := testConfig()
	config.DNSSECValidate = true
	config.DNSSECTrustAnchors = []string{anchor}
	validated, err := validateConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	fileConfig := newYAMLConfig(validated)
	if !fileConfig.DNS.DNSSECValidate || len(fileConfig.DNS.DNSSECTrustAnchors) != 1 {
		t.Fatalf("DNSSEC YAML fields were not initialized: %#v", fileConfig.DNS)
	}
	defaultValidator, err := NewDNSSECValidator(context.Background(), nil, dnssecTestResolver{resolve: func(*model.Request) (*model.Response, error) {
		return &model.Response{Res: &dns.Msg{}}, nil
	}})
	if err != nil {
		t.Fatalf("default IANA root trust anchors did not initialize: %v", err)
	}
	defaultValidator.Close()
}

func TestDNSSECADRequiresLocalValidationAndClientPermission(t *testing.T) {
	request := newTestRequest("signed.example.", dns.TypeA)
	request.AuthenticatedData = true
	response := &dns.Msg{MsgHdr: dns.MsgHdr{AuthenticatedData: true}}
	if got := filterResponseWithDNSSEC(response.Copy(), request, false); got.AuthenticatedData {
		t.Fatal("upstream AD must not be trusted without local validation")
	}
	if got := filterResponseWithDNSSEC(response.Copy(), request, true); !got.AuthenticatedData {
		t.Fatal("locally validated response should carry AD when requested")
	}
	request.CheckingDisabled = true
	if got := filterResponseWithDNSSEC(response.Copy(), request, true); got.AuthenticatedData {
		t.Fatal("AD must not be set for a CD request")
	}
}
