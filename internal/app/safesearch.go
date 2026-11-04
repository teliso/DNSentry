package app

import (
	"context"
	"time"

	"github.com/miekg/dns"
	"github.com/teliso/DNSentry/internal/dnsname"
)

// Safe search makes search engines and video sites return their filtered
// ("family safe") results. Each service publishes a special host name for that;
// queries for the normal names are answered with a CNAME to it.
var safeSearchHosts = func() map[string]string {
	hosts := map[string]string{
		"www.bing.com":             "strict.bing.com",
		"duckduckgo.com":           "safe.duckduckgo.com",
		"www.duckduckgo.com":       "safe.duckduckgo.com",
		"start.duckduckgo.com":     "safe.duckduckgo.com",
		"pixabay.com":              "safesearch.pixabay.com",
		"www.pixabay.com":          "safesearch.pixabay.com",
		"www.youtube.com":          "restrictmoderate.youtube.com",
		"m.youtube.com":            "restrictmoderate.youtube.com",
		"youtubei.googleapis.com":  "restrictmoderate.youtube.com",
		"youtube.googleapis.com":   "restrictmoderate.youtube.com",
		"www.youtube-nocookie.com": "restrictmoderate.youtube.com",
		"cn.bing.com":              "strict.bing.com",
	}
	// Google serves its search from a domain per country.
	for _, tld := range []string{
		"com", "com.hk", "com.tw", "com.sg", "com.au", "com.br", "com.mx", "com.tr", "com.ar", "com.sa", "com.eg", "com.ua", "com.vn", "com.ph", "com.my", "com.pk",
		"co.uk", "co.jp", "co.kr", "co.in", "co.th", "co.id", "co.za", "co.nz", "co.il",
		"de", "fr", "it", "es", "nl", "pl", "ru", "ca", "ch", "at", "be", "se", "no", "dk", "fi", "pt", "gr", "cz", "hu", "ro", "ie", "cl", "pe",
	} {
		hosts["www.google."+tld] = "forcesafesearch.google.com"
		hosts["google."+tld] = "forcesafesearch.google.com"
	}
	return hosts
}()

const safeSearchTTL = 300

// trustedName is true for names whose answers are deliberate redirections
// (explicit upstream routes, safe search); the rebinding filter and DNSSEC
// validation do not apply to them.
func (s *DNSServer) trustedName(config *Config, request *dns.Msg) bool {
	return s.routeFor(request) != nil || s.isSafeSearchQuery(config, request)
}

// safeSearchTarget returns the filtered host name for domain, if it has one.
func safeSearchTarget(domain string) (string, bool) {
	target, ok := safeSearchHosts[domain]
	return target, ok
}

// safeSearchOn is true when safe search is switched on, or a schedule window
// that forces it is open.
func (s *DNSServer) safeSearchOn(config *Config) bool {
	return config.SafeSearch || s.schedules.Load().SafeSearch(time.Now())
}

// watchSchedule empties the cache when a schedule window changes whether safe
// search is forced, so answers cached under the old state do not outlive it.
func (s *DNSServer) watchSchedule(ctx context.Context) {
	ticker := time.NewTicker(20 * time.Second)
	defer ticker.Stop()
	config := s.configSnapshot()
	last := s.safeSearchOn(&config)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			config = s.configSnapshot()
			if now := s.safeSearchOn(&config); now != last {
				last = now
				s.clearCache()
			}
		}
	}
}

// isSafeSearchQuery reports whether the query is answered by safe search: the
// setting is on and the name is one of the redirected hosts.
func (s *DNSServer) isSafeSearchQuery(config *Config, request *dns.Msg) bool {
	if !s.safeSearchOn(config) || len(request.Question) != 1 {
		return false
	}
	_, ok := safeSearchTarget(dnsname.Normalize(request.Question[0].Name))
	return ok
}

// exchangeSafeSearch answers a redirected name: A and AAAA queries get a CNAME
// to the filtered host plus that host's addresses, other types an empty answer
// (so HTTPS records cannot leak the unfiltered addresses).
func (s *DNSServer) exchangeSafeSearch(request *dns.Msg) (*dns.Msg, string, error) {
	question := request.Question[0]
	target, _ := safeSearchTarget(dnsname.Normalize(question.Name))
	response := new(dns.Msg)
	response.SetReply(request)
	response.RecursionAvailable = true
	if question.Qtype != dns.TypeA && question.Qtype != dns.TypeAAAA {
		return response, "", nil
	}
	lookup := new(dns.Msg)
	lookup.SetQuestion(dns.Fqdn(target), question.Qtype)
	lookup.RecursionDesired = true
	answer, upstream, err := s.exchange(lookup)
	if err != nil {
		return nil, "", err
	}
	response.Rcode = answer.Rcode
	response.Answer = append(response.Answer, &dns.CNAME{
		Hdr:    dns.RR_Header{Name: question.Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: safeSearchTTL},
		Target: dns.Fqdn(target),
	})
	response.Answer = append(response.Answer, answer.Answer...)
	return response, upstream, nil
}
