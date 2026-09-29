// Package rules implements DNS filter rules: parsing, the local rules file,
// remote rule lists with an on-disk cache, and lock-free matching.
package rules

import (
	"net"
	"strings"

	"github.com/teliso/DNSentry/internal/dnsname"
)

type Action string

const (
	ActionBlock Action = "block"
	ActionAllow Action = "allow"
)

// Entry is a single filter rule. Source is empty for rules from the local
// rules file and the list URL for rules from a remote source.
type Entry struct {
	Domain string `json:"domain"`
	Action Action `json:"action"`
	IP     string `json:"ip,omitempty"` // hosts-file syntax only, informational
	Source string `json:"source,omitempty"`
}

// Text returns the rule in canonical syntax.
func (e Entry) Text() string {
	switch {
	case e.IP != "":
		return e.IP + " " + e.Domain
	case e.Action == ActionAllow:
		return "@@||" + e.Domain + "^"
	default:
		return "||" + e.Domain + "^"
	}
}

// Names found in stock hosts files that must never be blocked.
var hostsReserved = map[string]bool{
	"localhost":             true,
	"localhost.localdomain": true,
	"local":                 true,
	"broadcasthost":         true,
	"ip6-localhost":         true,
	"ip6-loopback":          true,
	"ip6-localnet":          true,
	"ip6-mcastprefix":       true,
	"ip6-allnodes":          true,
	"ip6-allrouters":        true,
	"ip6-allhosts":          true,
	"0.0.0.0":               true,
}

// ParseLine parses one line of rule syntax and returns the rules it defines.
// Supported forms are plain domains ("example.com"), AdGuard/ABP domain rules
// ("||example.com^", "@@||example.com^") and hosts entries with a blocking
// address ("0.0.0.0 a.example b.example"). Comments, blank lines and rules with
// unsupported syntax (modifiers, wildcards, regular expressions, redirecting
// hosts entries) yield nil.
func ParseLine(line string) []Entry {
	line = strings.TrimSpace(line)
	if line == "" || line[0] == '#' || line[0] == '!' {
		return nil
	}
	if fields := strings.Fields(line); len(fields) >= 2 {
		ip := net.ParseIP(fields[0])
		if ip == nil {
			return nil
		}
		if !ip.IsUnspecified() && !ip.IsLoopback() {
			return nil
		}
		var entries []Entry
		for _, field := range fields[1:] {
			if strings.HasPrefix(field, "#") {
				break
			}
			name := dnsname.Normalize(field)
			if !hostsReserved[name] && dnsname.Valid(name) {
				entries = append(entries, Entry{Domain: name, Action: ActionBlock, IP: ip.String()})
			}
		}
		return entries
	}

	action := ActionBlock
	if strings.HasPrefix(line, "@@") {
		action = ActionAllow
		line = line[2:]
	}
	if strings.HasPrefix(line, "||") {
		line = line[2:]
	} else {
		line = strings.TrimPrefix(line, "|")
	}
	line = strings.TrimSuffix(strings.TrimSuffix(line, "|"), "^")
	name := dnsname.Normalize(line)
	if !dnsname.Valid(name) {
		return nil
	}
	return []Entry{{Domain: name, Action: action}}
}
