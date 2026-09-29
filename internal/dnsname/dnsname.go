// Package dnsname holds the DNS name helpers shared by rules, local records and
// access policy.
package dnsname

import "strings"

// Normalize lower-cases a name and strips whitespace and the trailing root dot.
func Normalize(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	return strings.TrimSuffix(value, ".")
}

// Valid reports whether a normalized name is a syntactically plausible domain.
func Valid(name string) bool {
	if name == "" || len(name) > 253 || strings.ContainsAny(name, " /\\,;()[]{}") {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
	}
	return true
}

// Parent returns the name with its left-most label removed, or "" for a
// single-label name.
func Parent(name string) string {
	if index := strings.IndexByte(name, '.'); index >= 0 {
		return name[index+1:]
	}
	return ""
}
