// Package dnsname holds the DNS name helpers shared by rules, local records and
// access policy.
package dnsname

import "strings"

// Normalize lower-cases a name and strips whitespace and the trailing root dot.
func Normalize(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	return strings.TrimSuffix(value, ".")
}

// Valid reports whether a normalized name is a syntactically valid host name:
// dot-separated labels of letters, digits, '-' and '_', without leading or
// trailing hyphens.
func Valid(name string) bool {
	if name == "" || len(name) > 253 {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for index := 0; index < len(label); index++ {
			c := label[index]
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return false
			}
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
