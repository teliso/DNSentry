package rules

import (
	"reflect"
	"testing"
)

func TestParseLine(t *testing.T) {
	for _, test := range []struct {
		line string
		want []Entry
	}{
		{"||ads.example.com^", []Entry{{Domain: "ads.example.com", Action: ActionBlock}}},
		{"@@||Trusted.Example.com^", []Entry{{Domain: "trusted.example.com", Action: ActionAllow}}},
		{"example.net", []Entry{{Domain: "example.net", Action: ActionBlock}}},
		{"|example.org^|", []Entry{{Domain: "example.org", Action: ActionBlock}}},
		{"0.0.0.0 a.example b.example # trailing", []Entry{
			{Domain: "a.example", Action: ActionBlock, IP: "0.0.0.0"},
			{Domain: "b.example", Action: ActionBlock, IP: "0.0.0.0"},
		}},
		{"127.0.0.1 localhost", nil},
		{"192.168.1.10 nas.lan", nil}, // redirecting hosts entry: not a filter rule
		{"||ads.example.com^$third-party", nil},
		{"*.example.com", nil},
		{"/ads[0-9]+/", nil},
		{"# comment", nil},
		{"! adblock comment", nil},
		{"   ", nil},
	} {
		if got := ParseLine(test.line); !reflect.DeepEqual(got, test.want) {
			t.Errorf("ParseLine(%q) = %#v, want %#v", test.line, got, test.want)
		}
	}
}

func TestEntryTextRoundTrips(t *testing.T) {
	for _, entry := range []Entry{
		{Domain: "a.example", Action: ActionBlock},
		{Domain: "a.example", Action: ActionAllow},
		{Domain: "a.example", Action: ActionBlock, IP: "0.0.0.0"},
	} {
		if got := ParseLine(entry.Text()); len(got) != 1 || got[0] != entry {
			t.Errorf("round trip of %#v = %#v", entry, got)
		}
	}
}
