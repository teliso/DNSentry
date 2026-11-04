// Package schedule turns weekly time windows into "what applies right now":
// the services to block and whether to force safe search, for example games
// blocked on school nights.
package schedule

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/teliso/DNSentry/internal/dnsname"
	"github.com/teliso/DNSentry/internal/services"
)

const MaxRules = 16

// Rule is one weekly window.
type Rule struct {
	Name    string `json:"name" yaml:"name,omitempty"`
	Enabled bool   `json:"enabled" yaml:"enabled"`
	// Days are the weekdays the window starts on, 0 = Sunday … 6 = Saturday;
	// empty means every day.
	Days []int `json:"days" yaml:"days,omitempty"`
	// Start and End are "HH:MM" (24 hours). An End at or before Start makes the
	// window run past midnight into the next day; equal values mean the whole day.
	Start string `json:"start" yaml:"start"`
	End   string `json:"end" yaml:"end"`
	// Services are blocked, and SafeSearch is forced, while the window is open.
	Services   []string `json:"services" yaml:"services,omitempty"`
	SafeSearch bool     `json:"safe_search" yaml:"safe_search,omitempty"`
}

// Config is the schedule section of the configuration.
type Config struct {
	// Timezone is an IANA name such as Asia/Shanghai; empty means the server's local time.
	Timezone string `json:"timezone" yaml:"timezone,omitempty"`
	Rules    []Rule `json:"rules" yaml:"rules,omitempty"`
}

// IsZero keeps an unused section out of the configuration file.
func (c Config) IsZero() bool { return c.Timezone == "" && len(c.Rules) == 0 }

func parseClock(value string) (int, error) {
	var hour, minute int
	if len(value) != 5 || value[2] != ':' {
		return 0, fmt.Errorf("time %q must look like 22:30", value)
	}
	if _, err := fmt.Sscanf(value, "%02d:%02d", &hour, &minute); err != nil || hour < 0 || hour > 23 || minute < 0 || minute > 59 {
		return 0, fmt.Errorf("time %q must look like 22:30", value)
	}
	return hour*60 + minute, nil
}

// Normalize validates the configuration and tidies it in place.
func Normalize(config *Config) error {
	config.Timezone = strings.TrimSpace(config.Timezone)
	if config.Timezone != "" {
		if _, err := time.LoadLocation(config.Timezone); err != nil {
			return fmt.Errorf("schedule: unknown time zone %q (use a name such as Asia/Shanghai)", config.Timezone)
		}
	}
	if len(config.Rules) > MaxRules {
		return fmt.Errorf("schedule: at most %d rules", MaxRules)
	}
	for index := range config.Rules {
		rule := &config.Rules[index]
		rule.Name = strings.TrimSpace(rule.Name)
		if len(rule.Name) > 64 {
			return fmt.Errorf("schedule.rules[%d]: name is too long", index)
		}
		start, err := parseClock(strings.TrimSpace(rule.Start))
		if err != nil {
			return fmt.Errorf("schedule.rules[%d]: %w", index, err)
		}
		end, err := parseClock(strings.TrimSpace(rule.End))
		if err != nil {
			return fmt.Errorf("schedule.rules[%d]: %w", index, err)
		}
		rule.Start, rule.End = fmt.Sprintf("%02d:%02d", start/60, start%60), fmt.Sprintf("%02d:%02d", end/60, end%60)
		for _, day := range rule.Days {
			if day < 0 || day > 6 {
				return fmt.Errorf("schedule.rules[%d]: days must be 0 (Sunday) to 6 (Saturday)", index)
			}
		}
		slices.Sort(rule.Days)
		rule.Days = slices.Compact(rule.Days)
		if len(rule.Days) == 7 {
			rule.Days = nil // every day
		}
		known, unknown := services.Normalize(rule.Services)
		if len(unknown) > 0 {
			return fmt.Errorf("schedule.rules[%d]: unknown service %q", index, unknown[0])
		}
		rule.Services = known
		if rule.Enabled && len(rule.Services) == 0 && !rule.SafeSearch {
			return fmt.Errorf("schedule.rules[%d]: choose at least one service or safe search", index)
		}
	}
	return nil
}

// Rules are compiled once per configuration and evaluated per query.
type compiled struct {
	rule    Rule
	start   int
	end     int
	days    [7]bool
	matcher *services.Matcher
}

// Set is an immutable, compiled schedule. A nil *Set has no active rules.
type Set struct {
	location *time.Location
	rules    []compiled
}

// Compile builds a Set from a normalized Config.
func Compile(config Config) *Set {
	set := &Set{location: time.Local}
	if config.Timezone != "" {
		if location, err := time.LoadLocation(config.Timezone); err == nil {
			set.location = location
		}
	}
	for _, rule := range config.Rules {
		if !rule.Enabled {
			continue
		}
		start, _ := parseClock(rule.Start)
		end, _ := parseClock(rule.End)
		item := compiled{rule: rule, start: start, end: end, matcher: services.NewMatcher(rule.Services)}
		if len(rule.Days) == 0 {
			for day := range item.days {
				item.days[day] = true
			}
		}
		for _, day := range rule.Days {
			item.days[day] = true
		}
		set.rules = append(set.rules, item)
	}
	return set
}

func (c *compiled) activeAt(t time.Time) bool {
	minutes := t.Hour()*60 + t.Minute()
	today := t.Weekday()
	switch {
	case c.start == c.end:
		return c.days[today] // the whole day
	case c.start < c.end:
		return c.days[today] && minutes >= c.start && minutes < c.end
	case minutes >= c.start: // a window past midnight: the evening part
		return c.days[today]
	case minutes < c.end: // ... and its morning part belongs to the day before
		return c.days[(today+6)%7]
	}
	return false
}

// Active lists the names of the rules whose window is open at now.
func (s *Set) Active(now time.Time) []string {
	if s == nil {
		return nil
	}
	now = now.In(s.location)
	var names []string
	for index := range s.rules {
		if s.rules[index].activeAt(now) {
			name := s.rules[index].rule.Name
			if name == "" {
				name = fmt.Sprintf("#%d", index+1)
			}
			names = append(names, name)
		}
	}
	return names
}

// MatchService reports the rule and service that block domain at now.
func (s *Set) MatchService(now time.Time, domain string) (ruleName string, service services.Service, ok bool) {
	if s == nil || len(s.rules) == 0 {
		return "", services.Service{}, false
	}
	now = now.In(s.location)
	domain = dnsname.Normalize(domain)
	for index := range s.rules {
		item := &s.rules[index]
		if !item.activeAt(now) {
			continue
		}
		if service, ok := item.matcher.Match(domain); ok {
			name := item.rule.Name
			if name == "" {
				name = fmt.Sprintf("#%d", index+1)
			}
			return name, service, true
		}
	}
	return "", services.Service{}, false
}

// SafeSearch reports whether an open window forces safe search.
func (s *Set) SafeSearch(now time.Time) bool {
	if s == nil {
		return false
	}
	now = now.In(s.location)
	for index := range s.rules {
		if s.rules[index].rule.SafeSearch && s.rules[index].activeAt(now) {
			return true
		}
	}
	return false
}
