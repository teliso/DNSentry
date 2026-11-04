package schedule

import (
	"testing"
	"time"
)

func at(t *testing.T, location *time.Location, value string) time.Time {
	t.Helper()
	parsed, err := time.ParseInLocation("2006-01-02 15:04", value, location)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

func compile(t *testing.T, rules ...Rule) *Set {
	t.Helper()
	config := Config{Timezone: "UTC", Rules: rules}
	if err := Normalize(&config); err != nil {
		t.Fatal(err)
	}
	return Compile(config)
}

func TestWindows(t *testing.T) {
	utc := time.UTC
	// 2026-11-02 is a Monday, 2026-11-06 a Friday, 2026-11-07 a Saturday.
	day := compile(t, Rule{Name: "work", Enabled: true, Days: []int{1, 2, 3, 4, 5}, Start: "09:00", End: "17:00", Services: []string{"youtube"}})
	for when, want := range map[string]bool{
		"2026-11-02 09:00": true, "2026-11-02 16:59": true, "2026-11-02 17:00": false, "2026-11-02 08:59": false,
		"2026-11-07 10:00": false, // Saturday
	} {
		if got := len(day.Active(at(t, utc, when))) == 1; got != want {
			t.Errorf("work %s = %v, want %v", when, got, want)
		}
	}

	night := compile(t, Rule{Name: "night", Enabled: true, Days: []int{5}, Start: "22:00", End: "07:00", Services: []string{"steam"}}) // Fridays, into Saturday
	for when, want := range map[string]bool{
		"2026-11-06 21:59": false, "2026-11-06 22:00": true, "2026-11-06 23:59": true, // Friday evening
		"2026-11-07 00:00": true, "2026-11-07 06:59": true, "2026-11-07 07:00": false, // Saturday morning belongs to Friday's window
		"2026-11-07 22:30": false, // Saturday evening: the window does not start on Saturday
		"2026-11-06 03:00": false, // Friday morning belongs to Thursday's window
	} {
		if got := len(night.Active(at(t, utc, when))) == 1; got != want {
			t.Errorf("night %s = %v, want %v", when, got, want)
		}
	}

	whole := compile(t, Rule{Enabled: true, Days: []int{6}, Start: "00:00", End: "00:00", SafeSearch: true})
	if !whole.SafeSearch(at(t, utc, "2026-11-07 13:00")) || whole.SafeSearch(at(t, utc, "2026-11-06 13:00")) {
		t.Error("equal start and end must mean the whole day, on the listed days only")
	}
	if got := whole.Active(at(t, utc, "2026-11-07 13:00")); len(got) != 1 || got[0] != "#1" {
		t.Errorf("an unnamed rule is called by its number: %v", got)
	}
}

func TestMatchServiceAndDisabledRules(t *testing.T) {
	set := compile(t,
		Rule{Name: "games", Enabled: true, Start: "20:00", End: "22:00", Services: []string{"steam", "roblox"}},
		Rule{Name: "off", Enabled: false, Start: "00:00", End: "00:00", Services: []string{"youtube"}},
	)
	evening, noon := at(t, time.UTC, "2026-11-03 21:00"), at(t, time.UTC, "2026-11-03 12:00")
	if name, service, ok := set.MatchService(evening, "store.steampowered.com"); !ok || name != "games" || service.ID != "steam" {
		t.Fatalf("evening: %q %v %v", name, service, ok)
	}
	if _, _, ok := set.MatchService(noon, "store.steampowered.com"); ok {
		t.Error("blocked outside the window")
	}
	if _, _, ok := set.MatchService(evening, "www.youtube.com"); ok {
		t.Error("a disabled rule blocked")
	}
	if _, _, ok := set.MatchService(evening, "example.org"); ok {
		t.Error("an unrelated domain was blocked")
	}
	var none *Set
	if none.Active(evening) != nil || none.SafeSearch(evening) {
		t.Error("a nil set must be inert")
	}
	if _, _, ok := none.MatchService(evening, "steampowered.com"); ok {
		t.Error("a nil set blocked")
	}
}

func TestTimezoneDecidesTheWallClock(t *testing.T) {
	shanghai, err := time.LoadLocation("Asia/Shanghai")
	if err != nil {
		t.Skip("no tzdata: ", err)
	}
	config := Config{Timezone: "Asia/Shanghai", Rules: []Rule{{Enabled: true, Start: "22:00", End: "23:00", SafeSearch: true}}}
	if err := Normalize(&config); err != nil {
		t.Fatal(err)
	}
	set := Compile(config)
	instant := time.Date(2026, 11, 3, 14, 30, 0, 0, time.UTC) // 22:30 in Shanghai
	if !set.SafeSearch(instant) || set.SafeSearch(instant.Add(2*time.Hour)) {
		t.Error("the window must follow the configured time zone")
	}
	_ = shanghai
}

func TestNormalizeRejectsBadInput(t *testing.T) {
	ok := Rule{Enabled: true, Start: "09:00", End: "10:00", Services: []string{"tiktok"}}
	mutate := func(change func(*Rule)) Config {
		rule := ok
		change(&rule)
		return Config{Rules: []Rule{rule}}
	}
	for name, config := range map[string]Config{
		"bad start":       mutate(func(r *Rule) { r.Start = "9:00" }),
		"hour 24":         mutate(func(r *Rule) { r.End = "24:00" }),
		"minute 60":       mutate(func(r *Rule) { r.End = "10:60" }),
		"text":            mutate(func(r *Rule) { r.Start = "noon" }),
		"bad day":         mutate(func(r *Rule) { r.Days = []int{7} }),
		"unknown service": mutate(func(r *Rule) { r.Services = []string{"nope"} }),
		"does nothing":    mutate(func(r *Rule) { r.Services = nil }),
		"bad time zone":   {Timezone: "Mars/Olympus", Rules: []Rule{ok}},
		"too many":        {Rules: make([]Rule, MaxRules+1)},
	} {
		if err := Normalize(&config); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	tidy := Config{Rules: []Rule{{Name: " x ", Enabled: true, Days: []int{3, 1, 3, 0, 2, 4, 5, 6}, Start: "07:05", End: " 07:05 ", Services: []string{"youtube", "tiktok", "youtube"}}}}
	if err := Normalize(&tidy); err != nil {
		t.Fatal(err)
	}
	if rule := tidy.Rules[0]; rule.Name != "x" || rule.Days != nil || len(rule.Services) != 2 || rule.Services[0] != "tiktok" {
		t.Fatalf("not tidied: %+v", rule)
	}
	if !(Config{}).IsZero() || (Config{Timezone: "UTC"}).IsZero() {
		t.Error("IsZero")
	}
}
