//go:build proxykit_pac

package pac

import (
	"net"
	"testing"
	"time"
)

func TestPacPureHelpers(t *testing.T) {
	t.Run("isPlainHostName", func(t *testing.T) {
		if !pacIsPlainHostName("www") || pacIsPlainHostName("www.example.com") {
			t.Fatal("isPlainHostName")
		}
	})
	t.Run("dnsDomainIs", func(t *testing.T) {
		if !pacDNSDomainIs("www.example.com", ".example.com") {
			t.Error("should match .example.com")
		}
		if pacDNSDomainIs("www.example.com", ".other.com") {
			t.Error("should not match .other.com")
		}
		if !pacDNSDomainIs("WWW.EXAMPLE.COM", ".example.com") {
			t.Error("should be case-insensitive")
		}
		// Netscape dnsDomainIs is a pure suffix match (host.substring(
		// host.length-domain.length) == domain); PAC authors pass a leading
		// dot for a label boundary. We match the spec, so a dotless suffix
		// matches even without a boundary — this is intentional, not a bug.
		if !pacDNSDomainIs("notexample.com", "example.com") {
			t.Error("pure suffix match per spec should match")
		}
		if pacDNSDomainIs("example.com", ".example.com") {
			t.Error("host shorter than domain should not match")
		}
	})
	t.Run("localHostOrDomainIs", func(t *testing.T) {
		if !pacLocalHostOrDomainIs("www.example.com", "www.example.com") {
			t.Error("exact should match")
		}
		if !pacLocalHostOrDomainIs("www", "www.example.com") {
			t.Error("plain host should match hostname part")
		}
		if pacLocalHostOrDomainIs("home.example.com", "www.example.com") {
			t.Error("different host should not match")
		}
	})
	t.Run("dnsDomainLevels", func(t *testing.T) {
		if pacDNSDomainLevels("www") != 0 || pacDNSDomainLevels("www.example.com") != 2 {
			t.Error("dnsDomainLevels")
		}
	})
	t.Run("shExpMatch", func(t *testing.T) {
		cases := []struct {
			str, exp string
			want     bool
		}{
			{"www.example.com", "*.example.com", true},
			{"example.com", "*.example.com", false},
			{"foo.bar", "foo.???", true},
			{"foo.barx", "foo.???", false},
			{"http://host/x", "http://*", true},
			{"a.b.c", "*.c", true},
		}
		for _, c := range cases {
			if got := pacShExpMatch(c.str, c.exp); got != c.want {
				t.Errorf("shExpMatch(%q,%q)=%v want %v", c.str, c.exp, got, c.want)
			}
		}
	})
	t.Run("isInNet", func(t *testing.T) {
		if !pacIsInNet(net.ParseIP("10.1.2.3"), net.ParseIP("10.1.0.0"), net.ParseIP("255.255.0.0")) {
			t.Error("10.1.2.3 should be in 10.1.0.0/16")
		}
		if pacIsInNet(net.ParseIP("10.2.2.3"), net.ParseIP("10.1.0.0"), net.ParseIP("255.255.0.0")) {
			t.Error("10.2.2.3 should not be in 10.1.0.0/16")
		}
		if pacIsInNet(net.ParseIP("::1"), net.ParseIP("10.0.0.0"), net.ParseIP("255.0.0.0")) {
			t.Error("IPv6 should not match an IPv4 net")
		}
	})
}

func TestPacWeekdayRange(t *testing.T) {
	now := time.Date(2026, time.June, 3, 12, 0, 0, 0, time.UTC)
	names := []string{"SUN", "MON", "TUE", "WED", "THU", "FRI", "SAT"}
	today := names[now.Weekday()]
	tomorrow := names[(int(now.Weekday())+1)%7]
	yesterday := names[(int(now.Weekday())+6)%7]

	if !pacWeekdayRange(now, []string{today}) {
		t.Error("today should match single")
	}
	if pacWeekdayRange(now, []string{tomorrow}) {
		t.Error("tomorrow single should not match")
	}
	if !pacWeekdayRange(now, []string{yesterday, tomorrow}) {
		t.Error("yesterday..tomorrow should include today")
	}
	if pacWeekdayRange(now, []string{tomorrow, yesterday}) {
		t.Error("tomorrow..yesterday (wrap) should exclude today")
	}
	if !pacWeekdayRange(now, []string{today, "GMT"}) {
		t.Error("trailing GMT should be accepted")
	}
	if pacWeekdayRange(now, []string{"XYZ"}) {
		t.Error("invalid weekday should not match")
	}
}

func TestPacTimeRange(t *testing.T) {
	now := time.Date(2026, time.June, 3, 12, 0, 0, 0, time.UTC) // 12:00:00
	cases := []struct {
		args []string
		want bool
	}{
		{[]string{"12"}, true},
		{[]string{"13"}, false},
		{[]string{"9", "17"}, true},
		{[]string{"13", "17"}, false},
		{[]string{"12", "0", "13", "0"}, true},
		{[]string{"22", "6"}, false},  // wraps past midnight; noon excluded
		{[]string{"12", "GMT"}, true}, // now is already UTC
		{[]string{"x"}, false},        // non-numeric
	}
	for _, c := range cases {
		if got := pacTimeRange(now, c.args); got != c.want {
			t.Errorf("timeRange(%v)=%v want %v", c.args, got, c.want)
		}
	}
}

func TestPacDateRange(t *testing.T) {
	now := time.Date(2026, time.June, 3, 12, 0, 0, 0, time.UTC) // 3 Jun 2026
	cases := []struct {
		args []string
		want bool
	}{
		{[]string{"3"}, true},                                     // single day == today (3)
		{[]string{"4"}, false},                                    // single day != today
		{[]string{"JUN"}, true},                                   // single month == current
		{[]string{"JUL"}, false},                                  // single month != current
		{[]string{"2026"}, true},                                  // single year == current
		{[]string{"2025"}, false},                                 // single year != current
		{[]string{"1", "5"}, true},                                // day range
		{[]string{"10", "20"}, false},                             // day range
		{[]string{"JAN", "DEC"}, true},                            // month range
		{[]string{"JUL", "AUG"}, false},                           // month range
		{[]string{"NOV", "FEB"}, false},                           // wrap month range
		{[]string{"2020", "2030"}, true},                          // year range
		{[]string{"2000", "2020"}, false},                         // year range
		{[]string{"1", "JUN", "2026", "30", "JUN", "2026"}, true}, // full form
		{[]string{"1", "JUL", "2026", "30", "JUL", "2026"}, false},
		{[]string{"1", "5", "GMT"}, true},
		{[]string{"x", "y"}, false},
	}
	for _, c := range cases {
		if got := pacDateRange(now, c.args); got != c.want {
			t.Errorf("dateRange(%v)=%v want %v", c.args, got, c.want)
		}
	}
}
