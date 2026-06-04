//go:build proxykit_pac

package pac

import (
	"context"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dop251/goja"
)

// pacResolverTimeout bounds each DNS lookup a PAC host function performs.
const pacResolverTimeout = 5 * time.Second

// pacClock returns the current time; overridable in tests for the
// weekday/date/time range helpers.
var pacClock = time.Now

// pacResolver supplies the network-dependent inputs the PAC host
// functions need (dnsResolve, isResolvable, isInNet, myIpAddress). It is
// injected so tests can run without real DNS.
type pacResolver interface {
	lookupIP(host string) []net.IP
	myIP() net.IP
}

// systemPACResolver is the production resolver backed by the OS.
type systemPACResolver struct{}

func (systemPACResolver) lookupIP(host string) []net.IP {
	ctx, cancel := context.WithTimeout(context.Background(), pacResolverTimeout)
	defer cancel()
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
	if err != nil {
		return nil
	}
	return ips
}

func (systemPACResolver) myIP() net.IP {
	addrs, err := net.InterfaceAddrs()
	if err == nil {
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok {
				if ip4 := ipnet.IP.To4(); ip4 != nil && !ip4.IsLoopback() {
					return ip4
				}
			}
		}
	}
	return net.IPv4(127, 0, 0, 1)
}

// --- pure helpers (unit-tested directly) --------------------------------

func pacIsPlainHostName(host string) bool { return !strings.Contains(host, ".") }

func pacDNSDomainIs(host, domain string) bool {
	host, domain = strings.ToLower(host), strings.ToLower(domain)
	return len(host) >= len(domain) && strings.HasSuffix(host, domain)
}

func pacLocalHostOrDomainIs(host, hostdom string) bool {
	host, hostdom = strings.ToLower(host), strings.ToLower(hostdom)
	if host == hostdom {
		return true
	}
	// A plain hostname matches if it equals the hostname part of hostdom.
	if !strings.Contains(host, ".") {
		if i := strings.IndexByte(hostdom, '.'); i >= 0 {
			return host == hostdom[:i]
		}
	}
	return false
}

func pacDNSDomainLevels(host string) int { return strings.Count(host, ".") }

// shExpCache memoizes compiled glob patterns. A nil *regexp.Regexp is
// cached for patterns that fail to compile.
var shExpCache sync.Map // shexp string -> *regexp.Regexp

// pacShExpMatch matches str against a shell glob (only * and ?) compiled
// to an anchored RE2 pattern — linear time, no backtracking (no ReDoS).
// Compiled patterns are cached, since FindProxyForURL often calls
// shExpMatch repeatedly with constant patterns.
func pacShExpMatch(str, shexp string) bool {
	v, ok := shExpCache.Load(shexp)
	if !ok {
		v = compileShExp(shexp)
		shExpCache.Store(shexp, v)
	}
	re, _ := v.(*regexp.Regexp)
	if re == nil {
		return false
	}
	return re.MatchString(str)
}

func compileShExp(shexp string) *regexp.Regexp {
	var b strings.Builder
	b.WriteByte('^')
	for _, r := range shexp {
		switch r {
		case '*':
			b.WriteString(".*")
		case '?':
			b.WriteByte('.')
		default:
			b.WriteString(regexp.QuoteMeta(string(r)))
		}
	}
	b.WriteByte('$')
	re, err := regexp.Compile(b.String())
	if err != nil {
		return nil
	}
	return re
}

// pacIsInNet reports whether ip lies in pattern/mask (classic IPv4 only).
func pacIsInNet(ip, pattern, mask net.IP) bool {
	ip4, pat4, mask4 := ip.To4(), pattern.To4(), mask.To4()
	if ip4 == nil || pat4 == nil || mask4 == nil {
		return false
	}
	for i := 0; i < net.IPv4len; i++ {
		if ip4[i]&mask4[i] != pat4[i]&mask4[i] {
			return false
		}
	}
	return true
}

var pacWeekdays = map[string]time.Weekday{
	"SUN": time.Sunday, "MON": time.Monday, "TUE": time.Tuesday, "WED": time.Wednesday,
	"THU": time.Thursday, "FRI": time.Friday, "SAT": time.Saturday,
}

// pacWeekdayRange implements weekdayRange(wd1 [,wd2] [,"GMT"]): true when
// now's weekday is wd1, or within the inclusive cyclic range wd1..wd2.
func pacWeekdayRange(now time.Time, args []string) bool {
	args, now = applyGMT(args, now)
	if len(args) == 0 {
		return false
	}
	wd1, ok := pacWeekdays[strings.ToUpper(strings.TrimSpace(args[0]))]
	if !ok {
		return false
	}
	today := now.Weekday()
	if len(args) == 1 {
		return today == wd1
	}
	wd2, ok := pacWeekdays[strings.ToUpper(strings.TrimSpace(args[1]))]
	if !ok {
		return today == wd1
	}
	if wd1 <= wd2 {
		return today >= wd1 && today <= wd2
	}
	return today >= wd1 || today <= wd2 // wraps over the weekend
}

// pacTimeRange implements the numeric forms of timeRange (1, 2, 4 or 6
// numeric args, plus optional trailing "GMT"): hour; hour1-hour2;
// h1:m1-h2:m2; h1:m1:s1-h2:m2:s2. Comparison is on seconds-of-day with an
// inclusive lower and exclusive upper bound, supporting ranges that wrap
// past midnight.
func pacTimeRange(now time.Time, args []string) bool {
	args, now = applyGMT(args, now)
	nums, ok := parseInts(args)
	if !ok {
		return false
	}
	sec := func(h, m, s int) int { return h*3600 + m*60 + s }
	cur := sec(now.Hour(), now.Minute(), now.Second())
	var lo, hi int
	switch len(nums) {
	case 1:
		return now.Hour() == nums[0]
	case 2:
		lo, hi = sec(nums[0], 0, 0), sec(nums[1], 0, 0)
	case 4:
		lo, hi = sec(nums[0], nums[1], 0), sec(nums[2], nums[3], 0)
	case 6:
		lo, hi = sec(nums[0], nums[1], nums[2]), sec(nums[3], nums[4], nums[5])
	default:
		return false
	}
	if lo <= hi {
		return cur >= lo && cur < hi
	}
	return cur >= lo || cur < hi // wraps past midnight
}

var pacMonths = map[string]time.Month{
	"JAN": time.January, "FEB": time.February, "MAR": time.March, "APR": time.April,
	"MAY": time.May, "JUN": time.June, "JUL": time.July, "AUG": time.August,
	"SEP": time.September, "OCT": time.October, "NOV": time.November, "DEC": time.December,
}

// pacDateRange implements the single-kind 2-arg forms of dateRange
// (day1-day2, month1-month2, year1-year2) and the full 6-arg form
// (day1, month1, year1, day2, month2, year2), each with optional trailing
// "GMT". Mixed 4-arg forms are uncommon and treated as no match.
func pacDateRange(now time.Time, args []string) bool {
	args, now = applyGMT(args, now)
	day, mon, year := now.Day(), now.Month(), now.Year()
	switch len(args) {
	case 1:
		if m, ok := parseMonth(args[0]); ok {
			return mon == m
		}
		n, err := strconv.Atoi(strings.TrimSpace(args[0]))
		if err != nil {
			return false
		}
		if n > 31 { // a year
			return year == n
		}
		return day == n // a day of the month
	case 2:
		if m1, ok1 := parseMonth(args[0]); ok1 {
			if m2, ok2 := parseMonth(args[1]); ok2 {
				return inCyclicMonth(mon, m1, m2)
			}
			return false
		}
		n1, e1 := strconv.Atoi(strings.TrimSpace(args[0]))
		n2, e2 := strconv.Atoi(strings.TrimSpace(args[1]))
		if e1 != nil || e2 != nil {
			return false
		}
		if n1 > 31 || n2 > 31 { // years
			return year >= n1 && year <= n2
		}
		return day >= n1 && day <= n2 // days of month
	case 6:
		d1, e1 := strconv.Atoi(strings.TrimSpace(args[0]))
		m1, mok1 := parseMonth(args[1])
		y1, e3 := strconv.Atoi(strings.TrimSpace(args[2]))
		d2, e4 := strconv.Atoi(strings.TrimSpace(args[3]))
		m2, mok2 := parseMonth(args[4])
		y2, e6 := strconv.Atoi(strings.TrimSpace(args[5]))
		if e1 != nil || e3 != nil || e4 != nil || e6 != nil || !mok1 || !mok2 {
			return false
		}
		lo := time.Date(y1, m1, d1, 0, 0, 0, 0, now.Location())
		hi := time.Date(y2, m2, d2, 23, 59, 59, int(time.Second-time.Nanosecond), now.Location())
		return !now.Before(lo) && !now.After(hi)
	default:
		return false
	}
}

func parseMonth(s string) (time.Month, bool) {
	m, ok := pacMonths[strings.ToUpper(strings.TrimSpace(s))]
	return m, ok
}

func inCyclicMonth(cur, m1, m2 time.Month) bool {
	if m1 <= m2 {
		return cur >= m1 && cur <= m2
	}
	return cur >= m1 || cur <= m2
}

// applyGMT strips a trailing "GMT" argument (if present) and converts now
// to UTC accordingly.
func applyGMT(args []string, now time.Time) ([]string, time.Time) {
	if len(args) > 0 && strings.EqualFold(strings.TrimSpace(args[len(args)-1]), "GMT") {
		return args[:len(args)-1], now.UTC()
	}
	return args, now
}

func parseInts(args []string) ([]int, bool) {
	out := make([]int, 0, len(args))
	for _, a := range args {
		n, err := strconv.Atoi(strings.TrimSpace(a))
		if err != nil {
			return nil, false
		}
		out = append(out, n)
	}
	return out, true
}

// registerPACHelpers installs the Netscape PAC host functions on vm,
// backed by res for the network-dependent ones.
func registerPACHelpers(vm *goja.Runtime, res pacResolver) error {
	arg := func(c goja.FunctionCall, i int) string {
		if i < len(c.Arguments) {
			return c.Arguments[i].String()
		}
		return ""
	}
	allArgs := func(c goja.FunctionCall) []string {
		out := make([]string, len(c.Arguments))
		for i, a := range c.Arguments {
			out[i] = a.String()
		}
		return out
	}
	resolveIPv4 := func(host string) net.IP {
		if ip := net.ParseIP(host); ip != nil {
			return ip
		}
		for _, ip := range res.lookupIP(host) {
			if ip.To4() != nil {
				return ip
			}
		}
		return nil
	}

	fns := map[string]func(goja.FunctionCall) goja.Value{
		"isPlainHostName": func(c goja.FunctionCall) goja.Value {
			return vm.ToValue(pacIsPlainHostName(arg(c, 0)))
		},
		"dnsDomainIs": func(c goja.FunctionCall) goja.Value {
			return vm.ToValue(pacDNSDomainIs(arg(c, 0), arg(c, 1)))
		},
		"localHostOrDomainIs": func(c goja.FunctionCall) goja.Value {
			return vm.ToValue(pacLocalHostOrDomainIs(arg(c, 0), arg(c, 1)))
		},
		"dnsDomainLevels": func(c goja.FunctionCall) goja.Value {
			return vm.ToValue(pacDNSDomainLevels(arg(c, 0)))
		},
		"shExpMatch": func(c goja.FunctionCall) goja.Value {
			return vm.ToValue(pacShExpMatch(arg(c, 0), arg(c, 1)))
		},
		"weekdayRange": func(c goja.FunctionCall) goja.Value {
			return vm.ToValue(pacWeekdayRange(pacClock(), allArgs(c)))
		},
		"timeRange": func(c goja.FunctionCall) goja.Value {
			return vm.ToValue(pacTimeRange(pacClock(), allArgs(c)))
		},
		"dateRange": func(c goja.FunctionCall) goja.Value {
			return vm.ToValue(pacDateRange(pacClock(), allArgs(c)))
		},
		"isResolvable": func(c goja.FunctionCall) goja.Value {
			return vm.ToValue(len(res.lookupIP(arg(c, 0))) > 0)
		},
		"dnsResolve": func(c goja.FunctionCall) goja.Value {
			if ip := resolveIPv4(arg(c, 0)); ip != nil {
				return vm.ToValue(ip.String())
			}
			return goja.Null()
		},
		"myIpAddress": func(c goja.FunctionCall) goja.Value {
			return vm.ToValue(res.myIP().String())
		},
		"isInNet": func(c goja.FunctionCall) goja.Value {
			ip := resolveIPv4(arg(c, 0))
			pat, mask := net.ParseIP(arg(c, 1)), net.ParseIP(arg(c, 2))
			if ip == nil || pat == nil || mask == nil {
				return vm.ToValue(false)
			}
			return vm.ToValue(pacIsInNet(ip, pat, mask))
		},
	}
	for name, fn := range fns {
		if err := vm.Set(name, fn); err != nil {
			return err
		}
	}
	return nil
}
