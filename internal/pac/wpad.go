package pac

import (
	"os"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// CandidateWPADURLs is the seam (overridable in tests) returning the
// ordered list of wpad.dat URLs to probe for active DNS-WPAD discovery.
var CandidateWPADURLs = systemWPADURLs

func systemWPADURLs() []string {
	domains := wpadDomains(systemHostname(), systemSearchDomains())
	urls := make([]string, 0, len(domains))
	for _, d := range domains {
		urls = append(urls, "http://wpad."+d+"/wpad.dat")
	}
	return urls
}

// wpadDomains derives the ordered, de-duplicated list of domains to probe
// from the host's FQDN domain part and the resolv.conf search domains.
func wpadDomains(hostname string, searchDomains []string) []string {
	var out []string
	seen := map[string]struct{}{}
	add := func(d string) {
		if d == "" {
			return
		}
		if _, ok := seen[d]; ok {
			return
		}
		seen[d] = struct{}{}
		out = append(out, d)
	}

	if i := strings.IndexByte(hostname, '.'); i >= 0 {
		for _, d := range domainWalk(hostname[i+1:]) {
			add(d)
		}
	}
	for _, sd := range searchDomains {
		for _, d := range domainWalk(sd) {
			add(d)
		}
	}
	return out
}

// domainWalk returns domain and each parent down to — but never above —
// the registrable domain (eTLD+1). A domain that is itself a public suffix
// (e.g. "co.uk") or a bare TLD yields nothing, so WPAD never probes a
// public registry like wpad.com.
func domainWalk(domain string) []string {
	domain = strings.Trim(strings.ToLower(domain), ".")
	if domain == "" {
		return nil
	}
	reg, err := publicsuffix.EffectiveTLDPlusOne(domain)
	if err != nil {
		return nil // public suffix / TLD / invalid — do not probe
	}
	var out []string
	for cur := domain; ; {
		out = append(out, cur)
		if cur == reg {
			break
		}
		i := strings.IndexByte(cur, '.')
		if i < 0 || len(cur) <= len(reg) {
			break // safety: never ascend past the registrable domain
		}
		cur = cur[i+1:]
	}
	return out
}

func systemHostname() string {
	h, err := os.Hostname()
	if err != nil {
		return ""
	}
	return h
}

// systemSearchDomains parses the "search"/"domain" directives from
// /etc/resolv.conf. On platforms without that file (Windows) it returns
// nil, so DNS-WPAD there relies on the FQDN alone (a documented
// limitation).
func systemSearchDomains() []string {
	data, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return nil
	}
	return parseResolvSearch(string(data))
}

// parseResolvSearch extracts domain suffixes from resolv.conf content: all
// arguments of a "search" line and the single argument of a "domain" line,
// per resolv.conf(5).
func parseResolvSearch(content string) []string {
	var out []string
	for _, line := range strings.Split(content, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		switch fields[0] {
		case "search":
			out = append(out, fields[1:]...)
		case "domain":
			out = append(out, fields[1]) // domain takes a single argument
		}
	}
	return out
}
