package proxykit

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
)

// ParseProxyURL parses a proxy address into a [*url.URL].
//
// It accepts URLs with scheme http, https, socks, or socks5, plus bare
// "host:port" or "host" (treated as http on the default port).
//
// The returned URL always has Host populated with an explicit port.
// Default ports per scheme: http=80, https=443, socks/socks5=1080.
//
// Unsupported schemes (socks4, socks4a, ftp, ...) and empty input
// return an error.
func ParseProxyURL(s string) (*url.URL, error) {
	if s == "" {
		return nil, errors.New("proxykit: empty proxy URL")
	}

	u, err := url.Parse(s)
	// "host:port" parses with Scheme set to the host and Opaque to the
	// port; "host" parses with no scheme. Both should be retried as
	// http://host[:port].
	retryAsBare := err != nil || u.Scheme == "" || u.Opaque != ""
	if retryAsBare {
		u, err = url.Parse("http://" + s)
		if err != nil {
			return nil, fmt.Errorf("proxykit: invalid proxy URL %q: %w", redactProxyURL(s), err)
		}
	}

	scheme := strings.ToLower(u.Scheme)
	if !isSupportedScheme(scheme) {
		return nil, fmt.Errorf("proxykit: unsupported proxy scheme %q", u.Scheme)
	}
	u.Scheme = scheme

	if u.Host == "" {
		return nil, fmt.Errorf("proxykit: proxy URL %q has no host", redactProxyURL(s))
	}

	if u.Port() == "" {
		u.Host = net.JoinHostPort(u.Hostname(), defaultPort(scheme))
	}

	return u, nil
}

func isSupportedScheme(s string) bool {
	switch s {
	case "http", "https", "socks", "socks5":
		return true
	}
	return false
}

func defaultPort(scheme string) string {
	switch scheme {
	case "https":
		return "443"
	case "socks", "socks5":
		return "1080"
	default:
		return "80"
	}
}

// schemeAuthority matches a leading "scheme://" so the userinfo that
// follows can be located even in strings url.Parse rejects. It is
// anchored and strict (RE2, linear time), so a "://" sitting inside a
// password cannot be mistaken for the scheme separator.
var schemeAuthority = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9+.-]*://`)

// redactProxyURL strips any embedded password from a proxy URL so it is
// safe to log or wrap in an error. A cleanly parsed URL with userinfo is
// redacted via url.URL.Redacted; otherwise — whether url.Parse rejected
// the string (e.g. a control character) or mis-parsed it so the userinfo
// went unrecognised (e.g. "user:pass@host" read as scheme "user") — the
// userinfo is located by hand and its password masked.
//
// The userinfo is everything before the last '@' (the same boundary
// url.Parse uses), after any leading scheme://. The password runs from
// the first ':' to that '@', so values containing '/', spaces, control
// characters or extra '@' signs are masked too. Strings with no
// "user:password@" segment are returned unchanged.
func redactProxyURL(raw string) string {
	if u, err := url.Parse(raw); err == nil && u.User != nil {
		return u.Redacted()
	}
	at := strings.LastIndexByte(raw, '@')
	if at < 0 {
		return raw // no userinfo, nothing to mask
	}
	start := 0
	if loc := schemeAuthority.FindStringIndex(raw); loc != nil {
		start = loc[1]
	}
	if start > at {
		return raw // '@' precedes the authority — not userinfo
	}
	colon := strings.IndexByte(raw[start:at], ':')
	if colon < 0 {
		return raw // username only, no password to mask
	}
	return raw[:start+colon+1] + "xxxxx" + raw[at:]
}
