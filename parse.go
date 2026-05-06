package proxykit

import (
	"errors"
	"fmt"
	"net"
	"net/url"
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
			return nil, fmt.Errorf("proxykit: invalid proxy URL %q: %w", s, err)
		}
	}

	scheme := strings.ToLower(u.Scheme)
	if !isSupportedScheme(scheme) {
		return nil, fmt.Errorf("proxykit: unsupported proxy scheme %q", u.Scheme)
	}
	u.Scheme = scheme

	if u.Host == "" {
		return nil, fmt.Errorf("proxykit: proxy URL %q has no host", s)
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
