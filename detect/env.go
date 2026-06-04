package detect

import (
	"net/url"

	"golang.org/x/net/http/httpproxy"
)

// EnvDetector reads the standard *_PROXY environment variables via
// golang.org/x/net/http/httpproxy.FromEnvironment, which honours both
// upper-case (HTTP_PROXY, HTTPS_PROXY, NO_PROXY) and lower-case
// (http_proxy, https_proxy, no_proxy) names per the longstanding
// libcurl convention.
//
// At most two candidates are returned (one for HTTPProxy, one for
// HTTPSProxy); duplicates are coalesced.
type EnvDetector struct{}

func init() {
	Default = append(Default, EnvDetector{})
}

// Detect returns the proxy candidates implied by the current process
// environment.
func (EnvDetector) Detect() ([]Candidate, error) {
	cfg := httpproxy.FromEnvironment()

	var out []Candidate
	if c, ok := candidateFromRaw(cfg.HTTPProxy, "env"); ok {
		out = append(out, c)
	}
	if c, ok := candidateFromRaw(cfg.HTTPSProxy, "env"); ok {
		if len(out) == 0 || out[0].URL != c.URL || out[0].User != c.User {
			out = append(out, c)
		}
	}
	return out, nil
}

// EnvNoProxy returns the no-proxy bypass list from the process environment
// (NO_PROXY/no_proxy), as parsed by golang.org/x/net/http/httpproxy. It is
// empty when unset. EnvDetector itself only surfaces proxy candidates and
// intentionally leaves bypass matching to the caller; this exposes the raw
// list so the dialer can honour it.
func EnvNoProxy() string {
	return httpproxy.FromEnvironment().NoProxy
}

// candidateFromRaw splits an inline-userinfo proxy URL into a
// Candidate with userinfo extracted into User/Pass and stripped from
// the URL string.
func candidateFromRaw(raw, source string) (Candidate, bool) {
	if raw == "" {
		return Candidate{}, false
	}
	c := Candidate{URL: raw, From: source}
	u, err := url.Parse(raw)
	if err != nil || u.User == nil {
		return c, true
	}
	c.User = u.User.Username()
	if p, ok := u.User.Password(); ok {
		c.Pass = p
	}
	stripped := *u
	stripped.User = nil
	c.URL = stripped.String()
	return c, true
}
