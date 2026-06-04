package proxykit

import (
	"context"
	"net"
	"net/url"
	"strings"

	"golang.org/x/net/http/httpproxy"

	"github.com/durck/proxykit/detect"
)

// resolveNoProxy combines the explicit Config.NoProxy with the environment's
// NO_PROXY/no_proxy. The environment list is consulted only when AutoDetect is
// enabled, matching how env proxies are sourced; the explicit list always
// applies. Either may be empty; the result is a single comma-joined list
// suitable for newNoProxyMatcher.
func resolveNoProxy(cfg Config) string {
	parts := make([]string, 0, 2)
	if cfg.NoProxy != "" {
		parts = append(parts, cfg.NoProxy)
	}
	if cfg.AutoDetect {
		if env := detect.EnvNoProxy(); env != "" {
			parts = append(parts, env)
		}
	}
	return strings.Join(parts, ",")
}

// noProxyMatcher decides whether a destination address must bypass the proxy.
// It reuses golang.org/x/net/http/httpproxy's well-tested NO_PROXY semantics
// (suffix and leading-dot matches, CIDR, host:port, "*", IPv6, case-folding)
// rather than reimplementing them: a sentinel proxy is configured so that
// ProxyFunc returns nil exactly for the hosts the no-proxy list exempts.
type noProxyMatcher struct {
	proxyFunc func(*url.URL) (*url.URL, error)
}

// newNoProxyMatcher builds a matcher for the given comma-separated no-proxy
// list. It returns nil when the list is empty, so callers can skip wrapping
// the dialer entirely (zero overhead) when no bypass is configured.
func newNoProxyMatcher(list string) *noProxyMatcher {
	if strings.TrimSpace(list) == "" {
		return nil
	}
	cfg := &httpproxy.Config{
		HTTPProxy:  "http://proxy.invalid",
		HTTPSProxy: "http://proxy.invalid",
		NoProxy:    list,
	}
	return &noProxyMatcher{proxyFunc: cfg.ProxyFunc()}
}

// bypass reports whether address ("host:port") is exempt from proxying. A nil
// matcher never bypasses.
func (m *noProxyMatcher) bypass(address string) bool {
	if m == nil {
		return false
	}
	// A dial address is "host:port". If it does not parse, fail safe to the
	// proxy path: httpproxy treats an unparseable address as "do not proxy",
	// which must not be mistaken here for a no-proxy match (silent direct dial).
	if _, _, err := net.SplitHostPort(address); err != nil {
		return false
	}
	// Scheme is irrelevant to NO_PROXY matching; the sentinel proxy is set for
	// both http and https. ProxyFunc returns a nil proxy exactly when the host
	// matches the no-proxy list (or is loopback, which is always bypassed).
	proxyURL, err := m.proxyFunc(&url.URL{Scheme: "http", Host: address})
	return err == nil && proxyURL == nil
}

// bypassDialer sends NO_PROXY-matched destinations straight to the direct
// dialer, and routes everything else through the wrapped proxied dialer.
type bypassDialer struct {
	matcher *noProxyMatcher
	proxied Dialer
	direct  Dialer
}

func (b *bypassDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if b.matcher.bypass(address) {
		return b.direct.DialContext(ctx, network, address)
	}
	return b.proxied.DialContext(ctx, network, address)
}
