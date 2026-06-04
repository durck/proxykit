package proxykit

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"

	"github.com/durck/proxykit/auth"
	"github.com/durck/proxykit/detect"
	"github.com/durck/proxykit/internal/pac"
	"github.com/durck/proxykit/transport"
)

// Dialer establishes outbound TCP connections, optionally through a
// proxy. The DialContext signature matches net.Dialer.DialContext so
// the result drops into http.Transport unchanged.
type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// NewDialer returns a Dialer wired according to cfg.
//
// Resolution order:
//
//  1. cfg.Manual (when non-empty) is tried first.
//  2. cfg.AutoDetect runs every registered detector (env vars,
//     WinINET on Windows) and appends each candidate.
//
// For each resolved proxy URL a transport is selected by scheme
// (http/https → CONNECT, socks/socks5 → SOCKS5). Userinfo embedded in
// the URL is converted into either an [auth.Basic] prepended to
// cfg.Auth (CONNECT proxies) or RFC 1929 SOCKS authentication.
//
// When several candidates resolve, dial attempts walk the chain in
// order and return the first success — preserving the precedence
// model in reverse_ssh. With no usable proxy the Dialer falls back
// to a direct net.Dialer with cfg.Timeout.
//
// PAC: when cfg.Manual is empty and a PAC source is configured
// (cfg.PAC/PACURL, a detected OS PAC URL, or cfg.WPAD) the returned
// Dialer chooses a proxy per destination by evaluating the PAC script.
// This requires building with -tags proxykit_pac; otherwise the PAC
// source is logged and ignored and routing degrades to the static chain.
func NewDialer(cfg Config) Dialer {
	entries, pacURLs := resolveEntries(cfg)
	static := staticDialer(entries, cfg)

	// PAC takes over per-destination routing when a source is configured
	// and the build supports it. An explicit Manual proxy always wins, so
	// PAC is skipped when Manual is set. Without -tags proxykit_pac a
	// configured PAC source is logged and ignored (degrade to static).
	if cfg.Manual == "" && hasPACSource(cfg, pacURLs) {
		if !pac.Supported {
			logf(cfg.OnLog, "warn", "proxykit: a PAC source is configured but this build lacks PAC support; rebuild with -tags proxykit_pac")
			return static
		}
		return newPACDialer(cfg, pacURLs, static)
	}
	return static
}

// staticDialer builds the destination-independent dialer from resolved
// proxy entries: a single dialer, an ordered fallback chain, or Direct
// when none resolve.
func staticDialer(entries []proxyEntry, cfg Config) Dialer {
	dialers := make([]Dialer, 0, len(entries))
	for _, e := range entries {
		if d := dialerForEntry(e, cfg); d != nil {
			dialers = append(dialers, d)
		}
	}
	switch len(dialers) {
	case 0:
		return &transport.Direct{Timeout: cfg.Timeout}
	case 1:
		return dialers[0]
	default:
		return &fallbackDialer{dialers: dialers, log: cfg.OnLog}
	}
}

// proxyEntry is a parsed proxy candidate ready for transport
// construction.
type proxyEntry struct {
	url  *url.URL // parsed, normalised, no userinfo
	user string
	pass string
}

// resolveEntries collects proxy candidates from cfg.Manual and from every
// registered detector when cfg.AutoDetect is true. Invalid URLs are logged
// via cfg.OnLog and skipped. Detected PAC-URL candidates (URL empty,
// PACURL set) are not proxies: they are returned separately as pacURLs for
// the PAC path.
func resolveEntries(cfg Config) (entries []proxyEntry, pacURLs []string) {
	add := func(rawURL, user, pass string) {
		u, err := ParseProxyURL(rawURL)
		if err != nil {
			logf(cfg.OnLog, "warn", "proxykit: skipping invalid proxy URL %q: %v", redactProxyURL(rawURL), err)
			return
		}
		if u.User != nil {
			if user == "" {
				user = u.User.Username()
				if p, ok := u.User.Password(); ok {
					pass = p
				}
			}
			u.User = nil
		}
		entries = append(entries, proxyEntry{url: u, user: user, pass: pass})
	}

	if cfg.Manual != "" {
		add(cfg.Manual, "", "")
	}

	if cfg.AutoDetect {
		cs, err := detect.All()
		if err != nil {
			logf(cfg.OnLog, "warn", "proxykit: detect: %v", err)
		}
		for _, c := range cs {
			if c.PACURL != "" {
				pacURLs = append(pacURLs, c.PACURL)
				continue
			}
			add(c.URL, c.User, c.Pass)
		}
	}

	return entries, pacURLs
}

// dialerForEntry constructs the transport-level dialer for a single
// resolved proxy entry. Returns nil for unsupported schemes (which
// ParseProxyURL already rejects, but we keep the guard explicit).
func dialerForEntry(e proxyEntry, cfg Config) Dialer {
	switch e.url.Scheme {
	case "http", "https":
		authChain := cfg.Auth
		if e.user != "" {
			authChain = append([]auth.Authenticator{auth.Basic(e.user, e.pass)}, authChain...)
		}
		return &transport.Connect{
			ProxyURL: e.url,
			Timeout:  cfg.Timeout,
			Auth:     authChain,
		}
	case "socks", "socks5":
		s := &transport.SOCKS5{
			ProxyURL: e.url,
			Timeout:  cfg.Timeout,
		}
		if e.user != "" {
			s.Auth = &transport.SOCKS5Auth{Username: e.user, Password: e.pass}
		}
		return s
	}
	return nil
}

// fallbackDialer dials through a list of upstream dialers in order
// and returns the first that succeeds. All errors are joined into
// the final return value when every dialer fails.
type fallbackDialer struct {
	dialers []Dialer
	log     func(level, msg string)
}

func (f *fallbackDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	var errs []error
	for i, d := range f.dialers {
		if err := ctx.Err(); err != nil {
			errs = append(errs, err)
			break
		}
		conn, err := d.DialContext(ctx, network, address)
		if err == nil {
			return conn, nil
		}
		if f.log != nil {
			f.log("debug", fmt.Sprintf("proxykit: dialer %d failed: %v", i, err))
		}
		errs = append(errs, err)
	}
	return nil, errors.Join(errs...)
}

func logf(hook func(level, msg string), level, format string, args ...any) {
	if hook == nil {
		return
	}
	hook(level, fmt.Sprintf(format, args...))
}
