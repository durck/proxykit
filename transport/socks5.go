package transport

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"time"

	"golang.org/x/net/proxy"
)

// SOCKS5 dials destinations through a SOCKS5 proxy (RFC 1928 + RFC 1929
// for username/password). It is a thin wrapper over
// golang.org/x/net/proxy.SOCKS5 that honours context.Context.
//
// ProxyURL must have scheme socks or socks5. Credentials may be supplied
// either via the typed Auth field or as userinfo in ProxyURL; Auth takes
// precedence. Both are forwarded as RFC 1929 username/password
// authentication.
type SOCKS5 struct {
	// ProxyURL is the proxy address. Scheme must be socks or socks5.
	ProxyURL *url.URL

	// Auth, when non-nil with a non-empty Username, supplies RFC 1929
	// username/password credentials and takes precedence over any
	// userinfo in ProxyURL. When nil (or its Username is empty),
	// credentials are inferred from ProxyURL.User if present. An empty
	// Username never authenticates: RFC 1929 has no such form, so it
	// falls back rather than forcing a doomed handshake.
	Auth *SOCKS5Auth

	// Timeout bounds a single dial attempt to the proxy or destination.
	// Zero means no timeout.
	Timeout time.Duration
}

// SOCKS5Auth carries RFC 1929 username/password credentials for a SOCKS5
// proxy. Set it on [SOCKS5.Auth] to authenticate without embedding the
// credentials in ProxyURL.
type SOCKS5Auth struct {
	Username string
	Password string
}

// DialContext opens a TCP tunnel through s.ProxyURL to address.
func (s *SOCKS5) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, fmt.Errorf("proxykit: SOCKS5 requires tcp network, got %q", network)
	}
	if s.ProxyURL == nil {
		return nil, errors.New("proxykit: SOCKS5.ProxyURL is nil")
	}
	switch s.ProxyURL.Scheme {
	case "socks", "socks5":
	default:
		return nil, fmt.Errorf("proxykit: SOCKS5 requires socks or socks5 proxy scheme, got %q", s.ProxyURL.Scheme)
	}

	// The base net.Dialer.Timeout below bounds only the TCP connect to
	// the proxy, not the SOCKS handshake. When a Timeout is set but the
	// caller's context carries no deadline, derive one so a proxy that
	// stalls mid-handshake cannot hang the dial forever.
	if s.Timeout > 0 {
		if _, ok := ctx.Deadline(); !ok {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, s.Timeout)
			defer cancel()
		}
	}

	// Typed Auth wins over URL userinfo; fall back to ProxyURL.User for
	// backward compatibility when no typed credentials are given. An
	// empty Username is treated as "unset" rather than activating a
	// username/password handshake that RFC 1929 would reject.
	var auth *proxy.Auth
	switch {
	case s.Auth != nil && s.Auth.Username != "":
		auth = &proxy.Auth{User: s.Auth.Username, Password: s.Auth.Password}
	case s.ProxyURL.User != nil:
		pw, _ := s.ProxyURL.User.Password()
		auth = &proxy.Auth{User: s.ProxyURL.User.Username(), Password: pw}
	}

	base := &net.Dialer{Timeout: s.Timeout}
	d, err := proxy.SOCKS5("tcp", s.ProxyURL.Host, auth, base)
	if err != nil {
		return nil, fmt.Errorf("proxykit: SOCKS5 setup: %w", err)
	}

	// x/net/proxy.SOCKS5 returns a Dialer that also implements
	// proxy.ContextDialer. Prefer the ctx-aware path; fall back to
	// goroutine-based cancellation if the future drops the interface.
	if cd, ok := d.(proxy.ContextDialer); ok {
		return cd.DialContext(ctx, network, address)
	}

	type result struct {
		conn net.Conn
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		c, err := d.Dial(network, address)
		ch <- result{c, err}
	}()
	select {
	case <-ctx.Done():
		// Cannot cancel the underlying Dial; drain in the background
		// to avoid leaking the goroutine and close the conn if it
		// arrives.
		go func() {
			r := <-ch
			if r.conn != nil {
				r.conn.Close()
			}
		}()
		return nil, ctx.Err()
	case r := <-ch:
		return r.conn, r.err
	}
}
