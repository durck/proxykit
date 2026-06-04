// Package proxykit is a small, dependency-light client for outbound network
// connections through HTTP/HTTPS CONNECT and SOCKS5 proxies. It offers:
//
//   - Transports: HTTP CONNECT (over TCP or TLS), SOCKS5, and Direct.
//   - Authentication: None, Basic, NTLM, and Negotiate/Kerberos (Windows via
//     SSPI; Linux/macOS via jcmturner/gokrb5).
//   - System-proxy auto-detection: *_PROXY environment variables on every
//     platform; the Windows WinINET (HKCU) and WinHTTP (HKLM + IE) registries;
//     the Linux /etc/environment file and the GNOME and KDE desktop settings;
//     and the macOS system configuration via scutil.
//   - NO_PROXY bypass: destinations in Config.NoProxy (and, under AutoDetect,
//     the NO_PROXY environment variable) are dialled directly, overriding any
//     Manual, detected, or PAC-selected proxy.
//   - Optional PAC/WPAD: per-destination proxy selection by evaluating a
//     FindProxyForURL script, with DNS-based WPAD discovery. This needs a JS
//     engine and is gated behind the proxykit_pac build tag (see below).
//
// The package exposes a [Dialer] that satisfies the standard net.Dial
// signature, plus an [http.RoundTripper] adapter ([NewHTTPTransport]) for use
// with http.Client. The default build is cgo-free and fully static.
//
// # Quickstart
//
//	cfg := proxykit.Config{Manual: "http://proxy:8080"}
//	d := proxykit.NewDialer(cfg)
//	conn, err := d.DialContext(ctx, "tcp", "example.com:443")
//
// # Build tags
//
//   - proxykit_pac: enable PAC/WPAD evaluation (adds the pure-Go goja engine).
//     Off by default; a configured PAC source is otherwise ignored.
//   - proxykit_nokerberos: drop the gokrb5 dependency, after which
//     [auth.Negotiate] reports errors.ErrUnsupported on non-Windows.
//
// See the examples directory and the README for more usage patterns.
package proxykit
