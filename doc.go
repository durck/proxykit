// Package proxykit provides a small, dependency-light client for outbound
// connections through HTTP CONNECT and SOCKS5 proxies, with optional
// system-proxy auto-detection and pluggable authentication (Basic, NTLM,
// Negotiate/Kerberos — Windows SSPI, or Linux/macOS via jcmturner/gokrb5).
//
// The package exposes a [Dialer] that satisfies the standard net.Dial
// signature, plus an [http.RoundTripper] adapter for use with http.Client.
//
// # Quickstart
//
//	cfg := proxykit.Config{Manual: "http://proxy:8080"}
//	d := proxykit.NewDialer(cfg)
//	conn, err := d.DialContext(ctx, "tcp", "example.com:443")
//
// See the examples directory for more usage patterns.
package proxykit
