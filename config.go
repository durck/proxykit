package proxykit

import (
	"time"

	"github.com/durck/proxykit/auth"
)

// Config configures a proxy [Dialer] or HTTP transport.
type Config struct {
	// Manual is an explicit proxy URL such as "http://proxy:8080" or
	// "socks5://1.2.3.4:1080". When set, it takes precedence over
	// AutoDetect. Empty means no manual override.
	Manual string

	// AutoDetect enables system proxy detection (environment variables,
	// Windows WinINET registry). It is independent of Manual: when both
	// are set, Manual is tried first and any detected proxies are
	// appended as fallbacks. When AutoDetect surfaces a system-configured
	// PAC URL it is used too (see PAC), but only in binaries built with
	// -tags proxykit_pac.
	AutoDetect bool

	// PAC is an inline Proxy Auto-Config script (the JavaScript body
	// defining FindProxyForURL). When set it takes precedence over PACURL
	// and any detected PAC URL. Evaluating it requires building with
	// -tags proxykit_pac; otherwise it is ignored with a warning.
	PAC string

	// PACURL is the URL of a .pac script to fetch and evaluate. Ignored
	// when PAC is set. Requires -tags proxykit_pac.
	PACURL string

	// WPAD enables ACTIVE DNS-based PAC discovery (probing
	// http://wpad.<domain>/wpad.dat up the host's domain). It is a
	// separate opt-in from AutoDetect because a rogue wpad host on the
	// network can serve an attacker-controlled PAC; enable it only on
	// trusted networks. Requires -tags proxykit_pac.
	WPAD bool

	// NoProxy is a comma-separated list of destinations that must be reached
	// directly, bypassing any proxy (Manual, AutoDetect, or PAC). It uses the
	// standard NO_PROXY syntax: a domain suffix (with or without a leading
	// dot, e.g. "corp.local" or ".corp.local"), an IP or CIDR (e.g.
	// "10.0.0.0/8"), a "host:port", or "*" to bypass everything. Matching is
	// case-insensitive. Loopback destinations (localhost, 127.0.0.0/8, ::1)
	// are always reached directly whenever a list is set, following the usual
	// convention. When AutoDetect is set, the environment's NO_PROXY/no_proxy
	// is merged in. Empty disables bypass.
	NoProxy string

	// Auth is the ordered list of Authenticators tried on HTTP 407
	// from a CONNECT proxy. The transport matches each Authenticator's
	// Scheme against the proxy-advertised Proxy-Authenticate values.
	Auth []auth.Authenticator

	// Timeout bounds a single dial attempt to the proxy or destination.
	// Zero means no timeout. When several proxies resolve into a fallback
	// chain the timeout applies per attempt, so the worst-case total dial
	// time is len(chain) × Timeout; use the context deadline to cap the
	// whole operation.
	Timeout time.Duration

	// OnLog, when non-nil, receives diagnostic messages. The level is
	// one of "debug", "info", "warn", "error".
	OnLog func(level, msg string)
}
