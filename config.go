package proxykit

import "time"

// Config configures a proxy [Dialer] or HTTP transport.
type Config struct {
	// Manual is an explicit proxy URL such as "http://proxy:8080" or
	// "socks5://1.2.3.4:1080". When set, it takes precedence over
	// AutoDetect. Empty means no manual override.
	Manual string

	// AutoDetect enables system proxy detection (environment variables,
	// Windows WinINET registry). Consulted only if Manual is empty.
	AutoDetect bool

	// Timeout bounds a single dial attempt to the proxy or destination.
	// Zero means no timeout.
	Timeout time.Duration

	// OnLog, when non-nil, receives diagnostic messages. The level is
	// one of "debug", "info", "warn", "error".
	OnLog func(level, msg string)
}
