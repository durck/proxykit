package proxykit

import (
	"context"
	"net"

	"github.com/durck/proxykit/transport"
)

// Dialer establishes outbound TCP connections, optionally through a
// proxy. The DialContext signature matches net.Dialer.DialContext so
// the result drops into http.Transport unchanged.
type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// NewDialer returns a Dialer configured per cfg.
//
// In the current step only direct dial is wired; proxy dispatch
// (Manual override and AutoDetect) is added in a later step.
func NewDialer(cfg Config) Dialer {
	return &transport.Direct{Timeout: cfg.Timeout}
}
