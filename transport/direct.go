// Package transport contains concrete dial implementations selected by
// the top-level [proxykit.Dialer].
package transport

import (
	"context"
	"net"
	"time"
)

// Direct dials network addresses without a proxy.
type Direct struct {
	// Timeout bounds a single dial attempt. Zero means no timeout.
	Timeout time.Duration
}

// DialContext opens a connection to address via net.Dialer, honouring
// d.Timeout and the supplied context.
func (d *Direct) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	nd := net.Dialer{Timeout: d.Timeout}
	return nd.DialContext(ctx, network, address)
}
