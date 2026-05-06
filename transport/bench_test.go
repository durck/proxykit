package transport_test

import (
	"context"
	"net"
	"net/http"
	"testing"

	"github.com/durck/proxykit/transport"
)

// BenchmarkConnect_Dial measures the cost of establishing a CONNECT
// tunnel through a local in-process proxy (200 OK + tunnel pipe).
// Dominated by syscall overhead from two TCP dials per iteration —
// useful as a regression baseline, not as an absolute throughput
// number.
func BenchmarkConnect_Dial(b *testing.B) {
	backend := httpEcho(b)

	proxy := connectProxy(b, func(req *http.Request, conn net.Conn) {
		conn.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))
		tunnelTo(req.URL.Host, conn)
	})

	c := &transport.Connect{ProxyURL: mustParseURL(b, proxy.URL)}
	target, ok := backendAddr(backend.URL)
	if !ok {
		b.Fatalf("strip http://: %s", backend.URL)
	}
	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		conn, err := c.DialContext(ctx, "tcp", target)
		if err != nil {
			b.Fatalf("DialContext: %v", err)
		}
		conn.Close()
	}
}

func backendAddr(rawURL string) (string, bool) {
	const prefix = "http://"
	if len(rawURL) <= len(prefix) || rawURL[:len(prefix)] != prefix {
		return "", false
	}
	return rawURL[len(prefix):], true
}
