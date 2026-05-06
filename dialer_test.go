package proxykit_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/durck/proxykit"
)

// TestNewDialer_Direct verifies that NewDialer with no proxy configured
// dials directly: we open a raw TCP connection to an httptest server
// and round-trip a minimal HTTP/1.1 request.
func TestNewDialer_Direct(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "hello")
	}))
	t.Cleanup(srv.Close)

	addr := strings.TrimPrefix(srv.URL, "http://")

	d := proxykit.NewDialer(proxykit.Config{})
	conn, err := d.DialContext(context.Background(), "tcp", addr)
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	req := "GET / HTTP/1.1\r\nHost: " + addr + "\r\nConnection: close\r\n\r\n"
	if _, err := io.WriteString(conn, req); err != nil {
		t.Fatalf("write: %v", err)
	}

	body, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !strings.Contains(string(body), "hello") {
		t.Errorf("response %q does not contain %q", body, "hello")
	}
}

// TestNewDialer_ReturnsNonNil guards against the obvious regression of
// returning a nil Dialer when the caller has no proxy config.
func TestNewDialer_ReturnsNonNil(t *testing.T) {
	if d := proxykit.NewDialer(proxykit.Config{}); d == nil {
		t.Fatal("NewDialer returned nil")
	}
}
