//go:build proxykit_pac

package proxykit

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNewDialer_PACActiveWithTag(t *testing.T) {
	d := NewDialer(Config{PAC: `function FindProxyForURL(u, h){ return "DIRECT"; }`})
	if _, ok := d.(*pacDialer); !ok {
		t.Fatalf("want *pacDialer with -tags proxykit_pac, got %T", d)
	}
}

// TestPACDialer_DirectE2E drives the full pacDialer path on a build with
// the tag: an inline PAC returns DIRECT, and a dial reaches a live server.
func TestPACDialer_DirectE2E(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, "pac-ok")
	}))
	defer srv.Close()
	addr := strings.TrimPrefix(srv.URL, "http://")

	d := NewDialer(Config{PAC: `function FindProxyForURL(url, host){ return "DIRECT"; }`})
	conn, err := d.DialContext(context.Background(), "tcp", addr)
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer conn.Close()

	io.WriteString(conn, "GET / HTTP/1.1\r\nHost: "+addr+"\r\nConnection: close\r\n\r\n")
	body, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !strings.Contains(string(body), "pac-ok") {
		t.Errorf("response %q does not contain pac-ok", body)
	}
}
