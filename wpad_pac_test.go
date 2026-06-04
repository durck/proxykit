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

// TestWPADDiscoveryE2E drives the full WPAD path: discovery (via the
// wpadCandidateURLs seam) → fetch the wpad.dat → compile → route a dial.
func TestWPADDiscoveryE2E(t *testing.T) {
	pac := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, `function FindProxyForURL(url, host){ return "DIRECT"; }`)
	}))
	defer pac.Close()

	orig := wpadCandidateURLs
	wpadCandidateURLs = func() []string { return []string{pac.URL + "/wpad.dat"} }
	defer func() { wpadCandidateURLs = orig }()

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, "wpad-ok")
	}))
	defer backend.Close()
	addr := strings.TrimPrefix(backend.URL, "http://")

	d := NewDialer(Config{WPAD: true})
	if _, ok := d.(*pacDialer); !ok {
		t.Fatalf("WPAD should yield a *pacDialer, got %T", d)
	}
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
	if !strings.Contains(string(body), "wpad-ok") {
		t.Errorf("response %q does not contain wpad-ok", body)
	}
}
