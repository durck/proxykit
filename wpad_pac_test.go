//go:build proxykit_pac

package proxykit

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/durck/proxykit/internal/pac"
)

// TestWPADDiscoveryE2E drives the full WPAD path end to end: discovery (via
// the wpadCandidateURLs seam) → fetch the wpad.dat → compile → route the
// dial through the PROXY the script selects (a mock CONNECT proxy), proving
// both WPAD discovery and PROXY routing together.
func TestWPADDiscoveryE2E(t *testing.T) {
	var hits int32
	proxyAddr := startConnectProxy(t, &hits)

	pacSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, `function FindProxyForURL(url, host){ return "PROXY `+proxyAddr+`"; }`)
	}))
	defer pacSrv.Close()

	orig := pac.CandidateWPADURLs
	pac.CandidateWPADURLs = func() []string { return []string{pacSrv.URL + "/wpad.dat"} }
	defer func() { pac.CandidateWPADURLs = orig }()

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
	if atomic.LoadInt32(&hits) == 0 {
		t.Error("WPAD-discovered PAC did not route through the proxy")
	}
}
