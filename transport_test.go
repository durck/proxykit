package proxykit_test

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/durck/proxykit"
)

func TestNewHTTPTransport_Direct(t *testing.T) {
	clearProxyEnv(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "hello")
	}))
	t.Cleanup(srv.Close)

	tr := proxykit.NewHTTPTransport(proxykit.Config{})
	client := &http.Client{Transport: tr}

	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if !strings.Contains(string(body), "hello") {
		t.Errorf("body %q does not contain hello", body)
	}
}

func TestNewHTTPTransport_ThroughCONNECTProxy(t *testing.T) {
	clearProxyEnv(t)

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "via-proxy")
	}))
	t.Cleanup(backend.Close)

	var requests int32
	proxy := connectProxy(t, func(req *http.Request, conn net.Conn) {
		atomic.AddInt32(&requests, 1)
		conn.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))
		tunnelTo(req.URL.Host, conn)
	})

	tr := proxykit.NewHTTPTransport(proxykit.Config{Manual: proxy.URL})
	client := &http.Client{Transport: tr}

	resp, err := client.Get(backend.URL)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if !strings.Contains(string(body), "via-proxy") {
		t.Errorf("body %q does not contain via-proxy", body)
	}
	if got := atomic.LoadInt32(&requests); got == 0 {
		t.Errorf("proxy received %d CONNECTs, want at least 1", got)
	}
}

func TestNewHTTPTransport_ReturnsNonNil(t *testing.T) {
	clearProxyEnv(t)
	if tr := proxykit.NewHTTPTransport(proxykit.Config{}); tr == nil {
		t.Fatal("NewHTTPTransport returned nil")
	}
}
