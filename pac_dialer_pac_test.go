//go:build proxykit_pac

package proxykit

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
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

// TestPACDialer_ProxyRoutingE2E proves a PAC "PROXY host:port" result
// actually routes the dial through that CONNECT proxy (not directly): the
// proxy's accept counter must increment.
func TestPACDialer_ProxyRoutingE2E(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, "via-proxy")
	}))
	defer backend.Close()
	backendAddr := strings.TrimPrefix(backend.URL, "http://")

	var hits int32
	proxyAddr := startConnectProxy(t, &hits)

	d := NewDialer(Config{PAC: `function FindProxyForURL(url, host){ return "PROXY ` + proxyAddr + `"; }`})
	conn, err := d.DialContext(context.Background(), "tcp", backendAddr)
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer conn.Close()

	io.WriteString(conn, "GET / HTTP/1.1\r\nHost: "+backendAddr+"\r\nConnection: close\r\n\r\n")
	body, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !strings.Contains(string(body), "via-proxy") {
		t.Errorf("response %q does not contain via-proxy", body)
	}
	if atomic.LoadInt32(&hits) == 0 {
		t.Error("dial did not go through the CONNECT proxy")
	}
}

// startConnectProxy runs a minimal HTTP CONNECT proxy for tests, counting
// accepted connections in hits.
func startConnectProxy(t *testing.T, hits *int32) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			atomic.AddInt32(hits, 1)
			go handleConnect(c)
		}
	}()
	return ln.Addr().String()
}

func handleConnect(c net.Conn) {
	defer c.Close()
	br := bufio.NewReader(c)
	line, err := br.ReadString('\n')
	if err != nil {
		return
	}
	fields := strings.Fields(line)
	if len(fields) < 2 || fields[0] != "CONNECT" {
		return
	}
	for { // drain headers
		h, err := br.ReadString('\n')
		if err != nil {
			return
		}
		if strings.TrimSpace(h) == "" {
			break
		}
	}
	upstream, err := net.Dial("tcp", fields[1])
	if err != nil {
		io.WriteString(c, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
		return
	}
	defer upstream.Close()
	io.WriteString(c, "HTTP/1.1 200 Connection established\r\n\r\n")
	go io.Copy(upstream, br) // br may hold bytes buffered past the headers
	io.Copy(c, upstream)
}
