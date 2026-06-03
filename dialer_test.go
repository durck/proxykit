package proxykit_test

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/durck/proxykit"
	"github.com/durck/proxykit/transport"
)

// --- helpers ------------------------------------------------------------

// envKeys lists every *_PROXY environment variable that influences
// detect.EnvDetector. Tests blank them out before applying their own
// settings to avoid bleed-through from the host environment.
var envKeys = []string{
	"HTTP_PROXY", "http_proxy",
	"HTTPS_PROXY", "https_proxy",
	"NO_PROXY", "no_proxy",
	"REQUEST_METHOD",
}

func clearProxyEnv(t *testing.T) {
	t.Helper()
	for _, k := range envKeys {
		t.Setenv(k, "")
	}
}

// httpEcho is a backend HTTP server that responds with "hello".
func httpEchoServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "hello")
	}))
	t.Cleanup(srv.Close)
	return srv
}

// connectProxy starts an httptest server that hijacks the connection
// on CONNECT and runs handler with the raw conn. Mirror of the helper
// in transport/connect_test.go to keep dialer_test.go self-contained.
func connectProxy(t *testing.T, handler func(req *http.Request, conn net.Conn)) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			http.Error(w, "expected CONNECT", http.StatusBadRequest)
			return
		}
		hj, ok := w.(http.Hijacker)
		if !ok {
			t.Errorf("ResponseWriter is not Hijacker")
			return
		}
		conn, _, err := hj.Hijack()
		if err != nil {
			t.Errorf("hijack: %v", err)
			return
		}
		defer conn.Close()
		handler(r, conn)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// tunnelTo bridges proxyConn to a fresh TCP connection to target
// (host:port).
func tunnelTo(target string, proxyConn net.Conn) {
	backend, err := net.Dial("tcp", target)
	if err != nil {
		return
	}
	defer backend.Close()
	done := make(chan struct{}, 2)
	go func() { io.Copy(backend, proxyConn); done <- struct{}{} }()
	go func() { io.Copy(proxyConn, backend); done <- struct{}{} }()
	<-done
}

// roundTripGet sends a minimal HTTP/1.1 GET / over conn and returns
// the response body.
func roundTripGet(t *testing.T, conn net.Conn, host string) string {
	t.Helper()
	if _, err := fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", host); err != nil {
		t.Fatalf("write GET: %v", err)
	}
	body, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	return string(body)
}

// --- direct path --------------------------------------------------------

func TestNewDialer_Direct(t *testing.T) {
	clearProxyEnv(t)

	srv := httpEchoServer(t)
	addr := strings.TrimPrefix(srv.URL, "http://")

	d := proxykit.NewDialer(proxykit.Config{})
	conn, err := d.DialContext(context.Background(), "tcp", addr)
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	if !strings.Contains(roundTripGet(t, conn, addr), "hello") {
		t.Errorf("response did not contain hello")
	}
}

func TestNewDialer_ReturnsNonNil(t *testing.T) {
	clearProxyEnv(t)
	if d := proxykit.NewDialer(proxykit.Config{}); d == nil {
		t.Fatal("NewDialer returned nil")
	}
}

// --- manual proxy -------------------------------------------------------

func TestNewDialer_ManualHTTPProxy(t *testing.T) {
	clearProxyEnv(t)

	backend := httpEchoServer(t)
	backendAddr := strings.TrimPrefix(backend.URL, "http://")

	proxy := connectProxy(t, func(req *http.Request, conn net.Conn) {
		conn.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))
		tunnelTo(req.URL.Host, conn)
	})

	d := proxykit.NewDialer(proxykit.Config{Manual: proxy.URL})
	conn, err := d.DialContext(context.Background(), "tcp", backendAddr)
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer conn.Close()
	if !strings.Contains(roundTripGet(t, conn, backendAddr), "hello") {
		t.Errorf("response did not contain hello")
	}
}

func TestNewDialer_ManualHTTPProxyWithBasicFromUserInfo(t *testing.T) {
	clearProxyEnv(t)

	backend := httpEchoServer(t)
	backendAddr := strings.TrimPrefix(backend.URL, "http://")

	wantAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("alice:secret"))
	proxy := connectProxy(t, func(req *http.Request, conn net.Conn) {
		got := req.Header.Get("Proxy-Authorization")
		if got == "" {
			conn.Write([]byte("HTTP/1.1 407 Proxy Authentication Required\r\n" +
				"Proxy-Authenticate: Basic realm=\"corp\"\r\n\r\n"))
			return
		}
		if got != wantAuth {
			t.Errorf("Proxy-Authorization = %q, want %q", got, wantAuth)
			conn.Write([]byte("HTTP/1.1 407\r\n\r\n"))
			return
		}
		conn.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))
		tunnelTo(req.URL.Host, conn)
	})

	// Splice user:pass@ into the manual URL.
	manualURL := strings.Replace(proxy.URL, "http://", "http://alice:secret@", 1)
	d := proxykit.NewDialer(proxykit.Config{Manual: manualURL})

	conn, err := d.DialContext(context.Background(), "tcp", backendAddr)
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer conn.Close()
	if !strings.Contains(roundTripGet(t, conn, backendAddr), "hello") {
		t.Errorf("response did not contain hello")
	}
}

func TestNewDialer_ManualSOCKS5(t *testing.T) {
	clearProxyEnv(t)

	backend := httpEchoServer(t)
	backendAddr := strings.TrimPrefix(backend.URL, "http://")

	socksAddr := startSocks5NoAuthStub(t)

	d := proxykit.NewDialer(proxykit.Config{Manual: "socks5://" + socksAddr})
	conn, err := d.DialContext(context.Background(), "tcp", backendAddr)
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer conn.Close()
	if !strings.Contains(roundTripGet(t, conn, backendAddr), "hello") {
		t.Errorf("response did not contain hello")
	}
}

func TestNewDialer_ManualSOCKS5_CredsUseTypedAuth(t *testing.T) {
	clearProxyEnv(t)

	// Credentials embedded in the manual URL must surface on the typed
	// SOCKS5.Auth option and must NOT be re-embedded in ProxyURL — the
	// whole point of exposing them as a typed option (issue #11).
	d := proxykit.NewDialer(proxykit.Config{Manual: "socks5://alice:s3cr3t@socks.corp:1080"})

	s, ok := d.(*transport.SOCKS5)
	if !ok {
		t.Fatalf("NewDialer returned %T, want *transport.SOCKS5", d)
	}
	if s.Auth == nil {
		t.Fatal("SOCKS5.Auth is nil; credentials were not wired through the typed option")
	}
	if s.Auth.Username != "alice" || s.Auth.Password != "s3cr3t" {
		t.Errorf("Auth = {%q, %q}, want {alice, s3cr3t}", s.Auth.Username, s.Auth.Password)
	}
	if s.ProxyURL.User != nil {
		t.Errorf("ProxyURL.User = %v, want nil (creds must not be embedded in the URL)", s.ProxyURL.User)
	}
}

func TestNewDialer_InvalidManualFallsThroughToDirect(t *testing.T) {
	clearProxyEnv(t)

	srv := httpEchoServer(t)
	addr := strings.TrimPrefix(srv.URL, "http://")

	var logged []string
	d := proxykit.NewDialer(proxykit.Config{
		Manual: "ftp://nope",
		OnLog:  func(level, msg string) { logged = append(logged, level+":"+msg) },
	})

	conn, err := d.DialContext(context.Background(), "tcp", addr)
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer conn.Close()
	if !strings.Contains(roundTripGet(t, conn, addr), "hello") {
		t.Errorf("response did not contain hello — direct fallback failed")
	}

	if len(logged) == 0 {
		t.Errorf("expected OnLog warn for invalid manual URL, got none")
	}
}

// --- auto-detect path ---------------------------------------------------

func TestNewDialer_AutoDetectFromEnv(t *testing.T) {
	clearProxyEnv(t)

	backend := httpEchoServer(t)
	backendAddr := strings.TrimPrefix(backend.URL, "http://")

	proxy := connectProxy(t, func(req *http.Request, conn net.Conn) {
		conn.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))
		tunnelTo(req.URL.Host, conn)
	})

	t.Setenv("HTTP_PROXY", proxy.URL)

	d := proxykit.NewDialer(proxykit.Config{AutoDetect: true})
	conn, err := d.DialContext(context.Background(), "tcp", backendAddr)
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer conn.Close()
	if !strings.Contains(roundTripGet(t, conn, backendAddr), "hello") {
		t.Errorf("response did not contain hello — env auto-detect failed")
	}
}

func TestNewDialer_FallbackStopsWhenContextCancelled(t *testing.T) {
	clearProxyEnv(t)

	var firstHits, secondHits atomic.Int32
	firstProxy := connectProxy(t, func(req *http.Request, conn net.Conn) {
		firstHits.Add(1)
		conn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
	})
	secondProxy := connectProxy(t, func(req *http.Request, conn net.Conn) {
		secondHits.Add(1)
		conn.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))
	})
	t.Setenv("HTTP_PROXY", secondProxy.URL)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var logs []string
	d := proxykit.NewDialer(proxykit.Config{
		Manual:     firstProxy.URL,
		AutoDetect: true,
		OnLog: func(level, msg string) {
			logs = append(logs, msg)
			cancel()
		},
	})

	conn, err := d.DialContext(ctx, "tcp", "example.com:443")
	if conn != nil {
		conn.Close()
		t.Fatalf("DialContext returned unexpected connection")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("DialContext error = %v, want context.Canceled", err)
	}
	if got := firstHits.Load(); got != 1 {
		t.Fatalf("first proxy hits = %d, want 1", got)
	}
	if got := secondHits.Load(); got != 0 {
		t.Fatalf("second proxy hits = %d, want 0 after context cancellation", got)
	}
	if got := len(logs); got != 1 {
		t.Fatalf("fallback log count = %d, want 1: %v", got, logs)
	}
	if !strings.Contains(logs[0], "dialer 0 failed") {
		t.Fatalf("fallback log = %q, want first dialer failure", logs[0])
	}
	if strings.Contains(strings.Join(logs, "\n"), "dialer 1 failed") {
		t.Fatalf("fallback attempted the second dialer after cancellation: %v", logs)
	}
}

// --- credential redaction -----------------------------------------------

func TestNewDialer_RedactsCredentialsInLog(t *testing.T) {
	var logs []string
	// Host-less URL with embedded credentials: ParseProxyURL fails, so the
	// URL is reported both in the warning log and in the wrapped error.
	// Neither must leak the password.
	proxykit.NewDialer(proxykit.Config{
		Manual: "http://alice:s3cr3t@",
		OnLog:  func(level, msg string) { logs = append(logs, msg) },
	})

	joined := strings.Join(logs, "\n")
	if joined == "" {
		t.Fatal("expected a warning log for the invalid proxy URL, got none")
	}
	if strings.Contains(joined, "s3cr3t") {
		t.Errorf("log leaked the proxy password: %q", joined)
	}
	if !strings.Contains(joined, "xxxxx") {
		t.Errorf("expected redacted password marker in log, got %q", joined)
	}
}

// --- fallback chain -----------------------------------------------------

func TestNewDialer_FallbackChain(t *testing.T) {
	clearProxyEnv(t)

	backend := httpEchoServer(t)
	backendAddr := strings.TrimPrefix(backend.URL, "http://")

	// First proxy in the chain — broken (always 500).
	bad := connectProxy(t, func(req *http.Request, conn net.Conn) {
		conn.Write([]byte("HTTP/1.1 500 Internal Server Error\r\n\r\n"))
	})
	// Second proxy in the chain — healthy.
	good := connectProxy(t, func(req *http.Request, conn net.Conn) {
		conn.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))
		tunnelTo(req.URL.Host, conn)
	})

	// Manual is the broken one; AutoDetect picks up the healthy one
	// from HTTP_PROXY.
	t.Setenv("HTTP_PROXY", good.URL)

	d := proxykit.NewDialer(proxykit.Config{
		Manual:     bad.URL,
		AutoDetect: true,
	})
	conn, err := d.DialContext(context.Background(), "tcp", backendAddr)
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer conn.Close()
	if !strings.Contains(roundTripGet(t, conn, backendAddr), "hello") {
		t.Errorf("response did not contain hello — fallback chain failed")
	}
}

func TestNewDialer_FallbackAllFailReturnsJoinedErrors(t *testing.T) {
	clearProxyEnv(t)

	bad1 := connectProxy(t, func(req *http.Request, conn net.Conn) {
		conn.Write([]byte("HTTP/1.1 500\r\n\r\n"))
	})
	bad2 := connectProxy(t, func(req *http.Request, conn net.Conn) {
		conn.Write([]byte("HTTP/1.1 502\r\n\r\n"))
	})

	t.Setenv("HTTP_PROXY", bad2.URL)

	d := proxykit.NewDialer(proxykit.Config{
		Manual:     bad1.URL,
		AutoDetect: true,
	})

	_, err := d.DialContext(context.Background(), "tcp", "example.com:80")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	msg := err.Error()
	if !strings.Contains(msg, "500") || !strings.Contains(msg, "502") {
		t.Errorf("error %q does not include both upstream statuses", msg)
	}
}

// --- minimal SOCKS5 stub (no-auth) for the dialer tests -----------------

func startSocks5NoAuthStub(t *testing.T) string {
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
			go socks5HandleNoAuth(c)
		}
	}()
	return ln.Addr().String()
}

func socks5HandleNoAuth(c net.Conn) {
	defer c.Close()

	// Greeting.
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(c, hdr); err != nil {
		return
	}
	if hdr[0] != 0x05 {
		return
	}
	methods := make([]byte, hdr[1])
	if _, err := io.ReadFull(c, methods); err != nil {
		return
	}
	c.Write([]byte{0x05, 0x00})

	// CONNECT request.
	req := make([]byte, 4)
	if _, err := io.ReadFull(c, req); err != nil {
		return
	}
	if req[0] != 0x05 || req[1] != 0x01 {
		return
	}
	var host string
	switch req[3] {
	case 0x01:
		addr := make([]byte, 4)
		if _, err := io.ReadFull(c, addr); err != nil {
			return
		}
		host = net.IP(addr).String()
	case 0x03:
		ln := make([]byte, 1)
		if _, err := io.ReadFull(c, ln); err != nil {
			return
		}
		addr := make([]byte, ln[0])
		if _, err := io.ReadFull(c, addr); err != nil {
			return
		}
		host = string(addr)
	default:
		return
	}
	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(c, portBytes); err != nil {
		return
	}
	port := uint16(portBytes[0])<<8 | uint16(portBytes[1])

	target, err := net.Dial("tcp", net.JoinHostPort(host, fmt.Sprint(port)))
	if err != nil {
		c.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer target.Close()
	c.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})

	done := make(chan struct{}, 2)
	go func() { io.Copy(target, c); done <- struct{}{} }()
	go func() { io.Copy(c, target); done <- struct{}{} }()
	<-done
}
