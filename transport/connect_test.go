package transport_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/durck/proxykit/auth"
	"github.com/durck/proxykit/transport"
)

// connectProxy starts an httptest server that hijacks the connection on
// CONNECT and runs handler with the raw conn. handler is responsible
// for writing the status line and any tunnel data.
func connectProxy(t testing.TB, handler func(req *http.Request, conn net.Conn)) *httptest.Server {
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

// connectProxyTLS is connectProxy over TLS (https proxy).
func connectProxyTLS(t testing.TB, handler func(req *http.Request, conn net.Conn)) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			http.Error(w, "expected CONNECT", http.StatusBadRequest)
			return
		}
		hj := w.(http.Hijacker)
		conn, _, err := hj.Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		handler(r, conn)
	}))
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// httpEcho is a backend HTTP server that responds with "hello".
func httpEcho(t testing.TB) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "hello")
	}))
	t.Cleanup(srv.Close)
	return srv
}

// tunnelTo opens a TCP connection to target, then bidirectionally
// pipes between proxyConn and target until either side closes.
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

func mustParseURL(t testing.TB, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("url.Parse(%q): %v", raw, err)
	}
	return u
}

func TestConnect_Success(t *testing.T) {
	backend := httpEcho(t)
	backendAddr := strings.TrimPrefix(backend.URL, "http://")

	proxy := connectProxy(t, func(req *http.Request, conn net.Conn) {
		if _, err := conn.Write([]byte("HTTP/1.1 200 OK\r\n\r\n")); err != nil {
			return
		}
		tunnelTo(req.URL.Host, conn)
	})

	c := &transport.Connect{ProxyURL: mustParseURL(t, proxy.URL)}
	conn, err := c.DialContext(context.Background(), "tcp", backendAddr)
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer conn.Close()

	if _, err := fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", backendAddr); err != nil {
		t.Fatalf("write GET: %v", err)
	}
	body, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("read tunnel: %v", err)
	}
	if !strings.Contains(string(body), "hello") {
		t.Errorf("tunnel response %q does not contain %q", body, "hello")
	}
}

func TestConnect_HTTPSProxy(t *testing.T) {
	backend := httpEcho(t)
	backendAddr := strings.TrimPrefix(backend.URL, "http://")

	proxy := connectProxyTLS(t, func(req *http.Request, conn net.Conn) {
		conn.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))
		tunnelTo(req.URL.Host, conn)
	})

	// Default TLSConfig (nil) uses InsecureSkipVerify=true and accepts
	// the self-signed httptest cert.
	c := &transport.Connect{ProxyURL: mustParseURL(t, proxy.URL)}
	conn, err := c.DialContext(context.Background(), "tcp", backendAddr)
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer conn.Close()

	if _, err := fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", backendAddr); err != nil {
		t.Fatalf("write GET: %v", err)
	}
	body, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("read tunnel: %v", err)
	}
	if !strings.Contains(string(body), "hello") {
		t.Errorf("tunnel response %q does not contain %q", body, "hello")
	}
}

func TestConnect_407_MultipleHeaders(t *testing.T) {
	proxy := connectProxy(t, func(req *http.Request, conn net.Conn) {
		conn.Write([]byte("HTTP/1.1 407 Proxy Authentication Required\r\n" +
			"Proxy-Authenticate: Basic realm=\"corp\"\r\n" +
			"Proxy-Authenticate: NTLM\r\n" +
			"\r\n"))
	})

	c := &transport.Connect{ProxyURL: mustParseURL(t, proxy.URL)}
	_, err := c.DialContext(context.Background(), "tcp", "example.com:443")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	var perr *transport.ProxyAuthError
	if !errors.As(err, &perr) {
		t.Fatalf("expected *ProxyAuthError, got %T: %v", err, err)
	}
	if !strings.Contains(perr.Status, "407") {
		t.Errorf("status %q does not contain 407", perr.Status)
	}
	want := []string{"basic", "ntlm"}
	if len(perr.Schemes) != len(want) {
		t.Fatalf("schemes = %v, want %v", perr.Schemes, want)
	}
	for i, s := range want {
		if perr.Schemes[i] != s {
			t.Errorf("scheme[%d] = %q, want %q", i, perr.Schemes[i], s)
		}
	}
}

func TestConnect_407_CommaSchemes(t *testing.T) {
	proxy := connectProxy(t, func(req *http.Request, conn net.Conn) {
		conn.Write([]byte("HTTP/1.1 407 Proxy Authentication Required\r\n" +
			"Proxy-Authenticate: Basic, NTLM, Negotiate\r\n" +
			"\r\n"))
	})

	c := &transport.Connect{ProxyURL: mustParseURL(t, proxy.URL)}
	_, err := c.DialContext(context.Background(), "tcp", "example.com:443")
	var perr *transport.ProxyAuthError
	if !errors.As(err, &perr) {
		t.Fatalf("expected *ProxyAuthError, got %T: %v", err, err)
	}
	want := []string{"basic", "ntlm", "negotiate"}
	if len(perr.Schemes) != len(want) {
		t.Fatalf("schemes = %v, want %v", perr.Schemes, want)
	}
	for i, s := range want {
		if perr.Schemes[i] != s {
			t.Errorf("scheme[%d] = %q, want %q", i, perr.Schemes[i], s)
		}
	}
}

func TestConnect_407_NoSchemes(t *testing.T) {
	// Some proxies return 407 without a Proxy-Authenticate header.
	proxy := connectProxy(t, func(req *http.Request, conn net.Conn) {
		conn.Write([]byte("HTTP/1.1 407 Proxy Authentication Required\r\n\r\n"))
	})

	c := &transport.Connect{ProxyURL: mustParseURL(t, proxy.URL)}
	_, err := c.DialContext(context.Background(), "tcp", "example.com:443")
	var perr *transport.ProxyAuthError
	if !errors.As(err, &perr) {
		t.Fatalf("expected *ProxyAuthError, got %T: %v", err, err)
	}
	if len(perr.Schemes) != 0 {
		t.Errorf("schemes = %v, want empty", perr.Schemes)
	}
}

func TestConnect_StatusError(t *testing.T) {
	proxy := connectProxy(t, func(req *http.Request, conn net.Conn) {
		conn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
	})

	c := &transport.Connect{ProxyURL: mustParseURL(t, proxy.URL)}
	_, err := c.DialContext(context.Background(), "tcp", "example.com:443")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	var perr *transport.ProxyAuthError
	if errors.As(err, &perr) {
		t.Fatalf("expected generic error, got *ProxyAuthError: %v", perr)
	}
	if !strings.Contains(err.Error(), "502") {
		t.Errorf("error %q does not contain 502", err.Error())
	}
}

func TestConnect_ProxyDialError(t *testing.T) {
	// Open and close a listener to obtain a guaranteed-unused port.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()

	c := &transport.Connect{
		ProxyURL: mustParseURL(t, "http://"+addr),
		Timeout:  500 * time.Millisecond,
	}
	_, err = c.DialContext(context.Background(), "tcp", "example.com:443")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestConnect_BadNetwork(t *testing.T) {
	c := &transport.Connect{ProxyURL: mustParseURL(t, "http://127.0.0.1:1")}
	_, err := c.DialContext(context.Background(), "udp", "x:1")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "tcp") {
		t.Errorf("error %q does not mention tcp", err.Error())
	}
}

func TestConnect_NilProxyURL(t *testing.T) {
	c := &transport.Connect{}
	_, err := c.DialContext(context.Background(), "tcp", "x:1")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "ProxyURL") {
		t.Errorf("error %q does not mention ProxyURL", err.Error())
	}
}

func TestConnect_BadProxyScheme(t *testing.T) {
	c := &transport.Connect{ProxyURL: mustParseURL(t, "socks5://127.0.0.1:1080")}
	_, err := c.DialContext(context.Background(), "tcp", "x:1")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "http or https") {
		t.Errorf("error %q does not mention http or https", err.Error())
	}
}

func TestConnect_TLSConfigOverride_Verifies(t *testing.T) {
	// With an empty *tls.Config (InsecureSkipVerify=false), the TLS
	// dial to the self-signed httptest proxy must fail.
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.StartTLS()
	t.Cleanup(srv.Close)

	c := &transport.Connect{
		ProxyURL:  mustParseURL(t, srv.URL),
		TLSConfig: &tls.Config{},
	}
	_, err := c.DialContext(context.Background(), "tcp", "example.com:443")
	if err == nil {
		t.Fatal("expected TLS verification error, got nil")
	}
}

// --- auth integration ---------------------------------------------------

func TestConnect_BasicAuth_Success(t *testing.T) {
	backend := httpEcho(t)
	backendAddr := strings.TrimPrefix(backend.URL, "http://")

	wantAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("alice:secret"))
	var requests int32

	proxy := connectProxy(t, func(req *http.Request, conn net.Conn) {
		atomic.AddInt32(&requests, 1)
		got := req.Header.Get("Proxy-Authorization")
		if got == "" {
			conn.Write([]byte("HTTP/1.1 407 Proxy Authentication Required\r\n" +
				"Proxy-Authenticate: Basic realm=\"corp\"\r\n\r\n"))
			return
		}
		if got != wantAuth {
			t.Errorf("Proxy-Authorization = %q, want %q", got, wantAuth)
			conn.Write([]byte("HTTP/1.1 407 Proxy Authentication Required\r\n\r\n"))
			return
		}
		conn.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))
		tunnelTo(req.URL.Host, conn)
	})

	c := &transport.Connect{
		ProxyURL: mustParseURL(t, proxy.URL),
		Auth:     []auth.Authenticator{auth.Basic("alice", "secret")},
	}

	conn, err := c.DialContext(context.Background(), "tcp", backendAddr)
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer conn.Close()

	if _, err := fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", backendAddr); err != nil {
		t.Fatalf("write GET: %v", err)
	}
	body, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("read tunnel: %v", err)
	}
	if !strings.Contains(string(body), "hello") {
		t.Errorf("tunnel response %q does not contain %q", body, "hello")
	}
	if got := atomic.LoadInt32(&requests); got != 2 {
		t.Errorf("proxy received %d CONNECTs, want 2 (no-auth + with-auth)", got)
	}
}

func TestConnect_BasicAuth_WrongCreds(t *testing.T) {
	proxy := connectProxy(t, func(req *http.Request, conn net.Conn) {
		// Always 407 regardless of credentials supplied.
		conn.Write([]byte("HTTP/1.1 407 Proxy Authentication Required\r\n" +
			"Proxy-Authenticate: Basic realm=\"corp\"\r\n\r\n"))
	})

	c := &transport.Connect{
		ProxyURL: mustParseURL(t, proxy.URL),
		Auth:     []auth.Authenticator{auth.Basic("alice", "wrong")},
	}

	_, err := c.DialContext(context.Background(), "tcp", "example.com:443")
	var perr *transport.ProxyAuthError
	if !errors.As(err, &perr) {
		t.Fatalf("expected *ProxyAuthError, got %T: %v", err, err)
	}
	if !strings.Contains(perr.Status, "407") {
		t.Errorf("status %q does not contain 407", perr.Status)
	}
}

func TestConnect_BasicAuth_NoMatchingScheme(t *testing.T) {
	proxy := connectProxy(t, func(req *http.Request, conn net.Conn) {
		// Proxy advertises only NTLM; client only has Basic.
		conn.Write([]byte("HTTP/1.1 407 Proxy Authentication Required\r\n" +
			"Proxy-Authenticate: NTLM\r\n\r\n"))
	})

	c := &transport.Connect{
		ProxyURL: mustParseURL(t, proxy.URL),
		Auth:     []auth.Authenticator{auth.Basic("a", "b")},
	}

	_, err := c.DialContext(context.Background(), "tcp", "example.com:443")
	var perr *transport.ProxyAuthError
	if !errors.As(err, &perr) {
		t.Fatalf("expected *ProxyAuthError, got %T: %v", err, err)
	}
	if len(perr.Schemes) != 1 || perr.Schemes[0] != "ntlm" {
		t.Errorf("schemes = %v, want [ntlm]", perr.Schemes)
	}
}

func TestConnect_BasicAuth_NoneSentinelSkipped(t *testing.T) {
	// auth.None has Scheme "" so it must never be picked, even when
	// the proxy demands auth. The result is the original 407.
	proxy := connectProxy(t, func(req *http.Request, conn net.Conn) {
		conn.Write([]byte("HTTP/1.1 407 Proxy Authentication Required\r\n" +
			"Proxy-Authenticate: Basic realm=\"corp\"\r\n\r\n"))
	})

	c := &transport.Connect{
		ProxyURL: mustParseURL(t, proxy.URL),
		Auth:     []auth.Authenticator{auth.None()},
	}

	_, err := c.DialContext(context.Background(), "tcp", "example.com:443")
	var perr *transport.ProxyAuthError
	if !errors.As(err, &perr) {
		t.Fatalf("expected *ProxyAuthError, got %T: %v", err, err)
	}
}

func TestConnect_AuthChain_FallsThrough(t *testing.T) {
	// First Basic creds (wrong) fails, second Basic creds (right) wins.
	wantAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("bob:right"))

	backend := httpEcho(t)
	backendAddr := strings.TrimPrefix(backend.URL, "http://")

	proxy := connectProxy(t, func(req *http.Request, conn net.Conn) {
		got := req.Header.Get("Proxy-Authorization")
		if got == wantAuth {
			conn.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))
			tunnelTo(req.URL.Host, conn)
			return
		}
		conn.Write([]byte("HTTP/1.1 407 Proxy Authentication Required\r\n" +
			"Proxy-Authenticate: Basic realm=\"corp\"\r\n\r\n"))
	})

	c := &transport.Connect{
		ProxyURL: mustParseURL(t, proxy.URL),
		Auth: []auth.Authenticator{
			auth.Basic("alice", "wrong"),
			auth.Basic("bob", "right"),
		},
	}

	conn, err := c.DialContext(context.Background(), "tcp", backendAddr)
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer conn.Close()

	fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", backendAddr)
	body, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !strings.Contains(string(body), "hello") {
		t.Errorf("tunnel response %q does not contain %q", body, "hello")
	}
}

// type2Fixture is a valid NTLM Type 2 (Challenge) message from the
// MS-NLMP examples — accepted by bodgit/ntlmssp.
var type2Fixture = []byte{
	0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00,
	0x02, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x0c, 0x00,
	0x38, 0x00, 0x00, 0x00, 0x33, 0x82, 0x02, 0xe2,
	0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x06, 0x00, 0x70, 0x17, 0x00, 0x00, 0x00, 0x0f,
	0x53, 0x00, 0x65, 0x00, 0x72, 0x00, 0x76, 0x00,
	0x65, 0x00, 0x72, 0x00,
}

// TestConnect_NTLM_FullDance walks the full 3-round NTLM exchange:
//   - initial CONNECT without auth → 407 advertising NTLM
//   - fresh proxy connection: Type 1 sent → 407 with Type 2 challenge
//   - same proxy connection: Type 3 sent → 200 → tunnel
//
// The mock proxy is a raw net.Listener that handles two consecutive
// CONNECT requests on the second TCP conn (NTLM is connection-bound)
// via http.ReadRequest, asserts the Type 1/3 message prefixes are
// well-formed, then bridges to the backend.
func TestConnect_NTLM_FullDance(t *testing.T) {
	backend := httpEcho(t)
	backendAddr := strings.TrimPrefix(backend.URL, "http://")

	type2B64 := base64.StdEncoding.EncodeToString(type2Fixture)

	var (
		gotType1 []byte
		gotType3 []byte
	)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)

		// Connection 1: initial no-auth attempt.
		c1, err := ln.Accept()
		if err != nil {
			return
		}
		func() {
			defer c1.Close()
			br := bufio.NewReader(c1)
			if _, err := http.ReadRequest(br); err != nil {
				return
			}
			c1.Write([]byte("HTTP/1.1 407 Proxy Authentication Required\r\n" +
				"Proxy-Authenticate: NTLM\r\n\r\n"))
		}()

		// Connection 2: NTLM dance.
		c2, err := ln.Accept()
		if err != nil {
			return
		}
		defer c2.Close()
		br := bufio.NewReader(c2)

		// Round 1: Type 1.
		req1, err := http.ReadRequest(br)
		if err != nil {
			t.Errorf("round 1 ReadRequest: %v", err)
			return
		}
		ah1 := req1.Header.Get("Proxy-Authorization")
		if !strings.HasPrefix(ah1, "NTLM ") {
			t.Errorf("round 1 Proxy-Authorization = %q, want NTLM prefix", ah1)
			return
		}
		gotType1, err = base64.StdEncoding.DecodeString(strings.TrimPrefix(ah1, "NTLM "))
		if err != nil {
			t.Errorf("round 1 base64: %v", err)
			return
		}
		c2.Write([]byte("HTTP/1.1 407 Proxy Authentication Required\r\n" +
			"Proxy-Authenticate: NTLM " + type2B64 + "\r\n\r\n"))

		// Round 2: Type 3.
		req2, err := http.ReadRequest(br)
		if err != nil {
			t.Errorf("round 2 ReadRequest: %v", err)
			return
		}
		ah2 := req2.Header.Get("Proxy-Authorization")
		gotType3, err = base64.StdEncoding.DecodeString(strings.TrimPrefix(ah2, "NTLM "))
		if err != nil {
			t.Errorf("round 2 base64: %v", err)
			return
		}
		c2.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))

		// Tunnel to backend.
		target, err := net.Dial("tcp", req2.URL.Host)
		if err != nil {
			return
		}
		defer target.Close()
		done := make(chan struct{}, 2)
		go func() { io.Copy(target, br); done <- struct{}{} }()
		go func() { io.Copy(c2, target); done <- struct{}{} }()
		<-done
	}()

	c := &transport.Connect{
		ProxyURL: mustParseURL(t, "http://"+ln.Addr().String()),
		Auth:     []auth.Authenticator{auth.NTLM("DOMAIN", "user", "pass")},
	}

	conn, err := c.DialContext(context.Background(), "tcp", backendAddr)
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer conn.Close()

	fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", backendAddr)
	body, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("read tunnel: %v", err)
	}
	if !strings.Contains(string(body), "hello") {
		t.Errorf("tunnel response %q does not contain hello", body)
	}

	<-serverDone

	if !bytes.HasPrefix(gotType1, []byte("NTLMSSP\x00")) {
		t.Errorf("Type 1 missing NTLMSSP signature: % x", gotType1[:min(8, len(gotType1))])
	}
	if len(gotType1) < 12 || gotType1[8] != 1 {
		t.Errorf("Type 1 MessageType = %#x, want 0x01", gotType1[8])
	}
	if !bytes.HasPrefix(gotType3, []byte("NTLMSSP\x00")) {
		t.Errorf("Type 3 missing NTLMSSP signature: % x", gotType3[:min(8, len(gotType3))])
	}
	if len(gotType3) < 12 || gotType3[8] != 3 {
		t.Errorf("Type 3 MessageType = %#x, want 0x03", gotType3[8])
	}
}

func TestProxyAuthError_Error(t *testing.T) {
	tests := []struct {
		name  string
		err   *transport.ProxyAuthError
		wants []string // substrings the message must contain
	}{
		{
			name:  "with schemes",
			err:   &transport.ProxyAuthError{Status: "HTTP/1.1 407 X", Schemes: []string{"basic", "ntlm"}},
			wants: []string{"407", "basic", "ntlm"},
		},
		{
			name:  "no schemes",
			err:   &transport.ProxyAuthError{Status: "HTTP/1.1 407 X"},
			wants: []string{"407", "authentication"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := tt.err.Error()
			for _, w := range tt.wants {
				if !strings.Contains(msg, w) {
					t.Errorf("error %q does not contain %q", msg, w)
				}
			}
		})
	}
}

func TestConnect_TimeoutBoundsHandshake(t *testing.T) {
	// Proxy accepts the TCP connection but never sends a CONNECT
	// response. With Timeout set and a context that carries no deadline,
	// DialContext must still unblock — regression guard: Timeout used to
	// bound only the TCP connect, not the response read.
	block := make(chan struct{})
	t.Cleanup(func() { close(block) })
	proxy := connectProxy(t, func(req *http.Request, conn net.Conn) {
		<-block // hold the connection open without answering
	})

	c := &transport.Connect{
		ProxyURL: mustParseURL(t, proxy.URL),
		Timeout:  150 * time.Millisecond,
	}

	start := time.Now()
	_, err := c.DialContext(context.Background(), "tcp", "example.com:443")
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
	if elapsed > 2*time.Second {
		t.Errorf("dial unblocked after %v; Timeout was 150ms", elapsed)
	}
}
