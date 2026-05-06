package transport_test

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/durck/proxykit/transport"
)

// connectProxy starts an httptest server that hijacks the connection on
// CONNECT and runs handler with the raw conn. handler is responsible
// for writing the status line and any tunnel data.
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

// connectProxyTLS is connectProxy over TLS (https proxy).
func connectProxyTLS(t *testing.T, handler func(req *http.Request, conn net.Conn)) *httptest.Server {
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
func httpEcho(t *testing.T) *httptest.Server {
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

func mustParseURL(t *testing.T, raw string) *url.URL {
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
