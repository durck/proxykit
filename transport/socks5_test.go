package transport_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/durck/proxykit/transport"
)

// Minimal SOCKS5 stub — RFC 1928 / RFC 1929. Just enough to exercise
// the client side: greeting, optional username/password
// subnegotiation, CONNECT request, target dial, bidirectional pipe.

type socks5Opts struct {
	// requireUserPass demands RFC 1929 user/pass auth and validates
	// against wantUser/wantPass.
	requireUserPass bool
	wantUser        string
	wantPass        string

	// rejectTarget, when non-nil, is consulted before dialing the
	// target; if it returns true the proxy replies with REP=0x05
	// (connection refused).
	rejectTarget func(host string, port uint16) bool

	// onConnections counts accepted client connections (atomic).
	onConnections *int32
}

func startSOCKS5Stub(tb testing.TB, opts socks5Opts) string {
	tb.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { ln.Close() })

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			if opts.onConnections != nil {
				atomic.AddInt32(opts.onConnections, 1)
			}
			go handleSOCKS5(c, opts)
		}
	}()

	return "socks5://127.0.0.1:" + portOf(ln)
}

func portOf(ln net.Listener) string {
	return fmt.Sprint(ln.Addr().(*net.TCPAddr).Port)
}

func handleSOCKS5(c net.Conn, opts socks5Opts) {
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

	// Method selection.
	wantMethod := byte(0x00) // no auth
	if opts.requireUserPass {
		wantMethod = 0x02
	}
	if !bytes.Contains(methods, []byte{wantMethod}) {
		c.Write([]byte{0x05, 0xFF}) // no acceptable methods
		return
	}
	c.Write([]byte{0x05, wantMethod})

	// User/pass subnegotiation (RFC 1929).
	if wantMethod == 0x02 {
		ver := make([]byte, 2)
		if _, err := io.ReadFull(c, ver); err != nil {
			return
		}
		if ver[0] != 0x01 {
			return
		}
		uname := make([]byte, ver[1])
		if _, err := io.ReadFull(c, uname); err != nil {
			return
		}
		plenByte := make([]byte, 1)
		if _, err := io.ReadFull(c, plenByte); err != nil {
			return
		}
		passwd := make([]byte, plenByte[0])
		if _, err := io.ReadFull(c, passwd); err != nil {
			return
		}
		if string(uname) != opts.wantUser || string(passwd) != opts.wantPass {
			c.Write([]byte{0x01, 0xFF}) // failure
			return
		}
		c.Write([]byte{0x01, 0x00}) // success
	}

	// CONNECT request.
	req := make([]byte, 4)
	if _, err := io.ReadFull(c, req); err != nil {
		return
	}
	if req[0] != 0x05 || req[1] != 0x01 || req[2] != 0x00 {
		// Only CONNECT is supported.
		c.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // command not supported
		return
	}

	var host string
	switch req[3] {
	case 0x01: // IPv4
		addr := make([]byte, 4)
		if _, err := io.ReadFull(c, addr); err != nil {
			return
		}
		host = net.IP(addr).String()
	case 0x03: // domain
		ln := make([]byte, 1)
		if _, err := io.ReadFull(c, ln); err != nil {
			return
		}
		addr := make([]byte, ln[0])
		if _, err := io.ReadFull(c, addr); err != nil {
			return
		}
		host = string(addr)
	case 0x04: // IPv6
		addr := make([]byte, 16)
		if _, err := io.ReadFull(c, addr); err != nil {
			return
		}
		host = net.IP(addr).String()
	default:
		c.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // address type not supported
		return
	}
	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(c, portBytes); err != nil {
		return
	}
	port := binary.BigEndian.Uint16(portBytes)

	if opts.rejectTarget != nil && opts.rejectTarget(host, port) {
		c.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // connection refused
		return
	}

	target, err := net.Dial("tcp", net.JoinHostPort(host, fmt.Sprint(port)))
	if err != nil {
		c.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // host unreachable
		return
	}
	defer target.Close()

	// Success reply with bound address 0.0.0.0:0.
	c.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})

	// Bidirectional pipe.
	done := make(chan struct{}, 2)
	go func() { io.Copy(target, c); done <- struct{}{} }()
	go func() { io.Copy(c, target); done <- struct{}{} }()
	<-done
}

// --- tests --------------------------------------------------------------

func TestSOCKS5_Success(t *testing.T) {
	backend := httpEcho(t)
	backendAddr := strings.TrimPrefix(backend.URL, "http://")

	proxyURL := startSOCKS5Stub(t, socks5Opts{})

	s := &transport.SOCKS5{ProxyURL: mustParseURL(t, proxyURL)}
	conn, err := s.DialContext(context.Background(), "tcp", backendAddr)
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
		t.Errorf("response %q does not contain %q", body, "hello")
	}
}

func TestSOCKS5_UserPass_Success(t *testing.T) {
	backend := httpEcho(t)
	backendAddr := strings.TrimPrefix(backend.URL, "http://")

	proxyURL := startSOCKS5Stub(t, socks5Opts{
		requireUserPass: true,
		wantUser:        "alice",
		wantPass:        "s3cr3t",
	})

	u := mustParseURL(t, proxyURL)
	u.User = url.UserPassword("alice", "s3cr3t")

	s := &transport.SOCKS5{ProxyURL: u}
	conn, err := s.DialContext(context.Background(), "tcp", backendAddr)
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
		t.Errorf("response %q does not contain %q", body, "hello")
	}
}

func TestSOCKS5_UserPass_Wrong(t *testing.T) {
	proxyURL := startSOCKS5Stub(t, socks5Opts{
		requireUserPass: true,
		wantUser:        "alice",
		wantPass:        "right",
	})

	u := mustParseURL(t, proxyURL)
	u.User = url.UserPassword("alice", "wrong")

	s := &transport.SOCKS5{ProxyURL: u}
	_, err := s.DialContext(context.Background(), "tcp", "example.com:80")
	if err == nil {
		t.Fatal("expected error from wrong creds, got nil")
	}
}

func TestSOCKS5_TypedAuth_Success(t *testing.T) {
	backend := httpEcho(t)
	backendAddr := strings.TrimPrefix(backend.URL, "http://")

	proxyURL := startSOCKS5Stub(t, socks5Opts{
		requireUserPass: true,
		wantUser:        "alice",
		wantPass:        "s3cr3t",
	})

	// Credentials live only in the typed option; the URL has no userinfo.
	s := &transport.SOCKS5{
		ProxyURL: mustParseURL(t, proxyURL),
		Auth:     &transport.SOCKS5Auth{Username: "alice", Password: "s3cr3t"},
	}
	conn, err := s.DialContext(context.Background(), "tcp", backendAddr)
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
		t.Errorf("response %q does not contain %q", body, "hello")
	}
}

func TestSOCKS5_TypedAuth_OverridesURL(t *testing.T) {
	backend := httpEcho(t)
	backendAddr := strings.TrimPrefix(backend.URL, "http://")

	proxyURL := startSOCKS5Stub(t, socks5Opts{
		requireUserPass: true,
		wantUser:        "alice",
		wantPass:        "right",
	})

	// URL userinfo carries the wrong password; the typed Auth carries the
	// right one. A successful tunnel proves the typed option takes
	// precedence over ProxyURL.User.
	u := mustParseURL(t, proxyURL)
	u.User = url.UserPassword("alice", "wrong")

	s := &transport.SOCKS5{
		ProxyURL: u,
		Auth:     &transport.SOCKS5Auth{Username: "alice", Password: "right"},
	}
	conn, err := s.DialContext(context.Background(), "tcp", backendAddr)
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
		t.Errorf("response %q does not contain %q", body, "hello")
	}
}

func TestSOCKS5_TypedAuth_EmptyFallsBack(t *testing.T) {
	backend := httpEcho(t)
	backendAddr := strings.TrimPrefix(backend.URL, "http://")

	// No-auth proxy. An empty &SOCKS5Auth{} must not activate an RFC 1929
	// username/password handshake (no empty-username form exists); it
	// falls back to no-auth and the dial succeeds.
	proxyURL := startSOCKS5Stub(t, socks5Opts{})

	s := &transport.SOCKS5{
		ProxyURL: mustParseURL(t, proxyURL),
		Auth:     &transport.SOCKS5Auth{},
	}
	conn, err := s.DialContext(context.Background(), "tcp", backendAddr)
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
		t.Errorf("response %q does not contain %q", body, "hello")
	}
}

func TestSOCKS5_TargetRejected(t *testing.T) {
	proxyURL := startSOCKS5Stub(t, socks5Opts{
		rejectTarget: func(host string, port uint16) bool { return true },
	})

	s := &transport.SOCKS5{ProxyURL: mustParseURL(t, proxyURL)}
	_, err := s.DialContext(context.Background(), "tcp", "example.com:80")
	if err == nil {
		t.Fatal("expected error from REP=0x05, got nil")
	}
}

func TestSOCKS5_NilProxyURL(t *testing.T) {
	s := &transport.SOCKS5{}
	_, err := s.DialContext(context.Background(), "tcp", "x:1")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "ProxyURL") {
		t.Errorf("error %q does not mention ProxyURL", err.Error())
	}
}

func TestSOCKS5_BadNetwork(t *testing.T) {
	s := &transport.SOCKS5{ProxyURL: mustParseURL(t, "socks5://127.0.0.1:1080")}
	_, err := s.DialContext(context.Background(), "udp", "x:1")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "tcp") {
		t.Errorf("error %q does not mention tcp", err.Error())
	}
}

func TestSOCKS5_BadScheme(t *testing.T) {
	s := &transport.SOCKS5{ProxyURL: mustParseURL(t, "http://127.0.0.1:1080")}
	_, err := s.DialContext(context.Background(), "tcp", "x:1")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "socks") {
		t.Errorf("error %q does not mention socks", err.Error())
	}
}

func TestSOCKS5_DialError(t *testing.T) {
	// Reserve and close a listener to obtain a guaranteed-unused
	// port.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()

	s := &transport.SOCKS5{
		ProxyURL: mustParseURL(t, "socks5://"+addr),
		Timeout:  500 * time.Millisecond,
	}
	_, err = s.DialContext(context.Background(), "tcp", "example.com:80")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestSOCKS5_ContextCancel(t *testing.T) {
	// Listener that accepts but never replies — DialContext should
	// honour ctx cancellation.
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
			// Hold the conn open until the listener is closed.
			t.Cleanup(func() { c.Close() })
		}
	}()

	s := &transport.SOCKS5{ProxyURL: mustParseURL(t, "socks5://"+ln.Addr().String())}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err = s.DialContext(ctx, "tcp", "example.com:80")
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected ctx error, got nil")
	}
	// x/net/proxy.SOCKS5 propagates ctx.Deadline by calling
	// conn.SetDeadline, so a deadline-induced cancellation surfaces
	// as a net.Error.Timeout (i/o timeout) rather than a literal
	// context.DeadlineExceeded. Either is acceptable as long as the
	// dial unblocked within the configured window.
	var nerr net.Error
	timeout := errors.As(err, &nerr) && nerr.Timeout()
	ctxErr := errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled)
	if !timeout && !ctxErr {
		t.Errorf("error %q is neither a net timeout nor a context error", err.Error())
	}
	if elapsed > 2*time.Second {
		t.Errorf("dial unblocked after %v, deadline was 100ms", elapsed)
	}
}

func TestSOCKS5_TimeoutBoundsHandshake(t *testing.T) {
	// Listener accepts TCP but never speaks SOCKS, so the handshake would
	// block forever. With Timeout set and a context that carries no
	// deadline, DialContext must still unblock — regression guard: Timeout
	// used to bound only the TCP connect, not the handshake.
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
			t.Cleanup(func() { c.Close() })
		}
	}()

	s := &transport.SOCKS5{
		ProxyURL: mustParseURL(t, "socks5://"+ln.Addr().String()),
		Timeout:  150 * time.Millisecond,
	}

	start := time.Now()
	_, err = s.DialContext(context.Background(), "tcp", "example.com:80")
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
	if elapsed > 2*time.Second {
		t.Errorf("dial unblocked after %v; Timeout was 150ms", elapsed)
	}
}
