package proxykit

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/durck/proxykit/transport"
)

func TestNoProxyMatcher_Bypass(t *testing.T) {
	m := newNoProxyMatcher("example.com, .corp.local, 10.0.0.0/8, localhost, 192.168.1.5:8080")
	if m == nil {
		t.Fatal("matcher must not be nil for a non-empty list")
	}
	cases := []struct {
		address string
		want    bool
	}{
		{"example.com:443", true},     // exact domain
		{"www.example.com:443", true}, // subdomain suffix
		{"example.org:443", false},    // unrelated domain
		{"api.corp.local:8080", true}, // subdomain of a leading-dot entry
		{"10.1.2.3:1234", true},       // inside CIDR
		{"11.0.0.1:1234", false},      // outside CIDR
		{"localhost:5432", true},      // plain hostname
		{"192.168.1.5:8080", true},    // exact host:port
		{"192.168.1.5:9090", false},   // same host, different port
		{"other.net:443", false},      // no match at all
		{"example.com", false},        // malformed (no port) → fail-safe, not bypassed
	}
	for _, c := range cases {
		if got := m.bypass(c.address); got != c.want {
			t.Errorf("bypass(%q) = %v, want %v", c.address, got, c.want)
		}
	}
}

func TestNoProxyMatcher_Wildcard(t *testing.T) {
	m := newNoProxyMatcher("*")
	if m == nil {
		t.Fatal("matcher must not be nil for \"*\"")
	}
	for _, addr := range []string{"example.com:443", "1.2.3.4:80", "[::1]:443"} {
		if !m.bypass(addr) {
			t.Errorf("bypass(%q) = false, want true for wildcard list", addr)
		}
	}
}

func TestNoProxyMatcher_EmptyIsNil(t *testing.T) {
	for _, list := range []string{"", "   ", "\t"} {
		if m := newNoProxyMatcher(list); m != nil {
			t.Errorf("newNoProxyMatcher(%q) = %v, want nil", list, m)
		}
	}
	// A nil matcher never bypasses.
	var m *noProxyMatcher
	if m.bypass("example.com:443") {
		t.Error("nil matcher must not bypass")
	}
}

func TestResolveNoProxy(t *testing.T) {
	t.Setenv("NO_PROXY", "env.example.com")

	// Explicit + env merge when AutoDetect is on.
	got := resolveNoProxy(Config{NoProxy: "explicit.local", AutoDetect: true})
	if !strings.Contains(got, "explicit.local") || !strings.Contains(got, "env.example.com") {
		t.Errorf("resolveNoProxy (autodetect) = %q, want both explicit.local and env.example.com", got)
	}

	// Without AutoDetect the environment list is ignored.
	got = resolveNoProxy(Config{NoProxy: "explicit.local"})
	if strings.Contains(got, "env.example.com") {
		t.Errorf("resolveNoProxy (no autodetect) = %q, must not include the env list", got)
	}
	if !strings.Contains(got, "explicit.local") {
		t.Errorf("resolveNoProxy (no autodetect) = %q, want explicit.local", got)
	}
}

func TestNewDialer_NoNoProxy_NoWrapper(t *testing.T) {
	// Ensure no ambient env list turns this into a bypassDialer.
	t.Setenv("NO_PROXY", "")
	t.Setenv("no_proxy", "")

	d := NewDialer(Config{Manual: "http://p:8080"})
	if _, ok := d.(*bypassDialer); ok {
		t.Fatalf("without a NoProxy list, NewDialer must not wrap in *bypassDialer; got %T", d)
	}
}

// TestNewDialer_NoProxyDirectE2E proves a NoProxy-matched destination dials
// directly: the Manual proxy points at a dead address, so if the bypass did
// not fire the dial would fail trying to reach the proxy.
func TestNewDialer_NoProxyDirectE2E(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, "direct-ok")
	}))
	defer backend.Close()
	addr := strings.TrimPrefix(backend.URL, "http://")
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split backend addr: %v", err)
	}

	d := NewDialer(Config{
		Manual:  "http://127.0.0.1:1", // nothing listening here
		NoProxy: host,
	})
	bd, ok := d.(*bypassDialer)
	if !ok {
		t.Fatalf("want *bypassDialer, got %T", d)
	}
	if _, ok := bd.direct.(*transport.Direct); !ok {
		t.Fatalf("bypass should dial direct via *transport.Direct, got %T", bd.direct)
	}

	conn, err := d.DialContext(context.Background(), "tcp", addr)
	if err != nil {
		t.Fatalf("bypassed dial should go direct and succeed, got: %v", err)
	}
	defer conn.Close()

	io.WriteString(conn, "GET / HTTP/1.1\r\nHost: "+addr+"\r\nConnection: close\r\n\r\n")
	body, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !strings.Contains(string(body), "direct-ok") {
		t.Errorf("response %q does not contain direct-ok", body)
	}
}

// recordingDialer records the addresses it is asked to dial and never opens a
// real connection, isolating routing decisions from networking.
type recordingDialer struct{ dialed []string }

func (r *recordingDialer) DialContext(_ context.Context, _, address string) (net.Conn, error) {
	r.dialed = append(r.dialed, address)
	return nil, errors.New("recorded")
}

// TestBypassDialer_RoutesByMatch proves bypassDialer routes by the NoProxy
// match itself — on non-loopback hosts, so the result cannot be attributed to
// httpproxy's unconditional loopback bypass.
func TestBypassDialer_RoutesByMatch(t *testing.T) {
	proxied := &recordingDialer{}
	direct := &recordingDialer{}
	bd := &bypassDialer{
		matcher: newNoProxyMatcher("internal.corp, 10.0.0.0/8"),
		proxied: proxied,
		direct:  direct,
	}
	ctx := context.Background()
	for _, addr := range []string{"api.internal.corp:443", "10.1.2.3:5432", "example.com:443"} {
		_, _ = bd.DialContext(ctx, "tcp", addr)
	}

	wantDirect := []string{"api.internal.corp:443", "10.1.2.3:5432"} // matched → direct
	wantProxied := []string{"example.com:443"}                       // unmatched → proxied
	if !slices.Equal(direct.dialed, wantDirect) {
		t.Errorf("direct dialed %v, want %v", direct.dialed, wantDirect)
	}
	if !slices.Equal(proxied.dialed, wantProxied) {
		t.Errorf("proxied dialed %v, want %v", proxied.dialed, wantProxied)
	}
}

// TestNewDialer_EnvNoProxyUnderAutoDetect proves the env NO_PROXY alone (no
// Config.NoProxy) activates the bypass under AutoDetect.
func TestNewDialer_EnvNoProxyUnderAutoDetect(t *testing.T) {
	t.Setenv("NO_PROXY", "internal.corp")
	d := NewDialer(Config{AutoDetect: true})
	if _, ok := d.(*bypassDialer); !ok {
		t.Fatalf("env NO_PROXY under AutoDetect should yield *bypassDialer, got %T", d)
	}
}
