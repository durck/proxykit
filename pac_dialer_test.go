package proxykit

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/durck/proxykit/transport"
)

type stubPACEngine struct {
	result string
	err    error
}

func (s stubPACEngine) findProxy(context.Context, string, string) (string, error) {
	return s.result, s.err
}
func (s stubPACEngine) close() {}

type sentinelDialer struct{}

func (*sentinelDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	return nil, errors.New("sentinel")
}

func TestPacChain(t *testing.T) {
	cfg := Config{}
	fb := &sentinelDialer{}

	t.Run("direct", func(t *testing.T) {
		d := pacChain(context.Background(), stubPACEngine{result: "DIRECT"}, "h", cfg, fb)
		if _, ok := d.(*transport.Direct); !ok {
			t.Fatalf("want *transport.Direct, got %T", d)
		}
	})
	t.Run("proxy", func(t *testing.T) {
		d := pacChain(context.Background(), stubPACEngine{result: "PROXY p:8080"}, "h", cfg, fb)
		c, ok := d.(*transport.Connect)
		if !ok {
			t.Fatalf("want *transport.Connect, got %T", d)
		}
		if c.ProxyURL.Host != "p:8080" {
			t.Errorf("ProxyURL.Host = %q, want p:8080", c.ProxyURL.Host)
		}
	})
	t.Run("socks", func(t *testing.T) {
		d := pacChain(context.Background(), stubPACEngine{result: "SOCKS s:1080"}, "h", cfg, fb)
		if _, ok := d.(*transport.SOCKS5); !ok {
			t.Fatalf("want *transport.SOCKS5, got %T", d)
		}
	})
	t.Run("multiple becomes a fallback chain", func(t *testing.T) {
		d := pacChain(context.Background(), stubPACEngine{result: "PROXY a:1; PROXY b:2"}, "h", cfg, fb)
		if _, ok := d.(*fallbackDialer); !ok {
			t.Fatalf("want *fallbackDialer, got %T", d)
		}
	})
	t.Run("eval error uses fallback", func(t *testing.T) {
		d := pacChain(context.Background(), stubPACEngine{err: errors.New("boom")}, "h", cfg, fb)
		if d != Dialer(fb) {
			t.Fatalf("want the fallback dialer, got %T", d)
		}
	})
	t.Run("unusable result uses fallback", func(t *testing.T) {
		d := pacChain(context.Background(), stubPACEngine{result: "GARBAGE TOKEN"}, "h", cfg, fb)
		if d != Dialer(fb) {
			t.Fatalf("want the fallback dialer, got %T", d)
		}
	})
}

func TestNewDialer_NoPACSource(t *testing.T) {
	if d := NewDialer(Config{}); func() bool { _, ok := d.(*transport.Direct); return !ok }() {
		t.Fatalf("empty config should give *transport.Direct, got %T", d)
	}
}

// TestNewDialer_PACDegradesWithoutTag verifies that, in the default build,
// a configured PAC source is ignored with a warning and routing falls back
// to the static dialer (here Direct) rather than creating a pacDialer.
func TestNewDialer_PACDegradesWithoutTag(t *testing.T) {
	if pacSupported {
		t.Skip("built with proxykit_pac; this is the default-build degradation path")
	}
	var warned bool
	d := NewDialer(Config{
		PAC:   `function FindProxyForURL(u, h){ return "DIRECT"; }`,
		OnLog: func(level, _ string) {
			if level == "warn" {
				warned = true
			}
		},
	})
	if _, ok := d.(*pacDialer); ok {
		t.Fatal("default build must not create a pacDialer")
	}
	if _, ok := d.(*transport.Direct); !ok {
		t.Fatalf("want *transport.Direct fallback, got %T", d)
	}
	if !warned {
		t.Error("expected a warning that PAC support is missing")
	}
}
