//go:build proxykit_pac

package proxykit

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

type fakeResolver struct {
	ips map[string][]net.IP
	my  net.IP
}

func (f fakeResolver) lookupIP(host string) []net.IP { return f.ips[host] }
func (f fakeResolver) myIP() net.IP                   { return f.my }

func TestNewPACEngine_Wired(t *testing.T) {
	if newPACEngine == nil {
		t.Fatal("newPACEngine nil; eval init did not run under proxykit_pac")
	}
	eng, err := newPACEngine(`function FindProxyForURL(url, host){ return "DIRECT"; }`)
	if err != nil {
		t.Fatalf("newPACEngine: %v", err)
	}
	defer eng.close()
	got, err := eng.findProxy(context.Background(), "https://x/", "x")
	if err != nil || got != "DIRECT" {
		t.Fatalf("findProxy = %q, %v; want DIRECT, nil", got, err)
	}
}

func TestCompilePAC_RoutingWithHelpers(t *testing.T) {
	script := `function FindProxyForURL(url, host) {
		if (isInNet(host, "10.0.0.0", "255.0.0.0")) return "DIRECT";
		if (shExpMatch(host, "*.corp")) return "PROXY p:8080";
		return "PROXY def:3128";
	}`
	res := fakeResolver{
		ips: map[string][]net.IP{
			"a.corp":   {net.ParseIP("1.2.3.4")},
			"internal": {net.ParseIP("10.1.1.1")},
		},
		my: net.ParseIP("192.168.1.5"),
	}
	eng, err := compilePAC(script, res)
	if err != nil {
		t.Fatalf("compilePAC: %v", err)
	}
	defer eng.close()

	cases := []struct{ host, want string }{
		{"internal", "DIRECT"},
		{"a.corp", "PROXY p:8080"},
		{"x.org", "PROXY def:3128"},
	}
	for _, c := range cases {
		got, err := eng.findProxy(context.Background(), "https://"+c.host+"/", c.host)
		if err != nil {
			t.Errorf("findProxy(%q): %v", c.host, err)
			continue
		}
		if got != c.want {
			t.Errorf("findProxy(%q) = %q, want %q", c.host, got, c.want)
		}
	}
}

func TestCompilePAC_FindProxyForURLEx(t *testing.T) {
	eng, err := compilePAC(`function FindProxyForURLEx(url, host){ return "PROXY ex:1"; }`, systemPACResolver{})
	if err != nil {
		t.Fatalf("compilePAC: %v", err)
	}
	defer eng.close()
	got, err := eng.findProxy(context.Background(), "https://x/", "x")
	if err != nil || got != "PROXY ex:1" {
		t.Fatalf("findProxy = %q, %v; want 'PROXY ex:1', nil", got, err)
	}
}

func TestCompilePAC_NoFunction(t *testing.T) {
	_, err := compilePAC(`var x = 1;`, systemPACResolver{})
	if !errors.Is(err, errors.ErrUnsupported) {
		t.Fatalf("err = %v, want wrapping ErrUnsupported", err)
	}
}

func TestCompilePAC_SyntaxError(t *testing.T) {
	if _, err := compilePAC(`function (`, systemPACResolver{}); err == nil {
		t.Fatal("expected a compile error for invalid JS")
	}
}

func TestGojaPACEngine_Timeout(t *testing.T) {
	eng, err := compilePAC(`function FindProxyForURL(url, host){ while(true){} }`, systemPACResolver{})
	if err != nil {
		t.Fatalf("compilePAC: %v", err)
	}
	defer eng.close()

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err = eng.findProxy(ctx, "https://x/", "x")
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("expected an interrupt error from the runaway PAC")
	}
	if elapsed > 2*time.Second {
		t.Errorf("eval unblocked after %v; watchdog should fire near 200ms", elapsed)
	}
}

// TestGojaPACEngine_Concurrent guards the goja mutex: concurrent
// DialContext-style calls must not race (run with -race).
func TestGojaPACEngine_Concurrent(t *testing.T) {
	eng, err := compilePAC(`function FindProxyForURL(url, host){ return "PROXY p:8080"; }`, systemPACResolver{})
	if err != nil {
		t.Fatalf("compilePAC: %v", err)
	}
	defer eng.close()

	var wg sync.WaitGroup
	for i := 0; i < 24; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if got, err := eng.findProxy(context.Background(), "https://x/", "x"); err != nil || got != "PROXY p:8080" {
				t.Errorf("findProxy = %q, %v", got, err)
			}
		}()
	}
	wg.Wait()
}
