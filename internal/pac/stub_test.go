//go:build !proxykit_pac

package pac

import (
	"errors"
	"testing"
)

// TestNewEngine_StubUnsupported verifies the default build (no
// proxykit_pac tag) wires a stub that reports the feature is unavailable
// via errors.ErrUnsupported, so callers can degrade gracefully.
func TestNewEngine_StubUnsupported(t *testing.T) {
	if NewEngine == nil {
		t.Fatal("NewEngine is nil; stub init did not run")
	}
	eng, err := NewEngine("function FindProxyForURL(url, host){ return 'DIRECT'; }")
	if eng != nil {
		t.Errorf("engine = %v, want nil in the default build", eng)
	}
	if !errors.Is(err, errors.ErrUnsupported) {
		t.Errorf("err = %v, want one wrapping errors.ErrUnsupported", err)
	}
}
