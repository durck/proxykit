//go:build !proxykit_pac

package proxykit

import (
	"errors"
	"testing"
)

// TestNewPACEngine_StubUnsupported verifies the default build (no
// proxykit_pac tag) wires a stub that reports the feature is unavailable
// via errors.ErrUnsupported, so callers can degrade gracefully.
func TestNewPACEngine_StubUnsupported(t *testing.T) {
	if newPACEngine == nil {
		t.Fatal("newPACEngine is nil; stub init did not run")
	}
	eng, err := newPACEngine("function FindProxyForURL(url, host){ return 'DIRECT'; }")
	if eng != nil {
		t.Errorf("engine = %v, want nil in the default build", eng)
	}
	if !errors.Is(err, errors.ErrUnsupported) {
		t.Errorf("err = %v, want one wrapping errors.ErrUnsupported", err)
	}
}
