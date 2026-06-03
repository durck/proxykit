//go:build !windows && proxykit_nokerberos

package auth_test

import (
	"errors"
	"testing"

	"github.com/durck/proxykit/auth"
)

// TestNegotiate_Unsupported verifies the proxykit_nokerberos opt-out
// stub: on non-Windows builds compiled with that tag, Negotiate reports
// errors.ErrUnsupported in a single (done=true) round.
func TestNegotiate_Unsupported(t *testing.T) {
	_, done, err := auth.Negotiate("HTTP/proxy").Headers(nil)
	if !errors.Is(err, errors.ErrUnsupported) {
		t.Errorf("err = %v, want errors.ErrUnsupported", err)
	}
	if !done {
		t.Error("done = false, want true")
	}
}
