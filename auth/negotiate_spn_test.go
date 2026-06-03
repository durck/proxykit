//go:build !proxykit_nokerberos

package auth_test

import (
	"strings"
	"testing"

	"github.com/durck/proxykit/auth"
)

// TestNegotiate_EmptySPN covers the Windows (SSPI) and gokrb5 backends,
// both of which reject an empty SPN with a terminal error mentioning the
// SPN. The proxykit_nokerberos stub returns ErrUnsupported regardless of
// the SPN and is excluded by the build tag.
func TestNegotiate_EmptySPN(t *testing.T) {
	_, done, err := auth.Negotiate("").Headers(nil)
	if err == nil {
		t.Fatal("expected error for empty SPN, got nil")
	}
	if !done {
		t.Error("done = false on terminal error, want true")
	}
	if !strings.Contains(err.Error(), "SPN") {
		t.Errorf("error %q does not mention SPN", err.Error())
	}
}
