package auth_test

import (
	"encoding/base64"
	"runtime"
	"strings"
	"testing"

	"github.com/durck/proxykit/auth"
)

func TestNegotiate_Scheme(t *testing.T) {
	if got := auth.Negotiate("http/x").Scheme(); got != "negotiate" {
		t.Errorf("Scheme = %q, want %q", got, "negotiate")
	}
}

// TestNegotiate_WindowsSmoke exercises the SSPI surface end-to-end on
// Windows. It accepts either success (we got a base64-encoded token)
// or a documented SSPI error: hosts without a valid Kerberos ticket
// for the chosen SPN (e.g. CI runners not joined to a domain) commonly
// return SEC_E_NO_CREDENTIALS / SEC_E_TARGET_UNKNOWN, which is fine —
// the test still proves the syscall path is wired correctly.
func TestNegotiate_WindowsSmoke(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-only")
	}
	a := auth.Negotiate("http/127.0.0.1")
	headers, done, err := a.Headers(nil)
	if err != nil {
		// Acceptable: domain-less hosts cannot mint a Kerberos
		// ticket for an arbitrary SPN. Verify the error came from
		// SSPI (named status code) rather than a Go-side bug.
		if !strings.Contains(err.Error(), "SSPI") && !strings.Contains(err.Error(), "negotiate:") {
			t.Errorf("unexpected error shape %q", err.Error())
		}
		return
	}
	if !done {
		t.Errorf("done = false, want true (Negotiate is single-round)")
	}
	if len(headers) != 1 {
		t.Fatalf("headers len = %d, want 1", len(headers))
	}
	const prefix = "Proxy-Authorization: Negotiate "
	if !strings.HasPrefix(headers[0], prefix) {
		t.Errorf("header %q does not start with %q", headers[0], prefix)
	}
	encoded := strings.TrimPrefix(headers[0], prefix)
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("base64 decode %q: %v", encoded, err)
	}
	if len(decoded) == 0 {
		t.Error("decoded token is empty")
	}
}
