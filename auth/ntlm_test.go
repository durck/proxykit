package auth_test

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/durck/proxykit/auth"
)

// type2Fixture is a valid NTLM Type 2 (Challenge) message taken from
// the MS-NLMP examples (also used as a test fixture by the underlying
// bodgit/ntlmssp library). bodgit/ntlmssp's Client accepts it and
// produces a Type 3 message in response.
var type2Fixture = []byte{
	0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00,
	0x02, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x0c, 0x00,
	0x38, 0x00, 0x00, 0x00, 0x33, 0x82, 0x02, 0xe2,
	0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x06, 0x00, 0x70, 0x17, 0x00, 0x00, 0x00, 0x0f,
	0x53, 0x00, 0x65, 0x00, 0x72, 0x00, 0x76, 0x00,
	0x65, 0x00, 0x72, 0x00,
}

const ntlmHeaderPrefix = "Proxy-Authorization: NTLM "

func decodeNTLMHeader(t *testing.T, h string) []byte {
	t.Helper()
	if !strings.HasPrefix(h, ntlmHeaderPrefix) {
		t.Fatalf("header %q does not start with %q", h, ntlmHeaderPrefix)
	}
	msg, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(h, ntlmHeaderPrefix))
	if err != nil {
		t.Fatalf("base64 decode: %v", err)
	}
	return msg
}

func TestNTLM_Scheme(t *testing.T) {
	if got := auth.NTLM("D", "u", "p").Scheme(); got != "ntlm" {
		t.Errorf("Scheme = %q, want %q", got, "ntlm")
	}
}

func TestNTLM_Type1Format(t *testing.T) {
	a := auth.NTLM("DOMAIN", "user", "pass")
	headers, done, err := a.Headers(nil)
	if err != nil {
		t.Fatalf("Headers(nil): %v", err)
	}
	if done {
		t.Errorf("done = true on first round, want false")
	}
	if len(headers) != 1 {
		t.Fatalf("headers len = %d, want 1", len(headers))
	}
	msg := decodeNTLMHeader(t, headers[0])
	if !bytes.HasPrefix(msg, []byte("NTLMSSP\x00")) {
		t.Errorf("Type 1 missing NTLMSSP signature: % x", msg[:min(8, len(msg))])
	}
	if len(msg) < 12 {
		t.Fatalf("Type 1 message too short: %d bytes", len(msg))
	}
	if msg[8] != 0x01 {
		t.Errorf("Type 1 MessageType = %#x, want 0x01", msg[8])
	}
}

func TestNTLM_Type3Format(t *testing.T) {
	a := auth.NTLM("Domain", "User", "Password")

	if _, _, err := a.Headers(nil); err != nil {
		t.Fatalf("negotiate (round 1): %v", err)
	}

	headers, done, err := a.Headers(type2Fixture)
	if err != nil {
		t.Fatalf("authenticate (round 2): %v", err)
	}
	if !done {
		t.Errorf("done = false on round 2, want true")
	}
	if len(headers) != 1 {
		t.Fatalf("headers len = %d, want 1", len(headers))
	}
	msg := decodeNTLMHeader(t, headers[0])
	if !bytes.HasPrefix(msg, []byte("NTLMSSP\x00")) {
		t.Errorf("Type 3 missing NTLMSSP signature")
	}
	if len(msg) < 12 {
		t.Fatalf("Type 3 message too short: %d bytes", len(msg))
	}
	if msg[8] != 0x03 {
		t.Errorf("Type 3 MessageType = %#x, want 0x03", msg[8])
	}
}

func TestNTLM_AuthenticateBeforeNegotiate(t *testing.T) {
	a := auth.NTLM("D", "u", "p")
	_, done, err := a.Headers(type2Fixture)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !done {
		t.Errorf("done = false on terminal error, want true")
	}
	if !strings.Contains(err.Error(), "negotiate") {
		t.Errorf("error %q does not mention negotiate", err.Error())
	}
}

func TestNTLM_FreshAttempt(t *testing.T) {
	// Two sequential attempts on the same Authenticator (Dialer dialing
	// twice). Each new round 1 must reset state and produce a valid
	// Type 1; round 2 must succeed in both attempts.
	a := auth.NTLM("D", "u", "p")

	for attempt := 1; attempt <= 2; attempt++ {
		h1, done1, err := a.Headers(nil)
		if err != nil {
			t.Fatalf("attempt %d round 1: %v", attempt, err)
		}
		if done1 {
			t.Errorf("attempt %d round 1 done=true, want false", attempt)
		}
		m1 := decodeNTLMHeader(t, h1[0])
		if !bytes.HasPrefix(m1, []byte("NTLMSSP\x00")) || m1[8] != 1 {
			t.Errorf("attempt %d round 1: not a valid Type 1: % x", attempt, m1[:min(12, len(m1))])
		}

		h2, done2, err := a.Headers(type2Fixture)
		if err != nil {
			t.Fatalf("attempt %d round 2: %v", attempt, err)
		}
		if !done2 {
			t.Errorf("attempt %d round 2 done=false, want true", attempt)
		}
		m2 := decodeNTLMHeader(t, h2[0])
		if !bytes.HasPrefix(m2, []byte("NTLMSSP\x00")) || m2[8] != 3 {
			t.Errorf("attempt %d round 2: not a valid Type 3: % x", attempt, m2[:min(12, len(m2))])
		}
	}
}
