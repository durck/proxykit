package auth_test

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/durck/proxykit/auth"
)

func TestBasic_Scheme(t *testing.T) {
	if got := auth.Basic("u", "p").Scheme(); got != "basic" {
		t.Errorf("Scheme = %q, want %q", got, "basic")
	}
}

func TestBasic_Headers_Encoding(t *testing.T) {
	tests := []struct {
		name, user, pass string
	}{
		{"simple", "alice", "secret"},
		{"empty pass", "alice", ""},
		{"empty user", "", "secret"},
		{"both empty", "", ""},
		{"colon in pass", "alice", "p:ass"},
		{"unicode", "ünüsüal", "пароль"},
		{"special chars", `O'Brien`, `pa$$w0rd!?#`},
		{"long pass", "u", strings.Repeat("x", 200)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := auth.Basic(tt.user, tt.pass)
			headers, done, err := a.Headers(nil)
			if err != nil {
				t.Fatalf("Headers: %v", err)
			}
			if !done {
				t.Errorf("done = false, want true")
			}
			if len(headers) != 1 {
				t.Fatalf("headers len = %d, want 1", len(headers))
			}
			const prefix = "Proxy-Authorization: Basic "
			if !strings.HasPrefix(headers[0], prefix) {
				t.Fatalf("header %q does not start with %q", headers[0], prefix)
			}
			encoded := strings.TrimPrefix(headers[0], prefix)
			decoded, err := base64.StdEncoding.DecodeString(encoded)
			if err != nil {
				t.Fatalf("base64 decode %q: %v", encoded, err)
			}
			want := tt.user + ":" + tt.pass
			if string(decoded) != want {
				t.Errorf("decoded = %q, want %q", decoded, want)
			}
		})
	}
}

func TestBasic_IgnoresChallenge(t *testing.T) {
	a := auth.Basic("u", "p")
	h1, _, _ := a.Headers(nil)
	h2, _, _ := a.Headers([]byte(`realm="corp"`))
	h3, _, _ := a.Headers([]byte("anything else"))
	if h1[0] != h2[0] || h1[0] != h3[0] {
		t.Errorf("output varied with challenge: %q vs %q vs %q", h1[0], h2[0], h3[0])
	}
}

func TestNone(t *testing.T) {
	a := auth.None()
	if a.Scheme() != "" {
		t.Errorf("Scheme = %q, want empty", a.Scheme())
	}
	headers, done, err := a.Headers(nil)
	if err != nil {
		t.Errorf("Headers err = %v, want nil", err)
	}
	if !done {
		t.Errorf("done = false, want true")
	}
	if len(headers) != 0 {
		t.Errorf("headers = %v, want empty", headers)
	}
}
