package proxykit

import (
	"strings"
	"testing"
)

// TestRedactProxyURL covers redactProxyURL, including the issue #5
// regression: a proxy URL that fails url.Parse (e.g. an embedded control
// character) must still have its password stripped before it reaches a
// log line or error string.
func TestRedactProxyURL(t *testing.T) {
	const secret = "s3cr3t"
	tests := []struct {
		name       string
		in         string
		wantNoLeak bool   // result must not contain `secret`
		wantMasked bool   // result must contain "xxxxx"
		wantExact  string // if set, result must equal this verbatim
	}{
		{
			name:       "well-formed with credentials",
			in:         "http://alice:" + secret + "@proxy.corp:8080",
			wantNoLeak: true,
			wantMasked: true,
		},
		{
			name:       "control char in host defeats url.Parse, creds still redacted",
			in:         "http://alice:" + secret + "@pr\x00oxy:8080",
			wantNoLeak: true,
			wantMasked: true,
		},
		{
			name:       "control char inside password",
			in:         "http://bob:pa\x00" + secret + "@proxy:8080",
			wantNoLeak: true,
			wantMasked: true,
		},
		{
			name:       "socks5 with credentials",
			in:         "socks5://carol:" + secret + "@socks:1080",
			wantNoLeak: true,
			wantMasked: true,
		},
		{
			// "user:pass@host" parses with scheme "user" and no
			// recognised userinfo, so url.Redacted never fires — the
			// string fallback must still strip the password.
			name:       "bare userinfo mis-parsed as scheme",
			in:         "dave:" + secret + "@host:8080",
			wantNoLeak: true,
			wantMasked: true,
		},
		{
			// Password with a '/' — must not stop the mask early.
			name:       "slash in password",
			in:         "http://user:pre/" + secret + "@host:8080",
			wantNoLeak: true,
			wantMasked: true,
		},
		{
			// Password with a newline (defeats url.Parse).
			name:       "newline in password",
			in:         "http://user:" + secret + "\ntrailing@host:8080",
			wantNoLeak: true,
			wantMasked: true,
		},
		{
			// Password with a space (defeats url.Parse).
			name:       "space in password",
			in:         "http://user:pre " + secret + "@host:8080",
			wantNoLeak: true,
			wantMasked: true,
		},
		{
			// "://" inside the password must not be mistaken for the
			// scheme separator.
			name:       "scheme-like sequence in password",
			in:         "http://user:" + secret + "://x@host:8080",
			wantNoLeak: true,
			wantMasked: true,
		},
		{
			// A stray '@' before the scheme must not let the credential
			// after a later '@' slip through (uses the last '@').
			name:       "stray at-sign before scheme",
			in:         "@http://user:" + secret + "@host:8080",
			wantNoLeak: true,
			wantMasked: true,
		},
		{
			name:      "no userinfo is returned unchanged",
			in:        "http://proxy.corp:8080",
			wantExact: "http://proxy.corp:8080",
		},
		{
			name:      "malformed without userinfo is not falsely masked",
			in:        "http://pr\x00oxy:8080",
			wantExact: "http://pr\x00oxy:8080",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := redactProxyURL(tc.in)
			if tc.wantNoLeak && strings.Contains(got, secret) {
				t.Errorf("redactProxyURL(%q) = %q — leaks the password", tc.in, got)
			}
			if tc.wantMasked && !strings.Contains(got, "xxxxx") {
				t.Errorf("redactProxyURL(%q) = %q — want masked password (xxxxx)", tc.in, got)
			}
			if tc.wantExact != "" && got != tc.wantExact {
				t.Errorf("redactProxyURL(%q) = %q — want %q unchanged", tc.in, got, tc.wantExact)
			}
		})
	}
}
