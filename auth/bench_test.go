package auth_test

import (
	"testing"

	"github.com/durck/proxykit/auth"
)

// BenchmarkBasic_Headers measures the cost of one Basic-auth header
// emission (base64 encode of user:pass).
func BenchmarkBasic_Headers(b *testing.B) {
	a := auth.Basic("alice", "s3cr3t-password-with-some-length")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, err := a.Headers(nil)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkNTLM_Handshake walks the full 2-round NTLM dance per
// iteration: Headers(nil) creates a fresh ntlmssp.Client and emits
// Type 1, Headers(challenge) consumes the canned Type 2 challenge
// and emits Type 3. Dominated by NTLMSSP crypto (NTLMv2 hash + LM
// response).
func BenchmarkNTLM_Handshake(b *testing.B) {
	a := auth.NTLM("DOMAIN", "user", "pass")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, _, err := a.Headers(nil); err != nil {
			b.Fatalf("round 1: %v", err)
		}
		if _, _, err := a.Headers(type2Fixture); err != nil {
			b.Fatalf("round 2: %v", err)
		}
	}
}
