//go:build linux && !proxykit_nokerberos

package auth

import (
	"errors"

	"github.com/jcmturner/gokrb5/v8/credentials"
)

// loadCCacheFromKeyring reads an MIT-format credential cache from the
// Linux kernel keyring. residual is the KRB5CCNAME value after the
// "KEYRING:" prefix, e.g. "krb_ccache_alice" or "persistent:1000:1000".
//
// The real keyctl-backed reader lands in a later step; until then this
// returns a clear, terminal error so a KEYRING-configured host fails
// loudly rather than silently falling back.
func loadCCacheFromKeyring(residual string) (*credentials.CCache, error) {
	_ = residual
	return nil, errors.New("KEYRING ccache support not yet implemented")
}
