//go:build !windows && !linux && !proxykit_nokerberos

package auth

import (
	"fmt"
	"runtime"

	"github.com/jcmturner/gokrb5/v8/credentials"
)

// loadCCacheFromKeyring is unsupported on non-Linux Unix systems (macOS,
// the BSDs): the kernel keyring is a Linux facility. Point KRB5CCNAME at
// a FILE or DIR cache instead.
func loadCCacheFromKeyring(_ string) (*credentials.CCache, error) {
	return nil, fmt.Errorf("KEYRING ccache unsupported on %s (set KRB5CCNAME=FILE:...)", runtime.GOOS)
}
