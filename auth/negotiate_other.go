//go:build !windows

package auth

import (
	"errors"
	"fmt"
)

// Negotiate on non-Windows builds returns an Authenticator whose
// Headers always reports errors.ErrUnsupported. SSPI is Windows-only;
// Linux/macOS Kerberos via gokrb5 lands in v0.2.
func Negotiate(spn string) Authenticator {
	return negotiateUnsupported{spn: spn}
}

type negotiateUnsupported struct {
	spn string
}

func (negotiateUnsupported) Scheme() string { return "negotiate" }

func (negotiateUnsupported) Headers(_ []byte) ([]string, bool, error) {
	return nil, true, fmt.Errorf("negotiate: SSPI is Windows-only: %w", errors.ErrUnsupported)
}
