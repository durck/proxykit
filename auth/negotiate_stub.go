//go:build !windows && proxykit_nokerberos

package auth

import (
	"errors"
	"fmt"
)

// Negotiate, on non-Windows builds compiled with the proxykit_nokerberos
// tag, returns an Authenticator whose Headers always reports
// errors.ErrUnsupported. The tag drops the github.com/jcmturner/gokrb5
// dependency from the build; omit it to get real Kerberos via gokrb5
// (see negotiate_gokrb5.go).
func Negotiate(spn string) Authenticator {
	return negotiateUnsupported{spn: spn}
}

type negotiateUnsupported struct {
	spn string
}

func (negotiateUnsupported) Scheme() string { return "negotiate" }

func (negotiateUnsupported) Headers(_ []byte) ([]string, bool, error) {
	return nil, true, fmt.Errorf("negotiate: built without Kerberos support (proxykit_nokerberos): %w", errors.ErrUnsupported)
}
