package auth

import "encoding/base64"

// Basic returns an HTTP Basic [Authenticator] (RFC 7617). It produces
// a single round emitting "Proxy-Authorization: Basic <base64(user:pass)>".
// The challenge is ignored — Basic does not depend on it.
//
// Basic transmits the credentials in plaintext (only base64-encoded);
// it is appropriate over TLS-protected proxy connections (https proxy
// scheme) but leaks credentials on plain http hops.
func Basic(user, pass string) Authenticator {
	return basic{user: user, pass: pass}
}

type basic struct {
	user, pass string
}

func (basic) Scheme() string { return "basic" }

func (b basic) Headers(_ []byte) ([]string, bool, error) {
	creds := base64.StdEncoding.EncodeToString([]byte(b.user + ":" + b.pass))
	return []string{"Proxy-Authorization: Basic " + creds}, true, nil
}
