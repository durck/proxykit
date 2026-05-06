package auth

// None returns an Authenticator that contributes no Proxy-Authorization
// header and finishes after a single round. Its Scheme is "" so it
// never matches a proxy-advertised scheme; it is a sentinel useful
// for tests and for explicit "no credentials available" entries.
func None() Authenticator { return none{} }

type none struct{}

func (none) Scheme() string { return "" }

func (none) Headers(_ []byte) ([]string, bool, error) {
	return nil, true, nil
}
