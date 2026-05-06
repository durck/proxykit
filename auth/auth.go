// Package auth provides Authenticator implementations for HTTP CONNECT
// proxy authentication. An Authenticator drives a multi-round
// Proxy-Authorization exchange; the transport layer iterates the
// Authenticators in [proxykit.Config.Auth] on HTTP 407 until one
// succeeds or all are exhausted.
package auth

// Authenticator drives a single CONNECT-with-auth handshake against an
// HTTP CONNECT proxy. Implementations are typically stateful (e.g.
// NTLM keeps a session struct between rounds) and not safe for
// concurrent use; the transport layer treats each Authenticator as
// belonging to a single dial attempt.
type Authenticator interface {
	// Scheme returns the canonical RFC 7235 auth scheme this
	// Authenticator implements, lower-cased ("basic", "ntlm",
	// "negotiate", ...). The transport matches it against the
	// Proxy-Authenticate values the proxy advertised; returning the
	// empty string disables scheme matching, which is the right
	// behaviour for sentinel implementations that contribute no
	// headers.
	Scheme() string

	// Headers returns the headers to attach to the next CONNECT
	// request given the most recent server challenge.
	//
	// challenge is nil on the first call. On subsequent calls it is
	// the payload the proxy supplied alongside its scheme in
	// Proxy-Authenticate, base64-decoded for binary schemes such as
	// NTLM or Negotiate.
	//
	// headers entries are complete HTTP header lines, e.g.
	// "Proxy-Authorization: Basic dXNlcjpwYXNz".
	//
	// done=true signals "this was my last round; do not call me
	// again". A subsequent HTTP 407 from the proxy is then reported
	// as a permanent failure for this Authenticator and the next one
	// in the chain is tried.
	Headers(challenge []byte) (headers []string, done bool, err error)
}
