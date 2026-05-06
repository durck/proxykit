package proxykit

import "net/http"

// NewHTTPTransport returns an [http.RoundTripper] that dials through
// the proxy chain configured by cfg. It is a thin wrapper over
// [http.Transport] with DialContext set to the result of [NewDialer];
// callers who need additional knobs (TLS config, idle pool sizing,
// HTTP/2 toggle) should construct their own *http.Transport using
// NewDialer directly.
func NewHTTPTransport(cfg Config) http.RoundTripper {
	d := NewDialer(cfg)
	return &http.Transport{
		DialContext: d.DialContext,
	}
}
