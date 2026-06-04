// Package detect discovers system proxy configurations from the sources
// available on the host — *_PROXY environment variables (all platforms),
// the Windows WinINET (HKCU) and WinHTTP (HKLM + IE) registries, the Linux
// /etc/environment file and the GNOME and KDE desktop settings, and the
// macOS system configuration via scutil — and exposes them as a uniform
// list of [Candidate]s. A Candidate carries either a concrete proxy URL or,
// when the source advertises one, a PAC URL ([Candidate.PACURL]).
//
// Each platform-specific file registers its detector into [Default]
// at init time; downstream consumers call [All] to retrieve the
// merged candidate list, or instantiate a specific [Detector] by
// hand for finer control.
package detect

import "errors"

// Candidate is a discovered proxy configuration.
type Candidate struct {
	// URL is the proxy URL with no userinfo, e.g. "http://proxy:8080"
	// or "socks5://proxy:1080".
	URL string

	// User and Pass are the credentials, when the source provided
	// them inline (e.g. HTTP_PROXY=http://user:pass@proxy:8080).
	// Both empty when no userinfo was attached.
	User string
	Pass string

	// From identifies the source detector — "env", "wininet",
	// "linux/gnome", etc. Useful for diagnostics and precedence
	// decisions in the caller.
	From string

	// PACURL, when non-empty, is the URL of a Proxy Auto-Config script
	// the source advertises (e.g. Windows AutoConfigURL, macOS
	// ProxyAutoConfigURLString, GNOME mode=auto autoconfig-url). It is a
	// PAC candidate rather than a concrete proxy: URL is then empty.
	// Consumers ignore it unless built with -tags proxykit_pac.
	PACURL string
}

// Detector returns proxy candidates from a single source.
type Detector interface {
	// Detect inspects the source and returns any proxy candidates
	// it finds. An empty slice + nil error means "source consulted,
	// nothing configured".
	Detect() ([]Candidate, error)
}

// Default is the list of detectors used by [All]. Each platform-
// specific file (env.go, wininet_windows.go, ...) appends its own
// detector at init time.
var Default []Detector

// All runs every detector in [Default] in order and concatenates
// their candidates. Per-detector errors are collected and joined;
// one source failing does not stop the others.
func All() ([]Candidate, error) {
	var out []Candidate
	var errs []error
	for _, d := range Default {
		cs, err := d.Detect()
		if err != nil {
			errs = append(errs, err)
			continue
		}
		out = append(out, cs...)
	}
	return out, errors.Join(errs...)
}
