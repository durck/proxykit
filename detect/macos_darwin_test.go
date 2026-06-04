//go:build darwin

package detect

import (
	"net/url"
	"testing"
)

// TestMacOSDetector_DarwinSmoke asserts the `scutil --proxy` path runs
// without panicking on macOS. The runner's actual proxy state is
// implementation-defined, so we only verify the contract: the call
// returns no error and every candidate is tagged "macos" with a parseable
// URL. This is the only test that exercises the live scutil exec; it runs
// on the macos-latest CI runner.
func TestMacOSDetector_DarwinSmoke(t *testing.T) {
	cs, err := MacOSDetector{}.Detect()
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	for _, c := range cs {
		if c.From != "macos" {
			t.Errorf("From = %q, want macos", c.From)
		}
		// A PAC candidate carries PACURL and no URL; validate it separately.
		if c.PACURL != "" {
			if _, perr := url.Parse(c.PACURL); perr != nil {
				t.Errorf("candidate PACURL %q does not parse: %v", c.PACURL, perr)
			}
			continue
		}
		u, perr := url.Parse(c.URL)
		if perr != nil {
			t.Errorf("candidate URL %q does not parse: %v", c.URL, perr)
			continue
		}
		if u.Host == "" {
			t.Errorf("candidate URL %q has empty host", c.URL)
		}
		if u.Scheme != "http" && u.Scheme != "socks5" {
			t.Errorf("candidate URL %q has unexpected scheme %q", c.URL, u.Scheme)
		}
	}
}
