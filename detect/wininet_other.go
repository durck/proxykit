//go:build !windows

package detect

// WinINETDetector exists on non-Windows builds so the type itself is
// referable from cross-platform code (e.g. tests asserting type
// identity), but its Detect is a no-op and it is NOT registered into
// detect.Default — auto-discovery via detect.All only runs detectors
// relevant to the host platform.
type WinINETDetector struct{}

// Detect always returns no candidates on non-Windows builds.
func (WinINETDetector) Detect() ([]Candidate, error) {
	return nil, nil
}
