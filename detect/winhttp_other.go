//go:build !windows

package detect

// WinHTTPDetector exists on non-Windows builds so the type is referable
// from cross-platform code (e.g. tests asserting type identity), but its
// Detect is a no-op and it is NOT registered into detect.Default —
// auto-discovery via detect.All only runs detectors relevant to the host
// platform.
type WinHTTPDetector struct{}

// Detect always returns no candidates on non-Windows builds.
func (WinHTTPDetector) Detect() ([]Candidate, error) {
	return nil, nil
}
