//go:build !darwin

package detect

// MacOSDetector exists on non-macOS builds so the type itself is
// referable from cross-platform code (e.g. tests asserting type
// identity), but its Detect is a no-op and it is NOT registered into
// detect.Default — scutil / SystemConfiguration is macOS-only.
type MacOSDetector struct{}

// Detect always returns no candidates on non-macOS builds.
func (MacOSDetector) Detect() ([]Candidate, error) {
	return nil, nil
}
