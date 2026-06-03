//go:build !linux

package detect

// KDEDetector exists on non-Linux builds so the type itself is
// referable from cross-platform code (e.g. tests asserting type
// identity), but its Detect is a no-op and it is NOT registered into
// detect.Default — kioslaverc is a Linux/KDE convention.
type KDEDetector struct{}

// Detect always returns no candidates on non-Linux builds.
func (KDEDetector) Detect() ([]Candidate, error) {
	return nil, nil
}
