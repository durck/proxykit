//go:build !linux

package detect

// EtcEnvironmentDetector exists on non-Linux builds so the type itself
// is referable from cross-platform code (e.g. tests asserting type
// identity), but its Detect is a no-op and it is NOT registered into
// detect.Default — /etc/environment is a Linux convention.
type EtcEnvironmentDetector struct{}

// Detect always returns no candidates on non-Linux builds.
func (EtcEnvironmentDetector) Detect() ([]Candidate, error) {
	return nil, nil
}
