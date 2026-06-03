//go:build !linux

package detect

// GNOMEDetector exists on non-Linux builds so the type itself is
// referable from cross-platform code (e.g. tests asserting type
// identity), but its Detect is a no-op and it is NOT registered into
// detect.Default — the GNOME GSettings schema is Linux-only.
type GNOMEDetector struct{}

// Detect always returns no candidates on non-Linux builds.
func (GNOMEDetector) Detect() ([]Candidate, error) {
	return nil, nil
}
