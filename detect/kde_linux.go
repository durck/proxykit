//go:build linux

package detect

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// KDEDetector reads the manual proxy configuration from the KDE
// kioslaverc file ($XDG_CONFIG_HOME/kioslaverc, or
// ~/.config/kioslaverc). Only ProxyType=1 (manual) is honoured; PAC,
// WPAD and "use environment" modes are out of scope (see
// parseKioslaverc).
type KDEDetector struct{}

func init() {
	Default = append(Default, KDEDetector{})
}

// Detect reads kioslaverc and returns the proxy candidates it declares.
// A missing file (no KDE config) is treated as "no proxy configured"
// (nil, nil), not an error; other read errors are surfaced.
func (KDEDetector) Detect() ([]Candidate, error) {
	path := kioslavercPath()
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("kde: read %s: %w", path, err)
	}
	return parseKioslaverc(string(data)), nil
}

// kioslavercPath resolves the kioslaverc location, honouring
// XDG_CONFIG_HOME and falling back to ~/.config. Returns "" when
// neither XDG_CONFIG_HOME nor HOME is set.
func kioslavercPath() string {
	if dir := os.Getenv("XDG_CONFIG_HOME"); dir != "" {
		return filepath.Join(dir, "kioslaverc")
	}
	if home := os.Getenv("HOME"); home != "" {
		return filepath.Join(home, ".config", "kioslaverc")
	}
	return ""
}
