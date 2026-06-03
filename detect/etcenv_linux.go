//go:build linux

package detect

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
)

// EtcEnvironmentDetector reads system-wide proxy settings from
// /etc/environment. Linux desktop and server users frequently set
// http_proxy / https_proxy there so the values apply to every login
// session; those assignments do not reach a non-login shell's
// environment, so EnvDetector alone would miss them.
type EtcEnvironmentDetector struct{}

func init() {
	Default = append(Default, EtcEnvironmentDetector{})
}

// Detect reads /etc/environment and returns the proxy candidates it
// declares. A missing file is treated as "no proxy configured" (nil,
// nil), not an error — many systems ship without one. Other read
// errors are surfaced.
func (EtcEnvironmentDetector) Detect() ([]Candidate, error) {
	const path = "/etc/environment"
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("etc-environment: read %s: %w", path, err)
	}
	return parseEtcEnvironment(string(data)), nil
}
