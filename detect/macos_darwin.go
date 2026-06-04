//go:build darwin

package detect

import (
	"context"
	"os/exec"
	"time"
)

// MacOSDetector reads the system proxy configuration on macOS by shelling
// out to `scutil --proxy`. Shelling out (rather than binding the
// SystemConfiguration framework via cgo) keeps the library cgo-free and
// statically linkable, matching the GNOMEDetector approach on Linux.
//
// Per-protocol manual proxies (HTTP/HTTPS/SOCKS) are honoured; PAC/WPAD
// (ProxyAutoConfigEnable) is out of scope as Candidate has no PAC field.
// macOS stores proxy credentials in the Keychain rather than in the proxy
// configuration, so candidates never carry User/Pass.
type MacOSDetector struct{}

func init() {
	Default = append(Default, MacOSDetector{})
}

// Detect runs `scutil --proxy` and returns the configured candidates. If
// scutil is not on PATH it returns no candidates and no error. A 5s
// budget guards against a hung invocation; a non-zero exit is treated as
// "nothing configured" rather than a detector failure, mirroring
// GNOMEDetector.
func (MacOSDetector) Detect() ([]Candidate, error) {
	if _, err := exec.LookPath("scutil"); err != nil {
		return nil, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	out, err := exec.CommandContext(ctx, "scutil", "--proxy").Output()
	if err != nil {
		return nil, nil
	}
	return parseSCUtilProxy(string(out)), nil
}
