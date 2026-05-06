//go:build windows

package detect

import (
	"errors"
	"fmt"

	"golang.org/x/sys/windows/registry"
)

const winINETInternetSettingsKey = `Software\Microsoft\Windows\CurrentVersion\Internet Settings`

// WinINETDetector reads the manual proxy configuration from the
// current user's WinINET registry hive
// (HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings).
// Only the ProxyEnable + ProxyServer values are honoured.
//
// AutoConfigURL (PAC) and AutoDetect (WPAD) are intentionally out of
// scope for v0.1; per-machine HKLM overrides and Group Policy paths
// are likewise not consulted.
type WinINETDetector struct{}

func init() {
	Default = append(Default, WinINETDetector{})
}

// Detect reads the registry and returns at most one candidate. An
// empty result with nil error means "key opened but no proxy is
// configured". A non-existent key is also treated as "no proxy",
// not as an error — a fresh user profile may legitimately lack the
// values.
func (WinINETDetector) Detect() ([]Candidate, error) {
	k, err := registry.OpenKey(registry.CURRENT_USER, winINETInternetSettingsKey, registry.QUERY_VALUE)
	if err != nil {
		if errors.Is(err, registry.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("wininet: open HKCU\\%s: %w", winINETInternetSettingsKey, err)
	}
	defer k.Close()

	enable, _, err := k.GetIntegerValue("ProxyEnable")
	if err != nil {
		if errors.Is(err, registry.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("wininet: read ProxyEnable: %w", err)
	}
	if enable != 1 {
		return nil, nil
	}

	server, _, err := k.GetStringValue("ProxyServer")
	if err != nil {
		if errors.Is(err, registry.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("wininet: read ProxyServer: %w", err)
	}

	parsed := parseWinINETProxyString(server)
	if parsed == "" {
		return nil, nil
	}
	return []Candidate{{URL: parsed, From: "wininet"}}, nil
}
