//go:build windows

package detect

import (
	"errors"
	"fmt"
	"strings"

	"golang.org/x/sys/windows/registry"
)

const winINETInternetSettingsKey = `Software\Microsoft\Windows\CurrentVersion\Internet Settings`

// WinINETDetector reads the manual proxy configuration from the
// current user's WinINET registry hive
// (HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings):
// the ProxyEnable + ProxyServer values, plus AutoConfigURL surfaced as a
// PACURL candidate (used only in -tags proxykit_pac builds).
//
// The per-machine HKLM hive is consulted by WinHTTPDetector instead, and
// Group Policy paths are not read.
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
	parsed, err := readInternetSettingsProxy(registry.CURRENT_USER, "wininet")
	if err != nil {
		return nil, err
	}
	var out []Candidate
	if parsed != "" {
		out = append(out, Candidate{URL: parsed, From: "wininet"})
	}
	if pac := readInternetSettingsAutoConfigURL(registry.CURRENT_USER); pac != "" {
		out = append(out, Candidate{PACURL: pac, From: "wininet"})
	}
	return out, nil
}

// readInternetSettingsAutoConfigURL reads the AutoConfigURL (PAC URL)
// string value from the "Internet Settings" key under root. It returns ""
// when the key/value is absent or unreadable — a PAC URL is optional, so
// failure to find one is never an error.
func readInternetSettingsAutoConfigURL(root registry.Key) string {
	k, err := registry.OpenKey(root, winINETInternetSettingsKey, registry.QUERY_VALUE)
	if err != nil {
		return ""
	}
	defer k.Close()
	v, _, err := k.GetStringValue("AutoConfigURL")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(v)
}

// readInternetSettingsProxy reads ProxyEnable + ProxyServer from the
// "Internet Settings" key under root and returns the parsed proxy URL
// (see parseWinINETProxyString). It returns "" with a nil error when the
// key or values are absent, or when ProxyEnable != 1 — a missing or
// disabled configuration is "nothing here", not a failure. label
// prefixes any genuine error. Shared by the HKCU WinINETDetector and the
// HKLM branch of WinHTTPDetector.
func readInternetSettingsProxy(root registry.Key, label string) (string, error) {
	k, err := registry.OpenKey(root, winINETInternetSettingsKey, registry.QUERY_VALUE)
	if err != nil {
		if errors.Is(err, registry.ErrNotExist) {
			return "", nil
		}
		return "", fmt.Errorf("%s: open Internet Settings: %w", label, err)
	}
	defer k.Close()

	enable, _, err := k.GetIntegerValue("ProxyEnable")
	if err != nil {
		if errors.Is(err, registry.ErrNotExist) {
			return "", nil
		}
		return "", fmt.Errorf("%s: read ProxyEnable: %w", label, err)
	}
	if enable != 1 {
		return "", nil
	}

	server, _, err := k.GetStringValue("ProxyServer")
	if err != nil {
		if errors.Is(err, registry.ErrNotExist) {
			return "", nil
		}
		return "", fmt.Errorf("%s: read ProxyServer: %w", label, err)
	}
	return parseWinINETProxyString(server), nil
}
