//go:build linux

package detect

import (
	"context"
	"os/exec"
	"time"
)

const gnomeProxySchema = "org.gnome.system.proxy"

// GNOMEDetector reads the manual proxy configuration from the GNOME
// desktop's org.gnome.system.proxy GSettings schema by shelling out to
// gsettings (no D-Bus dependency). "manual" mode yields proxy
// candidates; "auto" mode surfaces autoconfig-url as a PACURL candidate
// (used only in -tags proxykit_pac builds).
//
// Stored credentials (org.gnome.system.proxy.http use-authentication /
// authentication-user / authentication-password) are read into the
// http candidate's User/Pass.
type GNOMEDetector struct{}

func init() {
	Default = append(Default, GNOMEDetector{})
}

// Detect queries gsettings and returns the configured proxy candidates.
// If gsettings is not installed (a non-GNOME host) it returns no
// candidates and no error. A whole call budget of 5s guards against a
// hung gsettings; individual key reads that fail are treated as unset
// rather than failing the detector.
func (GNOMEDetector) Detect() ([]Candidate, error) {
	if _, err := exec.LookPath("gsettings"); err != nil {
		return nil, nil
	}

	// One budget covers up to ten sequential gsettings reads (mode plus
	// host/port across http/https/socks plus the three auth keys).
	// gsettings is normally a few tens of ms per call; 5s leaves wide
	// margin while still bounding a hung invocation.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	get := func(schema, key string) string {
		out, err := exec.CommandContext(ctx, "gsettings", "get", schema, key).Output()
		if err != nil {
			return ""
		}
		return unquoteGSettings(string(out))
	}

	// Read mode first and branch: "manual" issues the nine proxy reads,
	// "auto" reads the single PAC URL, anything else (incl. a failed read
	// yielding "") means no candidates, no error.
	switch get(gnomeProxySchema, "mode") {
	case "auto":
		return gnomeCandidates(gnomeProxy{
			Mode:          "auto",
			AutoconfigURL: get(gnomeProxySchema, "autoconfig-url"),
		}), nil
	case "manual":
		return gnomeCandidates(gnomeProxy{
			Mode:      "manual",
			HTTPHost:  get(gnomeProxySchema+".http", "host"),
			HTTPPort:  get(gnomeProxySchema+".http", "port"),
			HTTPSHost: get(gnomeProxySchema+".https", "host"),
			HTTPSPort: get(gnomeProxySchema+".https", "port"),
			SOCKSHost: get(gnomeProxySchema+".socks", "host"),
			SOCKSPort: get(gnomeProxySchema+".socks", "port"),
			UseAuth:   get(gnomeProxySchema+".http", "use-authentication") == "true",
			AuthUser:  get(gnomeProxySchema+".http", "authentication-user"),
			AuthPass:  get(gnomeProxySchema+".http", "authentication-password"),
		}), nil
	default:
		return nil, nil
	}
}
