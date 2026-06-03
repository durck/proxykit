package detect

import "strings"

// parseKioslaverc extracts proxy candidates from the contents of a KDE
// kioslaverc file. Only the [Proxy Settings] group is consulted, and
// only when ProxyType=1 (manual). Other ProxyType values are skipped:
//
//	0  no proxy
//	2  PAC script        — Candidate cannot represent a PAC URL
//	3  WPAD auto-detect  — likewise
//	4  use environment   — already covered by EnvDetector
//
// httpProxy / httpsProxy map to an http:// URL, socksProxy to socks5://.
//
// Kept platform-agnostic so the parser is testable without a real KDE
// config on disk.
func parseKioslaverc(content string) []Candidate {
	s := kioslavercSection(content, "Proxy Settings")
	if s["ProxyType"] != "1" {
		return nil
	}

	var out []Candidate
	add := func(scheme, rawVal string) {
		hostPort := parseKDEProxyValue(rawVal)
		if hostPort == "" {
			return
		}
		c, ok := candidateFromRaw(scheme+"://"+hostPort, "linux/kde")
		if !ok {
			return
		}
		for _, e := range out {
			if e.URL == c.URL { // collapse http/https pointing at one proxy
				return
			}
		}
		out = append(out, c)
	}

	add("http", s["httpProxy"])
	add("http", s["httpsProxy"])
	add("socks5", s["socksProxy"])
	return out
}

// kioslavercSection returns the key/value pairs of a single INI group.
// Keys and values are trimmed; keys keep their original case (kioslaverc
// is case-sensitive). Blank lines and '#' comments are ignored.
func kioslavercSection(content, want string) map[string]string {
	out := map[string]string{}
	inSection := false
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			inSection = strings.TrimSpace(line[1:len(line)-1]) == want
			continue
		}
		if !inSection {
			continue
		}
		if key, val, ok := strings.Cut(line, "="); ok {
			out[strings.TrimSpace(key)] = strings.TrimSpace(val)
		}
	}
	return out
}

// parseKDEProxyValue normalises one kioslaverc proxy value to a bare
// "host:port", stripping any scheme. KDE classically stores the value
// as "scheme://host port" (space before the port); it may also appear
// as "scheme://host:port" or without a scheme. Returns "" when empty.
//
// The scheme is dropped here and re-applied by the caller, so a socks
// entry stored as "socks://..." becomes socks5:// like the other
// detectors. Any inline userinfo survives for candidateFromRaw to
// extract.
func parseKDEProxyValue(raw string) string {
	fields := strings.Fields(raw)
	if len(fields) == 0 {
		return ""
	}
	host := stripScheme(fields[0])
	if host == "" {
		return ""
	}
	if len(fields) >= 2 {
		// classic "host<space>port" form
		return host + ":" + fields[1]
	}
	return host // already "host:port" (or a bare host)
}

// stripScheme removes a leading "scheme://" prefix if present.
func stripScheme(s string) string {
	if i := strings.Index(s, "://"); i >= 0 {
		return s[i+3:]
	}
	return s
}
