package detect

import "strings"

// parseEtcEnvironment extracts proxy candidates from the contents of
// an /etc/environment file. The file is a sequence of KEY=value lines
// (no shell export, comments introduced by '#'); values may be wrapped
// in single or double quotes.
//
// Only http_proxy / https_proxy are honoured, matched case-insensitively
// like EnvDetector. no_proxy is ignored — Candidate carries no
// no-proxy list, mirroring how EnvDetector drops NO_PROXY. When a key
// appears more than once the last occurrence wins.
//
// Kept platform-agnostic so the parser is testable on every CI matrix
// entry without a real /etc/environment to read.
func parseEtcEnvironment(content string) []Candidate {
	var httpRaw, httpsRaw string
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		// Trim outside the quotes, then again after unquoting (spaces
		// inside the quotes), so a value like "  http://p:8080  " yields
		// a clean URL rather than one padded with spaces.
		val = strings.TrimSpace(unquoteEnvValue(strings.TrimSpace(val)))
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "http_proxy":
			httpRaw = val
		case "https_proxy":
			httpsRaw = val
		}
	}

	var out []Candidate
	if c, ok := candidateFromRaw(httpRaw, "linux/etc-environment"); ok {
		out = append(out, c)
	}
	if c, ok := candidateFromRaw(httpsRaw, "linux/etc-environment"); ok {
		// Same coalescing shape as env.go: drop the https entry when it is
		// the same endpoint as the http one. Pass is intentionally not
		// compared, matching EnvDetector.
		if len(out) == 0 || out[0].URL != c.URL || out[0].User != c.User {
			out = append(out, c)
		}
	}
	return out
}

// unquoteEnvValue strips one layer of matching surrounding single or
// double quotes, as found in /etc/environment values.
func unquoteEnvValue(s string) string {
	if len(s) >= 2 {
		if c := s[0]; (c == '"' || c == '\'') && s[len(s)-1] == c {
			return s[1 : len(s)-1]
		}
	}
	return s
}
