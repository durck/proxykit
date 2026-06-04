package detect

import (
	"net"
	"strings"
)

// parseSCUtilProxy turns the output of `scutil --proxy` into proxy
// candidates. The command prints an Apple property-list-style nested
// dictionary:
//
//	<dictionary> {
//	  ExceptionsList : <array> {
//	    0 : *.local
//	  }
//	  HTTPEnable : 1
//	  HTTPProxy : proxy.example.com
//	  HTTPPort : 8080
//	  HTTPSEnable : 1
//	  HTTPSProxy : proxy.example.com
//	  HTTPSPort : 8443
//	  SOCKSEnable : 1
//	  SOCKSProxy : socks.example.com
//	  SOCKSPort : 1080
//	}
//
// A per-protocol entry is emitted only when its <P>Enable flag is "1" and
// a host is present. http and https map to an http:// URL (reached via
// CONNECT), socks to socks5://, de-duplicated by URL — matching
// gnomeCandidates and parseWinINETProxyString. When ProxyAutoConfigEnable
// is "1" the ProxyAutoConfigURLString is surfaced as a PACURL candidate
// (used only in -tags proxykit_pac builds). macOS keeps proxy credentials
// in the Keychain rather than the proxy configuration, so candidates
// never carry User/Pass.
//
// Kept platform-agnostic so it is tested on every CI matrix entry without
// a real macOS host.
func parseSCUtilProxy(raw string) []Candidate {
	kv := parseSCUtilDict(raw)

	var out []Candidate
	add := func(scheme, enableKey, hostKey, portKey string) {
		if kv[enableKey] != "1" {
			return
		}
		host := strings.TrimSpace(kv[hostKey])
		port := strings.TrimSpace(kv[portKey])
		if host == "" || port == "" || port == "0" {
			return
		}
		url := scheme + "://" + net.JoinHostPort(host, port)
		for _, e := range out {
			if e.URL == url {
				return
			}
		}
		out = append(out, Candidate{URL: url, From: "macos"})
	}

	add("http", "HTTPEnable", "HTTPProxy", "HTTPPort")
	add("http", "HTTPSEnable", "HTTPSProxy", "HTTPSPort")
	add("socks5", "SOCKSEnable", "SOCKSProxy", "SOCKSPort")

	if kv["ProxyAutoConfigEnable"] == "1" {
		if pac := strings.TrimSpace(kv["ProxyAutoConfigURLString"]); pac != "" {
			out = append(out, Candidate{PACURL: pac, From: "macos"})
		}
	}

	return out
}

// parseSCUtilDict extracts the top-level scalar "Key : value" pairs from
// scutil's dictionary output. Nested blocks (e.g. ExceptionsList :
// <array> { ... }) are skipped: brace depth is tracked so only entries at
// the outer dictionary's level (depth 1) are read.
func parseSCUtilDict(raw string) map[string]string {
	kv := map[string]string{}
	depth := 0
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		open := strings.Contains(line, "{")
		closed := strings.Contains(line, "}")

		// Capture only scalar pairs at the outer dictionary's level; a line
		// that opens or closes a block is structural, not a scalar.
		if depth == 1 && !open && !closed {
			if k, v, ok := splitSCUtilKV(line); ok {
				kv[k] = v
			}
		}
		// open and closed are adjusted independently, so a single-line
		// block ("X : <array> {}") nets to no depth change. Malformed input
		// that underflows past zero simply never matches depth == 1 again,
		// yielding an empty result rather than panicking.
		if open {
			depth++
		}
		if closed {
			depth--
		}
	}
	return kv
}

// splitSCUtilKV splits a "Key : value" line on the first " : " separator.
// The spaced separator avoids mis-splitting IPv6 hosts (e.g. "::1") and
// values that contain a bare colon. Returns ok=false when no separator or
// an empty key is found.
func splitSCUtilKV(line string) (key, value string, ok bool) {
	i := strings.Index(line, " : ")
	if i < 0 {
		return "", "", false
	}
	key = strings.TrimSpace(line[:i])
	value = strings.TrimSpace(line[i+len(" : "):])
	if key == "" {
		return "", "", false
	}
	return key, value, true
}
