package detect

import "strings"

// parseWinINETProxyString parses the value of the WinINET ProxyServer
// registry value. Two formats are accepted:
//
//	"host:port"                                — single proxy for all schemes
//	"http=h:p;https=h:p;ftp=h:p;socks=h:p"     — per-scheme list
//
// Selection order for the per-scheme form:
//
//  1. http=  → "http://h:p"
//  2. https= → "http://h:p"  (still reachable via CONNECT)
//  3. socks= → "socks5://h:p"
//
// ftp= entries are ignored. Returns "" if no usable entry is found.
//
// Lifted from reverse_ssh's parseWinINETProxyString (BSD-3) and kept
// platform-agnostic so tests run on every CI matrix entry without a
// real registry to point at.
func parseWinINETProxyString(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}

	if !strings.Contains(raw, "=") {
		return "http://" + raw
	}

	entries := map[string]string{}
	for _, part := range strings.Split(raw, ";") {
		part = strings.TrimSpace(part)
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			continue
		}
		scheme := strings.ToLower(strings.TrimSpace(kv[0]))
		hostPort := strings.TrimSpace(kv[1])
		if hostPort == "" {
			continue
		}
		entries[scheme] = hostPort
	}

	if v, ok := entries["http"]; ok {
		return "http://" + v
	}
	if v, ok := entries["https"]; ok {
		return "http://" + v
	}
	if v, ok := entries["socks"]; ok {
		return "socks5://" + v
	}
	return ""
}
