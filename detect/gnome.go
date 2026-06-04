package detect

import (
	"net"
	"strings"
)

// gnomeProxy holds the raw values read from the org.gnome.system.proxy
// GSettings schema (already unquoted). It is the input to the pure
// gnomeCandidates builder, keeping the exec/GSettings I/O out of the
// testable path.
type gnomeProxy struct {
	Mode string // "none" | "manual" | "auto"

	// AutoconfigURL is the PAC URL read from autoconfig-url when
	// Mode == "auto"; empty otherwise.
	AutoconfigURL string

	HTTPHost, HTTPPort   string
	HTTPSHost, HTTPSPort string
	SOCKSHost, SOCKSPort string

	// Authentication is stored only under the .http sub-schema.
	UseAuth  bool
	AuthUser string
	AuthPass string
}

// gnomeCandidates turns a resolved GNOME proxy configuration into
// candidates. "manual" mode yields proxy candidates; "auto" mode yields a
// single PACURL candidate from AutoconfigURL (used only in -tags
// proxykit_pac builds); "none" (or anything else) yields nothing.
//
// http and https proxies map to an http:// URL (reached via CONNECT),
// socks to socks5://, matching parseWinINETProxyString. Stored
// credentials, when use-authentication is on, are attached to the
// http candidate — GNOME keeps them only under .http.
func gnomeCandidates(v gnomeProxy) []Candidate {
	if v.Mode == "auto" {
		if u := strings.TrimSpace(v.AutoconfigURL); u != "" {
			return []Candidate{{PACURL: u, From: "linux/gnome"}}
		}
		return nil
	}
	if v.Mode != "manual" {
		return nil
	}

	var out []Candidate
	add := func(c Candidate, ok bool) {
		if !ok {
			return
		}
		// Collapse http/https that point at one proxy. Dedup is by URL
		// only, deliberately not by User: the http candidate is added
		// first and may carry credentials, so an identical-endpoint https
		// (which has no credentials of its own) must fold into it and keep
		// the authed one. Adding a User check here would re-emit the same
		// endpoint twice (authed + unauthed).
		for _, e := range out {
			if e.URL == c.URL {
				return
			}
		}
		out = append(out, c)
	}

	httpC, httpOK := gnomeProxyCandidate("http", v.HTTPHost, v.HTTPPort)
	if httpOK && v.UseAuth && v.AuthUser != "" {
		httpC.User = v.AuthUser
		httpC.Pass = v.AuthPass
	}
	add(httpC, httpOK)
	add(gnomeProxyCandidate("http", v.HTTPSHost, v.HTTPSPort))
	add(gnomeProxyCandidate("socks5", v.SOCKSHost, v.SOCKSPort))
	return out
}

// gnomeProxyCandidate builds a single candidate for one protocol.
// A missing host or an unset port (empty or "0") yields ok=false.
func gnomeProxyCandidate(scheme, host, port string) (Candidate, bool) {
	host = strings.TrimSpace(host)
	port = strings.TrimSpace(port)
	if host == "" || port == "" || port == "0" {
		return Candidate{}, false
	}
	return Candidate{
		URL:  scheme + "://" + net.JoinHostPort(host, port),
		From: "linux/gnome",
	}, true
}

// unquoteGSettings normalises one line of `gsettings get` output into a
// bare value. GSettings prints GVariant text: strings are single-quoted
// (double-quoted when they contain a single quote), and some scalar
// types carry a leading type tag (e.g. "uint32 8080"). Examples:
//
//	"'manual'\n" -> "manual"
//	"uint32 8080" -> "8080"
//	"''"          -> ""
//	"true"        -> "true"
func unquoteGSettings(raw string) string {
	s := strings.TrimSpace(raw)

	for _, tag := range []string{"uint32 ", "int32 ", "uint64 ", "int64 ", "byte ", "double ", "boolean ", "handle "} {
		if strings.HasPrefix(s, tag) {
			s = strings.TrimSpace(s[len(tag):])
			break
		}
	}

	if len(s) >= 2 {
		if q := s[0]; (q == '\'' || q == '"') && s[len(s)-1] == q {
			s = s[1 : len(s)-1]
			s = strings.ReplaceAll(s, `\\`, `\`)
			s = strings.ReplaceAll(s, `\`+string(q), string(q))
		}
	}
	return s
}
