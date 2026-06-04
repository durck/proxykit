package proxykit

import (
	"context"
	"net/url"
	"strings"
)

// pacEngine evaluates a compiled PAC (Proxy Auto-Config) script's
// FindProxyForURL for a destination. It is implemented only in binaries
// built with -tags proxykit_pac; the default build wires a stub whose
// constructor reports errors.ErrUnsupported.
type pacEngine interface {
	// findProxy runs FindProxyForURL(rawURL, host) and returns its raw
	// result string, e.g. "PROXY proxy:8080; DIRECT".
	findProxy(ctx context.Context, rawURL, host string) (string, error)

	// close releases any resources (e.g. the JS runtime watchdog).
	close()
}

// newPACEngine compiles a PAC script into a pacEngine. It is assigned at
// init time by pac_eval.go (//go:build proxykit_pac) or pac_stub.go
// (//go:build !proxykit_pac), so it is never nil after package init.
var newPACEngine func(script string) (pacEngine, error)

// pacResult is one hop from a parsed FindProxyForURL result: either a
// direct connection or a single proxy URL.
type pacResult struct {
	direct bool     // true => connect directly to the destination
	url    *url.URL // proxy URL when !direct (scheme http/https/socks5, explicit port)
}

// parsePACResult converts a FindProxyForURL return string into an ordered
// list of hops. The return value is a ';'-separated list of tokens
// (case-insensitive), each one of:
//
//	DIRECT             -> connect directly
//	PROXY host:port    -> http://host:port  (reached via CONNECT)
//	HTTP  host:port    -> http://host:port
//	HTTPS host:port    -> https://host:port
//	SOCKS host:port    -> socks5://host:port
//	SOCKS5 host:port   -> socks5://host:port
//
// Unknown tokens and malformed entries (a proxy token without a host) are
// skipped. PAC results never carry credentials. An empty or wholly
// unparseable result yields nil; callers treat that as "go direct".
func parsePACResult(result string) []pacResult {
	var out []pacResult
	for _, tok := range strings.Split(result, ";") {
		fields := strings.Fields(tok)
		if len(fields) == 0 {
			continue
		}
		kind := strings.ToUpper(fields[0])
		if kind == "DIRECT" {
			out = append(out, pacResult{direct: true})
			continue
		}
		if len(fields) < 2 {
			continue // proxy token without a host:port
		}
		var scheme string
		switch kind {
		case "PROXY", "HTTP":
			scheme = "http"
		case "HTTPS":
			scheme = "https"
		case "SOCKS", "SOCKS5":
			scheme = "socks5"
		default:
			continue // unknown directive
		}
		u, err := ParseProxyURL(scheme + "://" + fields[1])
		if err != nil {
			continue
		}
		out = append(out, pacResult{url: u})
	}
	return out
}
