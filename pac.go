package proxykit

import (
	"context"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/durck/proxykit/internal/pac"
	"github.com/durck/proxykit/transport"
)

const (
	pacCacheTTL = 30 * time.Second
	pacCacheMax = 1024
)

// hasPACSource reports whether any PAC source is configured: an inline
// script, an explicit URL, a detected OS PAC URL, or active WPAD.
func hasPACSource(cfg Config, detectedPACURLs []string) bool {
	return cfg.PAC != "" || cfg.PACURL != "" || len(detectedPACURLs) > 0 || cfg.WPAD
}

// pacDialer routes each dial through the proxy(ies) a PAC script selects
// for the destination host. The script is fetched and compiled lazily on
// first use, so NewDialer never blocks on the network; per-host results
// are memoized for pacCacheTTL to keep evaluation off the hot path. When
// the engine cannot be built, or a result yields nothing usable, it falls
// back to the static/Direct dialer. The PAC protocol itself (engine,
// fetch, WPAD discovery) lives in internal/pac; this type only assembles
// transport dialers from the PAC's per-host decision.
type pacDialer struct {
	cfg         Config
	inline      string
	pacURL      string
	detectedPAC []string
	wpad        bool
	fallback    Dialer

	once   sync.Once
	engine pac.Engine // nil after once means "always use fallback"

	mu    sync.Mutex
	cache map[string]pacCacheEntry
}

type pacCacheEntry struct {
	dialer  Dialer
	expires time.Time
}

func newPACDialer(cfg Config, detectedPACURLs []string, fallback Dialer) *pacDialer {
	return &pacDialer{
		cfg:         cfg,
		inline:      cfg.PAC,
		pacURL:      cfg.PACURL,
		detectedPAC: detectedPACURLs,
		wpad:        cfg.WPAD,
		fallback:    fallback,
		cache:       map[string]pacCacheEntry{},
	}
}

// DialContext routes address through the PAC-selected proxy chain.
func (p *pacDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	p.once.Do(func() {
		// Fetch+compile once on an INDEPENDENT context, so a single
		// short-lived or cancelled first dial cannot permanently poison the
		// engine for every later dial.
		bctx, cancel := context.WithTimeout(context.Background(), pac.FetchTimeout)
		defer cancel()
		p.engine = p.buildEngine(bctx)
	})
	if p.engine == nil {
		return p.fallback.DialContext(ctx, network, address)
	}

	host, port, err := net.SplitHostPort(address)
	if err != nil {
		host = address
	}
	// The Dialer interface carries no application scheme, so infer the PAC
	// url from the port (80 → http, otherwise https). This only matters for
	// PAC scripts that branch on the url's scheme.
	scheme := "https"
	if port == "80" {
		scheme = "http"
	}
	return p.dialerForHost(ctx, scheme, host).DialContext(ctx, network, address)
}

func (p *pacDialer) dialerForHost(ctx context.Context, scheme, host string) Dialer {
	key := scheme + "|" + host
	now := time.Now()
	p.mu.Lock()
	if e, ok := p.cache[key]; ok && now.Before(e.expires) {
		p.mu.Unlock()
		return e.dialer
	}
	p.mu.Unlock()

	// Evaluate outside the lock (PAC eval may do DNS). Two goroutines hitting
	// the same cold key may both evaluate; the duplicate is benign as the
	// results are equivalent.
	d := pacChain(ctx, p.engine, scheme, host, p.cfg, p.fallback)

	p.mu.Lock()
	if len(p.cache) >= pacCacheMax {
		p.cache = map[string]pacCacheEntry{} // bound memory; cheap reset under a cold burst
	}
	p.cache[key] = pacCacheEntry{dialer: d, expires: now.Add(pacCacheTTL)}
	p.mu.Unlock()
	return d
}

// pacChain evaluates the PAC for scheme://host and turns its result into a
// dialer. On eval error or an empty/unusable result it returns fallback.
func pacChain(ctx context.Context, eng pac.Engine, scheme, host string, cfg Config, fallback Dialer) Dialer {
	res, err := eng.FindProxy(ctx, scheme+"://"+host, host)
	if err != nil {
		logf(cfg.OnLog, "warn", "proxykit: PAC eval for %q failed: %v", host, err)
		return fallback
	}
	hops := parsePACResult(res)
	dialers := make([]Dialer, 0, len(hops))
	for _, h := range hops {
		if h.direct {
			dialers = append(dialers, &transport.Direct{Timeout: cfg.Timeout})
			continue
		}
		if d := dialerForEntry(proxyEntry{url: h.url}, cfg); d != nil {
			dialers = append(dialers, d)
		}
	}
	switch len(dialers) {
	case 0:
		return fallback
	case 1:
		return dialers[0]
	default:
		return &fallbackDialer{dialers: dialers, log: cfg.OnLog}
	}
}

// buildEngine resolves the PAC script source and compiles it. Returns nil
// (→ fallback) when no script loads or compilation fails.
func (p *pacDialer) buildEngine(ctx context.Context) pac.Engine {
	script, src := p.pacScript(ctx)
	if script == "" {
		logf(p.cfg.OnLog, "warn", "proxykit: no PAC script could be loaded; routing statically")
		return nil
	}
	eng, err := pac.NewEngine(script)
	if err != nil {
		logf(p.cfg.OnLog, "warn", "proxykit: PAC compile failed (%s): %v", src, err)
		return nil
	}
	logf(p.cfg.OnLog, "info", "proxykit: PAC active (%s)", src)
	return eng
}

// pacScript loads the PAC script body from the highest-precedence source:
// inline, then the explicit URL, then any detected OS PAC URL, then WPAD
// discovery (wpadScript).
func (p *pacDialer) pacScript(ctx context.Context) (script, source string) {
	if p.inline != "" {
		return p.inline, "inline"
	}
	if p.pacURL != "" {
		if s := pac.FetchScript(ctx, p.pacURL, p.cfg.OnLog); s != "" {
			return s, "url " + p.pacURL
		}
	}
	for _, u := range p.detectedPAC {
		if s := pac.FetchScript(ctx, u, p.cfg.OnLog); s != "" {
			return s, "detected " + u
		}
	}
	return p.wpadScript(ctx)
}

// wpadScript performs active DNS-WPAD discovery when Config.WPAD is set: it
// probes http://wpad.<domain>/wpad.dat for each candidate domain (derived
// in internal/pac from the host's FQDN and, on unix, the resolv.conf search
// list) and returns the first script that loads. Disabled (returns "")
// otherwise.
//
// SECURITY: a rogue "wpad" host on the local network can serve an
// attacker-controlled PAC, so this runs only behind the explicit
// Config.WPAD opt-in, never via AutoDetect.
func (p *pacDialer) wpadScript(ctx context.Context) (script, source string) {
	if !p.wpad {
		return "", ""
	}
	for _, u := range pac.CandidateWPADURLs() {
		if s := pac.FetchScript(ctx, u, p.cfg.OnLog); s != "" {
			return s, "wpad " + u
		}
	}
	return "", ""
}

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
