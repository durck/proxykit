package pac

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

// FetchTimeout bounds fetching a PAC script. The host also reuses it as
// the overall budget for loading a PAC source (fetch + WPAD discovery).
const FetchTimeout = 10 * time.Second

// maxPACSize caps a fetched PAC body at 1 MiB.
const maxPACSize = 1 << 20

// FetchScript downloads a PAC script directly — never through a proxy, to
// avoid recursing into proxy selection. Bounded by time and size; returns
// "" on any failure (logged via log).
func FetchScript(ctx context.Context, pacURL string, log func(level, msg string)) string {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, pacURL, nil)
	if err != nil {
		logf(log, "warn", "proxykit: bad PAC URL %q: %v", pacURL, err)
		return ""
	}
	client := &http.Client{
		Timeout: FetchTimeout,
		Transport: &http.Transport{
			Proxy:               nil, // never use a proxy to fetch the PAC
			DialContext:         (&net.Dialer{Timeout: FetchTimeout}).DialContext,
			TLSHandshakeTimeout: FetchTimeout,
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		logf(log, "warn", "proxykit: fetch PAC %q: %v", pacURL, err)
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		logf(log, "warn", "proxykit: fetch PAC %q: status %s", pacURL, resp.Status)
		return ""
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxPACSize))
	if err != nil {
		logf(log, "warn", "proxykit: read PAC %q: %v", pacURL, err)
		return ""
	}
	return string(body)
}

// logf forwards a formatted diagnostic to the host's optional log hook.
func logf(hook func(level, msg string), level, format string, args ...any) {
	if hook == nil {
		return
	}
	hook(level, fmt.Sprintf(format, args...))
}
