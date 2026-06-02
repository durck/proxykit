package transport

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/textproto"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/durck/proxykit/auth"
)

// maxAuthRounds bounds how many CONNECT requests a single Authenticator
// may issue. NTLM uses 2-3 rounds, Negotiate 1-2; 5 leaves headroom.
const maxAuthRounds = 5

// Connect dials a destination through an HTTP CONNECT proxy.
//
// ProxyURL must have scheme http or https. For https the TLS connection
// to the proxy is established with InsecureSkipVerify=true by default —
// corporate CONNECT proxies frequently terminate TLS with self-signed
// or internally-issued certificates, and the security boundary is the
// inner protocol, not the proxy hop. Set TLSConfig to opt out.
//
// On HTTP 407 each Authenticator in Auth whose Scheme matches one of
// the proxy-advertised schemes is tried in order on a fresh proxy
// connection. The first one that wins returns the tunnel; if none
// succeeds the original *ProxyAuthError is returned.
type Connect struct {
	// ProxyURL is the proxy address. Scheme must be http or https.
	ProxyURL *url.URL

	// Timeout bounds a single dial+CONNECT-handshake attempt. Zero
	// means no timeout. ctx.Deadline() takes precedence when sooner.
	Timeout time.Duration

	// TLSConfig overrides the default {InsecureSkipVerify: true} used
	// for https proxies. Cloned per dial. Ignored for http proxies.
	TLSConfig *tls.Config

	// Auth is the ordered list of Authenticators tried on HTTP 407.
	// Each Authenticator whose Scheme matches an advertised
	// Proxy-Authenticate scheme gets a fresh proxy connection. Empty
	// means do not attempt auth — surface the 407 immediately.
	Auth []auth.Authenticator
}

// ProxyAuthError is returned from Connect.DialContext when the proxy
// answers with HTTP 407 Proxy Authentication Required and either no
// Authenticator is configured for an advertised scheme or every
// matching Authenticator finished without producing 200.
type ProxyAuthError struct {
	// Status is the raw status line from the final 407 response.
	Status string

	// Schemes are the lower-cased auth schemes advertised by the
	// proxy in Proxy-Authenticate, e.g. {"basic", "ntlm", "negotiate"}.
	Schemes []string
}

// Error reports the proxy authentication failure including advertised
// schemes.
func (e *ProxyAuthError) Error() string {
	if len(e.Schemes) == 0 {
		return "proxykit: proxy requires authentication: " + e.Status
	}
	return fmt.Sprintf("proxykit: proxy requires authentication (%s): %s",
		strings.Join(e.Schemes, ", "), e.Status)
}

// DialContext opens a CONNECT tunnel through c.ProxyURL to address.
// On HTTP 200 the returned net.Conn is the raw tunnel. On HTTP 407 the
// authenticator chain is consulted; if none succeeds the error is a
// *ProxyAuthError. Any other status returns an opaque error wrapping
// the status line.
func (c *Connect) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, fmt.Errorf("proxykit: CONNECT requires tcp network, got %q", network)
	}
	if c.ProxyURL == nil {
		return nil, errors.New("proxykit: Connect.ProxyURL is nil")
	}

	// Initial attempt without credentials. This both succeeds for
	// open proxies and discovers the schemes the proxy will accept.
	conn, err := c.attempt(ctx, address, nil)
	var perr *ProxyAuthError
	if !errors.As(err, &perr) || len(c.Auth) == 0 {
		return conn, err
	}

	// 407 — iterate Authenticators whose Scheme matches an advertised
	// scheme.
	for _, a := range c.Auth {
		if !schemeMatches(a.Scheme(), perr.Schemes) {
			continue
		}
		authConn, authErr := c.attempt(ctx, address, a)
		if authErr == nil {
			return authConn, nil
		}
		var authPErr *ProxyAuthError
		if !errors.As(authErr, &authPErr) {
			// Non-auth failure (write/read/timeout): surface it.
			return nil, authErr
		}
		// 407 again — this Authenticator failed, keep trying.
		perr = authPErr
	}

	return nil, perr
}

// attempt opens a fresh proxy connection and runs one CONNECT
// handshake. If a is nil, a single round without Proxy-Authorization
// is performed. Otherwise the Authenticator dance loops until done or
// the proxy answers 200/non-407.
func (c *Connect) attempt(ctx context.Context, address string, a auth.Authenticator) (net.Conn, error) {
	proxyConn, err := c.dialProxy(ctx)
	if err != nil {
		return nil, err
	}

	// Bound the handshake reads/writes. Prefer the context deadline;
	// otherwise fall back to c.Timeout so a proxy that accepts the TCP
	// connection but never answers cannot hang the dial forever. Cleared
	// on success before the tunnel is handed back.
	if d, ok := ctx.Deadline(); ok {
		_ = proxyConn.SetDeadline(d)
	} else if c.Timeout > 0 {
		_ = proxyConn.SetDeadline(time.Now().Add(c.Timeout))
	}

	br := bufio.NewReader(proxyConn)
	var challenge []byte

	for round := 0; round < maxAuthRounds; round++ {
		var extraHeaders []string
		done := true

		if a != nil {
			var hdrErr error
			extraHeaders, done, hdrErr = a.Headers(challenge)
			if hdrErr != nil {
				proxyConn.Close()
				return nil, fmt.Errorf("proxykit: auth %s: %w", a.Scheme(), hdrErr)
			}
		}

		if err := writeConnectRequest(proxyConn, address, extraHeaders); err != nil {
			proxyConn.Close()
			return nil, fmt.Errorf("proxykit: write CONNECT: %w", err)
		}

		status, headers, err := readResponseHead(br)
		if err != nil {
			proxyConn.Close()
			return nil, fmt.Errorf("proxykit: read CONNECT response: %w", err)
		}

		switch parseStatusCode(status) {
		case http.StatusOK:
			_ = proxyConn.SetDeadline(time.Time{})
			return &bufferedConn{Conn: proxyConn, r: br}, nil
		case http.StatusProxyAuthRequired:
			if done {
				proxyConn.Close()
				return nil, &ProxyAuthError{
					Status:  status,
					Schemes: parseAuthSchemes(headers.Values("Proxy-Authenticate")),
				}
			}
			challenge = extractChallenge(headers, a.Scheme())
		default:
			proxyConn.Close()
			return nil, fmt.Errorf("proxykit: proxy CONNECT failed: %s", status)
		}
	}

	proxyConn.Close()
	scheme := ""
	if a != nil {
		scheme = a.Scheme()
	}
	return nil, fmt.Errorf("proxykit: auth %q exceeded %d rounds", scheme, maxAuthRounds)
}

func (c *Connect) dialProxy(ctx context.Context) (net.Conn, error) {
	nd := net.Dialer{Timeout: c.Timeout}
	switch strings.ToLower(c.ProxyURL.Scheme) {
	case "http":
		return nd.DialContext(ctx, "tcp", c.ProxyURL.Host)
	case "https":
		cfg := defaultProxyTLSConfig()
		if c.TLSConfig != nil {
			cfg = c.TLSConfig.Clone()
		}
		if cfg.ServerName == "" && !cfg.InsecureSkipVerify {
			cfg.ServerName = c.ProxyURL.Hostname()
		}
		td := tls.Dialer{NetDialer: &nd, Config: cfg}
		return td.DialContext(ctx, "tcp", c.ProxyURL.Host)
	default:
		return nil, fmt.Errorf("proxykit: CONNECT requires http or https proxy scheme, got %q", c.ProxyURL.Scheme)
	}
}

func defaultProxyTLSConfig() *tls.Config {
	// InsecureSkipVerify is intentional — see Connect doc.
	return &tls.Config{InsecureSkipVerify: true} //nolint:gosec
}

// writeConnectRequest sends a CONNECT request with the supplied extra
// headers (each entry is a complete "Name: value" line).
func writeConnectRequest(w io.Writer, address string, extraHeaders []string) error {
	var b strings.Builder
	b.WriteString("CONNECT ")
	b.WriteString(address)
	b.WriteString(" HTTP/1.1\r\nHost: ")
	b.WriteString(address)
	b.WriteString("\r\n")
	for _, h := range extraHeaders {
		b.WriteString(h)
		b.WriteString("\r\n")
	}
	b.WriteString("\r\n")
	_, err := io.WriteString(w, b.String())
	return err
}

// readResponseHead reads the status line and headers of an HTTP/1.x
// response. The reader is left positioned at the start of the body,
// if any.
func readResponseHead(br *bufio.Reader) (status string, headers http.Header, err error) {
	tr := textproto.NewReader(br)
	statusLine, err := tr.ReadLine()
	if err != nil {
		return "", nil, err
	}
	mh, err := tr.ReadMIMEHeader()
	if err != nil {
		return statusLine, nil, err
	}
	return statusLine, http.Header(mh), nil
}

// parseStatusCode extracts the numeric status from "HTTP/1.x CODE TEXT".
// Returns 0 on a malformed status line.
func parseStatusCode(statusLine string) int {
	fs := strings.Fields(statusLine)
	if len(fs) < 2 {
		return 0
	}
	code, err := strconv.Atoi(fs[1])
	if err != nil {
		return 0
	}
	return code
}

// parseAuthSchemes extracts auth scheme tokens from Proxy-Authenticate
// header values. Multiple schemes may appear comma-separated within a
// single value (RFC 7235); each scheme is the first whitespace token of
// its chunk. Output is lower-cased and deduplicated.
func parseAuthSchemes(values []string) []string {
	seen := map[string]struct{}{}
	out := []string{}
	for _, v := range values {
		for _, chunk := range strings.Split(v, ",") {
			chunk = strings.TrimSpace(chunk)
			if chunk == "" {
				continue
			}
			scheme := strings.ToLower(strings.Fields(chunk)[0])
			if _, ok := seen[scheme]; ok {
				continue
			}
			seen[scheme] = struct{}{}
			out = append(out, scheme)
		}
	}
	return out
}

// extractChallenge returns the raw challenge payload for the given
// scheme from Proxy-Authenticate header values. Binary payloads
// (NTLM/Negotiate) are base64-decoded; non-base64 payloads are
// returned as-is. Returns nil if the scheme is not present.
func extractChallenge(headers http.Header, scheme string) []byte {
	for _, v := range headers.Values("Proxy-Authenticate") {
		for _, chunk := range strings.Split(v, ",") {
			chunk = strings.TrimSpace(chunk)
			if chunk == "" {
				continue
			}
			fs := strings.SplitN(chunk, " ", 2)
			if !strings.EqualFold(fs[0], scheme) {
				continue
			}
			if len(fs) < 2 {
				return []byte{}
			}
			payload := strings.TrimSpace(fs[1])
			if data, err := base64.StdEncoding.DecodeString(payload); err == nil {
				return data
			}
			return []byte(payload)
		}
	}
	return nil
}

// schemeMatches reports whether want appears in advertised. An empty
// want never matches: sentinel Authenticators must opt out by scheme.
func schemeMatches(want string, advertised []string) bool {
	if want == "" {
		return false
	}
	for _, a := range advertised {
		if a == want {
			return true
		}
	}
	return false
}

// bufferedConn drains buffered bytes from r before falling through to
// the underlying conn.
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

// Read consumes any bytes bufio buffered past the CONNECT response head
// before reading from the underlying conn.
func (b *bufferedConn) Read(p []byte) (int, error) {
	return b.r.Read(p)
}
