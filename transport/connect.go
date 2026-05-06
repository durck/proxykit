package transport

import (
	"bufio"
	"context"
	"crypto/tls"
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
)

// Connect dials a destination through an HTTP CONNECT proxy.
//
// ProxyURL must have scheme http or https. For https the TLS connection
// to the proxy is established with InsecureSkipVerify=true by default —
// corporate CONNECT proxies frequently terminate TLS with self-signed
// or internally-issued certificates, and the security boundary is the
// inner protocol, not the proxy hop. Set TLSConfig to opt out.
type Connect struct {
	// ProxyURL is the proxy address. Scheme must be http or https.
	ProxyURL *url.URL

	// Timeout bounds a single dial+CONNECT-handshake attempt. Zero
	// means no timeout. ctx.Deadline() takes precedence when sooner.
	Timeout time.Duration

	// TLSConfig overrides the default {InsecureSkipVerify: true} used
	// for https proxies. Cloned per dial. Ignored for http proxies.
	TLSConfig *tls.Config
}

// ProxyAuthError is returned from Connect.DialContext when the proxy
// answers with HTTP 407 Proxy Authentication Required. Schemes lists
// the auth schemes from Proxy-Authenticate headers (lower-cased,
// deduplicated, in the order the proxy advertised them).
type ProxyAuthError struct {
	// Status is the raw status line, e.g.
	// "HTTP/1.1 407 Proxy Authentication Required".
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
// On HTTP 200 the returned net.Conn is the raw tunnel ready for the
// inner protocol. On HTTP 407 the error is a *ProxyAuthError so the
// caller can retry with credentials. Any other status returns an
// opaque error wrapping the status line.
func (c *Connect) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, fmt.Errorf("proxykit: CONNECT requires tcp network, got %q", network)
	}
	if c.ProxyURL == nil {
		return nil, errors.New("proxykit: Connect.ProxyURL is nil")
	}

	proxyConn, err := c.dialProxy(ctx)
	if err != nil {
		return nil, err
	}

	// Honour ctx deadline during the CONNECT handshake.
	if d, ok := ctx.Deadline(); ok {
		_ = proxyConn.SetDeadline(d)
	}

	if err := writeConnectRequest(proxyConn, address); err != nil {
		proxyConn.Close()
		return nil, fmt.Errorf("proxykit: write CONNECT: %w", err)
	}

	br := bufio.NewReader(proxyConn)
	status, headers, err := readResponseHead(br)
	if err != nil {
		proxyConn.Close()
		return nil, fmt.Errorf("proxykit: read CONNECT response: %w", err)
	}

	switch parseStatusCode(status) {
	case http.StatusOK:
		// Reset deadline before handing the conn to the caller.
		// Wrap so the caller's first reads consume any bytes bufio
		// pre-read past the response head.
		_ = proxyConn.SetDeadline(time.Time{})
		return &bufferedConn{Conn: proxyConn, r: br}, nil
	case http.StatusProxyAuthRequired:
		proxyConn.Close()
		return nil, &ProxyAuthError{
			Status:  status,
			Schemes: parseAuthSchemes(headers.Values("Proxy-Authenticate")),
		}
	default:
		proxyConn.Close()
		return nil, fmt.Errorf("proxykit: proxy CONNECT failed: %s", status)
	}
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

// writeConnectRequest sends a minimal CONNECT request to w. The auth
// layer issues a fresh CONNECT with Proxy-Authorization on retry, so
// no extra headers are emitted here.
func writeConnectRequest(w io.Writer, address string) error {
	var b strings.Builder
	b.WriteString("CONNECT ")
	b.WriteString(address)
	b.WriteString(" HTTP/1.1\r\nHost: ")
	b.WriteString(address)
	b.WriteString("\r\n\r\n")
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
