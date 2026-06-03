//go:build !windows && !proxykit_nokerberos

package auth

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/credentials"
	"github.com/jcmturner/gokrb5/v8/spnego"
)

// Negotiate returns an HTTP Negotiate (SPNEGO/Kerberos) Authenticator
// backed by github.com/jcmturner/gokrb5. spn is the proxy's service
// principal name, e.g. "HTTP/proxy.corp.local".
//
// It mints a single SPNEGO token from the ambient Kerberos identity —
// the credential cache named by KRB5CCNAME (or /tmp/krb5cc_<uid> when
// unset) — using the configuration in $KRB5_CONFIG or /etc/krb5.conf.
// FILE and DIR caches are supported; a KEYRING: prefix is recognised but
// its reader is not yet implemented (see [resolveCCache]).
//
// Like the Windows SSPI backend it is single-round: it emits the SPNEGO
// blob in the first Proxy-Authorization and the proxy either accepts
// (200) or rejects (407 → permanent failure for this Authenticator).
// Obtaining the service ticket may contact the KDC (a TGS-REQ) when the
// ticket is not already cached, exactly as SSPI does on Windows.
//
// Build with -tags proxykit_nokerberos to drop the gokrb5 dependency;
// Negotiate then returns errors.ErrUnsupported on non-Windows.
func Negotiate(spn string) Authenticator {
	return negotiateAuth{spn: spn}
}

type negotiateAuth struct {
	spn string
}

func (negotiateAuth) Scheme() string { return "negotiate" }

// Headers mints a single SPNEGO token for the configured SPN. The
// challenge is ignored: SPNEGO for proxy CONNECT is one-shot
// (done=true), and the optional mutual-authentication token the proxy
// may return alongside its 200 is not required to open the tunnel. Every
// failure path returns done=true with a "negotiate: …"-prefixed error,
// mirroring the Windows SSPI backend.
func (n negotiateAuth) Headers(_ []byte) ([]string, bool, error) {
	if n.spn == "" {
		return nil, true, errors.New("negotiate: empty SPN")
	}

	cfg, err := loadKrb5Config()
	if err != nil {
		return nil, true, fmt.Errorf("negotiate: load krb5.conf: %w", err)
	}

	cc, err := resolveCCache()
	if err != nil {
		return nil, true, fmt.Errorf("negotiate: load credential cache: %w", err)
	}

	cl, err := client.NewFromCCache(cc, cfg, client.DisablePAFXFAST(true))
	if err != nil {
		return nil, true, fmt.Errorf("negotiate: client from ccache: %w", err)
	}
	defer cl.Destroy()

	s := spnego.SPNEGOClient(cl, n.spn)
	if err := s.AcquireCred(); err != nil {
		return nil, true, fmt.Errorf("negotiate: acquire credential: %w", err)
	}
	token, err := s.InitSecContext()
	if err != nil {
		return nil, true, fmt.Errorf("negotiate: init security context: %w", err)
	}
	tokenBytes, err := token.Marshal()
	if err != nil {
		return nil, true, fmt.Errorf("negotiate: marshal token: %w", err)
	}

	return []string{"Proxy-Authorization: Negotiate " + base64.StdEncoding.EncodeToString(tokenBytes)}, true, nil
}

// loadKrb5Config loads the Kerberos configuration from $KRB5_CONFIG, or
// /etc/krb5.conf when the variable is unset.
func loadKrb5Config() (*config.Config, error) {
	path := os.Getenv("KRB5_CONFIG")
	if path == "" {
		path = "/etc/krb5.conf"
	}
	return config.Load(path)
}

// resolveCCache loads the credential cache named by KRB5CCNAME. The
// value may carry a type prefix:
//
//	FILE:/path           a single ccache file (a bare /path is also FILE)
//	DIR:/path            a collection; the primary subsidiary is used
//	DIR::/path/tktXXXX    a specific subsidiary (the DIR:: form)
//	KEYRING:name         the Linux kernel keyring (not yet implemented)
//
// When KRB5CCNAME is unset it defaults to FILE:/tmp/krb5cc_<uid>.
func resolveCCache() (*credentials.CCache, error) {
	raw := os.Getenv("KRB5CCNAME")
	if raw == "" {
		raw = "FILE:/tmp/krb5cc_" + strconv.Itoa(os.Getuid())
	}

	typ, residual := splitCCacheName(raw)
	switch typ {
	case "FILE":
		return credentials.LoadCCache(residual)
	case "DIR":
		return loadDirCCache(residual)
	case "KEYRING":
		return loadCCacheFromKeyring(residual)
	default:
		return nil, fmt.Errorf("unsupported ccache type %q (KRB5CCNAME=%q)", typ, raw)
	}
}

// splitCCacheName splits a KRB5CCNAME value into its upper-cased type and
// residual. A value whose prefix is not a recognised cache type is
// treated as a bare FILE path — this covers absolute paths such as
// /tmp/krb5cc_1000 that contain no "TYPE:" prefix.
func splitCCacheName(raw string) (typ, residual string) {
	i := strings.IndexByte(raw, ':')
	if i < 0 {
		return "FILE", raw
	}
	switch prefix := strings.ToUpper(raw[:i]); prefix {
	case "FILE", "DIR", "KEYRING", "API", "KCM", "MEMORY":
		return prefix, raw[i+1:]
	default:
		// A bare path that merely happens to contain a colon.
		return "FILE", raw
	}
}

// loadDirCCache resolves a DIR collection residual to a ccache file and
// loads it. residual is either "/path" (use the primary subsidiary named
// in /path/primary) or ":/path/tktXXXX" (a specific subsidiary, the
// DIR:: form).
func loadDirCCache(residual string) (*credentials.CCache, error) {
	if strings.HasPrefix(residual, ":") {
		return credentials.LoadCCache(strings.TrimPrefix(residual, ":"))
	}
	primary, err := os.ReadFile(filepath.Join(residual, "primary"))
	if err != nil {
		return nil, fmt.Errorf("read DIR primary: %w", err)
	}
	name := strings.TrimSpace(string(primary))
	if name == "" {
		return nil, errors.New("DIR primary file is empty")
	}
	return credentials.LoadCCache(filepath.Join(residual, name))
}
