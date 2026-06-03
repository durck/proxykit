# proxykit

Small, dependency-light Go library for outbound connections through HTTP/HTTPS CONNECT and SOCKS5 proxies, with optional system-proxy auto-detection and pluggable authentication.

> **Status:** `v0.1` complete. The public API is unstable until `v1.0` — expect occasional renames during the `v0.x` line.

## Features

| Area              | Support                                                           |
|-------------------|-------------------------------------------------------------------|
| Transports        | HTTP CONNECT (TCP+TLS), SOCKS5, Direct                            |
| Authentication    | None, Basic, NTLM, Negotiate / Kerberos (Windows SSPI, Linux/macOS via gokrb5) |
| Auto-detection    | `*_PROXY` env vars (any platform), Windows WinINET (HKCU), Linux `/etc/environment` + GNOME + KDE |
| API               | `Dialer` (`net.Dial`-compatible), `http.RoundTripper` adapter     |
| Platforms         | Windows, Linux, macOS — no cgo, fully static                      |

### Out of scope (v0.1)

PAC / WPAD, SOCKS4 / SOCKS4a, Digest auth, server-side SOCKS, TLS interception / MITM, connection pooling, retry / circuit breaker, macOS / BSD detection.

### Roadmap

- **v0.2** — Linux detection done (`/etc/environment`, GNOME GSettings, KDE kioslaverc); Linux/macOS Kerberos via `jcmturner/gokrb5` — FILE/DIR caches, Linux `KEYRING:` caches, and a Dockerised KDC integration test are in place.
- **v0.3+** — community-driven (SOCKS5 user/pass options, WinHTTP detection, macOS detection on request).

## Install

```sh
go get github.com/durck/proxykit
```

## Quickstart

### Direct dial — no proxy configured

```go
import "github.com/durck/proxykit"

d := proxykit.NewDialer(proxykit.Config{})
conn, err := d.DialContext(ctx, "tcp", "example.com:443")
```

### Explicit proxy

```go
d := proxykit.NewDialer(proxykit.Config{
    Manual: "http://proxy.corp:8080",
})
conn, err := d.DialContext(ctx, "tcp", "example.com:443")
```

### Auto-detect from env / system proxy

```go
d := proxykit.NewDialer(proxykit.Config{AutoDetect: true})
conn, err := d.DialContext(ctx, "tcp", "example.com:443")
```

`HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY` (and the lower-case spellings) are honoured everywhere; on Windows the manual ProxyServer in `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings` is read as well; on Linux, `/etc/environment` and the GNOME (GSettings) and KDE (kioslaverc) desktop proxy settings are consulted too.

### Authenticated proxy

```go
import (
    "github.com/durck/proxykit"
    "github.com/durck/proxykit/auth"
)

d := proxykit.NewDialer(proxykit.Config{
    Manual: "http://proxy.corp:8080",
    Auth: []auth.Authenticator{
        auth.Negotiate("HTTP/PROXY.CORP.LOCAL"), // Windows: SSPI · Linux/macOS: gokrb5 (Kerberos ticket)
        auth.NTLM("CORP", "alice", "secret"),
        auth.Basic("alice", "secret"),
    },
})
```

Authenticators are tried in order against schemes the proxy advertises in `Proxy-Authenticate`. Userinfo embedded in the proxy URL (`http://user:pass@proxy:8080`) is automatically converted into a Basic authenticator and prepended to the chain.

#### Negotiate / Kerberos across platforms

`auth.Negotiate(spn)` is the same call everywhere; only the backend differs:

- **Windows** — the SSPI subsystem, under the identity the process runs as.
- **Linux / macOS** — [`jcmturner/gokrb5`](https://github.com/jcmturner/gokrb5)
  mints an SPNEGO token from your Kerberos ticket. It reads the configuration in
  `$KRB5_CONFIG` (else `/etc/krb5.conf`) and the credential cache named by
  `$KRB5CCNAME` — `FILE:` and `DIR:` caches on Linux/macOS, plus Linux
  `KEYRING:` caches. When unset, it defaults to `/tmp/krb5cc_<uid>`.
  Get a ticket first (e.g. `kinit alice@REALM`).

`spn` must match the proxy's registered service principal (e.g.
`HTTP/proxy.corp.local`). Kerberos is **on by default** on Linux/macOS; build
with `-tags proxykit_nokerberos` to drop the gokrb5 dependency, after which
`Negotiate` returns `errors.ErrUnsupported` on non-Windows.

The Kerberos proxy path has a tagged integration test that starts a local MIT
KDC in Docker and validates the emitted SPNEGO token with a service keytab:

```sh
go test -tags integration ./transport -run TestConnect_Negotiate_FullDance -count=1 -v
```

### As an `http.RoundTripper`

```go
client := &http.Client{
    Transport: proxykit.NewHTTPTransport(proxykit.Config{
        Manual:  "http://proxy.corp:8080",
        Timeout: 30 * time.Second,
    }),
}
resp, err := client.Get("https://example.com")
```

## Security note

For an **`https`** proxy, the TLS handshake *to the proxy* skips certificate verification by default (`InsecureSkipVerify`). Corporate CONNECT proxies routinely present internally-issued certificates, and the end-to-end TLS to your actual destination is unaffected by this. To verify the proxy certificate instead, build a `transport.Connect{TLSConfig: ...}` directly rather than going through `Config`. Plain `http` proxies and SOCKS5 are unaffected.

## Examples

Runnable demos live under [`examples/`](examples/):

- [`examples/basic`](examples/basic/main.go) — explicit `--proxy URL` dial.
- [`examples/autodetect`](examples/autodetect/main.go) — `cfg.AutoDetect = true`.
- [`examples/http_client`](examples/http_client/main.go) — `http.Client{Transport: NewHTTPTransport(cfg)}`.

Run them with `go run`:

```sh
go run ./examples/basic --proxy http://proxy:8080 example.com:443
HTTPS_PROXY=http://proxy:8080 go run ./examples/autodetect example.com:443
go run ./examples/http_client --auto https://example.com
```

## proxytest CLI

`cmd/proxytest` is a diagnostic CLI bundled with the module:

```sh
go install github.com/durck/proxykit/cmd/proxytest@latest

proxytest detect
# URL                                       FROM        USER
# http://proxy.corp:8080                    env
# socks5://socks.corp:1080                  wininet
# (on Linux, linux/etc-environment, linux/gnome and linux/kde rows appear too)

proxytest dial example.com:443                            # direct
proxytest dial --auto example.com:443                     # detect.All
proxytest dial --proxy http://proxy:8080 example.com:443  # explicit
```

## Architecture

- `proxykit` (root) — public API (`Config`, `Dialer`, `NewDialer`, `NewHTTPTransport`, `ParseProxyURL`).
- `proxykit/transport` — concrete dialers: `Direct`, `Connect` (HTTP CONNECT), `SOCKS5`. Each implements the `Dialer` shape directly and is composable.
- `proxykit/auth` — `Authenticator` interface plus `Basic`, `None`, `NTLM`, `Negotiate` (Windows SSPI; Linux/macOS via `jcmturner/gokrb5`, opt out with `-tags proxykit_nokerberos`).
- `proxykit/detect` — `Detector` framework, `EnvDetector` (always), `WinINETDetector` (Windows-only), and the Linux-only `EtcEnvironmentDetector`, `GNOMEDetector`, `KDEDetector`.

## License

[MIT](LICENSE).
