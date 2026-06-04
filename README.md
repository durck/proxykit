# proxykit

Small, dependency-light Go library for outbound connections through HTTP/HTTPS CONNECT and SOCKS5 proxies, with optional system-proxy auto-detection and pluggable authentication.

> **Status:** all planned `v0.1`–`v0.3` features are implemented (see [`CHANGELOG.md`](CHANGELOG.md)). The public API is unstable until `v1.0` — expect occasional renames during the `v0.x` line.

## Features

| Area              | Support                                                           |
|-------------------|-------------------------------------------------------------------|
| Transports        | HTTP CONNECT (TCP+TLS), SOCKS5, Direct                            |
| Authentication    | None, Basic, NTLM, Negotiate / Kerberos (Windows SSPI, Linux/macOS via gokrb5) |
| Auto-detection    | `*_PROXY` env vars (any platform), Windows WinINET (HKCU) + WinHTTP (HKLM + IE), Linux `/etc/environment` + GNOME + KDE, macOS `scutil` |
| PAC / WPAD        | `FindProxyForURL` evaluation (goja) + DNS-WPAD discovery — opt-in `-tags proxykit_pac` |
| API               | `Dialer` (`net.Dial`-compatible), `http.RoundTripper` adapter     |
| Platforms         | Windows, Linux, macOS — no cgo, fully static                      |

### Out of scope

SOCKS4 / SOCKS4a, Digest auth, server-side SOCKS, TLS interception / MITM, connection pooling, retry / circuit breaker, BSD detection, and DHCP-based WPAD (option 252).

### Status

All roadmap items through `v0.3` are implemented: cross-platform detection (env vars, Windows WinINET + WinHTTP, Linux env-file/GNOME/KDE, macOS scutil), Negotiate/Kerberos on Linux/macOS via gokrb5, the typed SOCKS5 credential option, and opt-in PAC/WPAD. See [`CHANGELOG.md`](CHANGELOG.md) for the full history and [`docs/ROADMAP.md`](docs/ROADMAP.md) for how each piece was scoped.

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

`HTTP_PROXY` and `HTTPS_PROXY` (and the lower-case spellings) are honoured on every platform; `NO_PROXY` is honoured as a bypass list (see [Bypassing proxies](#bypassing-proxies-no_proxy)). Beyond env vars, proxykit reads the Windows WinINET (per-user `HKCU`) and WinHTTP (per-machine `HKLM` + the IE config) proxy settings; on Linux, `/etc/environment` plus the GNOME (GSettings) and KDE (kioslaverc) desktop settings; and on macOS, the system configuration via `scutil`. Built with `-tags proxykit_pac`, a system-configured PAC URL is honoured too (see [PAC / WPAD](#pac--wpad-opt-in)).

### Bypassing proxies (NO_PROXY)

Destinations that must always be reached directly go in `Config.NoProxy`, using
the standard `NO_PROXY` syntax — a domain suffix (`corp.local` or `.corp.local`),
an IP or CIDR (`10.0.0.0/8`), a `host:port`, or `*` to bypass everything:

```go
d := proxykit.NewDialer(proxykit.Config{
    Manual:  "http://proxy.corp:8080",
    NoProxy: "localhost,127.0.0.1,.internal.corp,10.0.0.0/8",
})
```

A matching destination dials directly, overriding `Manual`, `AutoDetect`, and
PAC. With `AutoDetect` enabled the environment's `NO_PROXY`/`no_proxy` is merged
in. Only the environment variable and `Config.NoProxy` currently feed the bypass
list; the OS exception lists (WinINET/WinHTTP, GNOME/KDE, `scutil`) are not yet
wired in.

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

### SOCKS5 credentials

A `socks5://user:pass@host` URL works through `Config.Manual` like any other proxy. When building the transport directly, supply credentials via the typed `transport.SOCKS5.Auth` option instead of embedding them in the URL:

```go
import (
    "net/url"

    "github.com/durck/proxykit/transport"
)

proxyURL, _ := url.Parse("socks5://socks.corp:1080")
d := &transport.SOCKS5{
    ProxyURL: proxyURL,
    Auth:     &transport.SOCKS5Auth{Username: "alice", Password: "s3cr3t"},
}
conn, err := d.DialContext(ctx, "tcp", "example.com:443")
```

`Auth` takes precedence over any userinfo in `ProxyURL`; leave it nil to fall back to `ProxyURL.User`.

### PAC / WPAD (opt-in)

Proxy Auto-Config evaluates a JavaScript `FindProxyForURL(url, host)` to pick a proxy **per destination**. It needs a JS engine, so it is gated behind a build tag to keep the default build dependency-light and `cgo`-free:

```sh
go build -tags proxykit_pac ./...
```

With the tag, supply the PAC via `Config`:

```go
// 1) an explicit PAC URL (fetched directly, never through a proxy):
d := proxykit.NewDialer(proxykit.Config{PACURL: "http://wpad.corp/proxy.pac"})

// 2) the OS-configured PAC URL (Windows AutoConfigURL, macOS / GNOME auto mode):
d = proxykit.NewDialer(proxykit.Config{AutoDetect: true})

// 3) active DNS-WPAD discovery (probes http://wpad.<domain>/wpad.dat):
d = proxykit.NewDialer(proxykit.Config{WPAD: true})

// 4) an inline script (handy for tests):
d = proxykit.NewDialer(proxykit.Config{PAC: `function FindProxyForURL(u,h){ return "DIRECT"; }`})
```

The PAC result (`"PROXY host:port; SOCKS host:port; DIRECT"`) becomes a per-destination fallback chain. `Config.Manual` always wins; if a PAC source is set but the binary was built **without** `-tags proxykit_pac`, it is logged and ignored (routing degrades to static/DIRECT).

**Security:** `WPAD` is a separate opt-in from `AutoDetect` because a rogue `wpad` host on the network can serve an attacker-controlled PAC — enable it only on trusted networks. Evaluation is time-bounded (a watchdog interrupts a runaway script) and `shExpMatch` uses RE2 (no ReDoS). DHCP-based WPAD (option 252) is out of scope.

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
# http://machine-proxy.corp:8080            winhttp
# PAC http://wpad.corp/proxy.pac            winhttp
# (on Linux, linux/etc-environment, linux/gnome and linux/kde rows appear too; on macOS, a macos row)

proxytest dial example.com:443                            # direct
proxytest dial --auto example.com:443                     # detect.All
proxytest dial --proxy http://proxy:8080 example.com:443  # explicit
```

## Development

```sh
go test ./...                      # default build
go test -tags proxykit_pac ./...   # with PAC/WPAD enabled
go vet ./... && go build ./...
```

Two opt-in build tags toggle optional dependencies:

| Tag | Effect |
|-----|--------|
| `proxykit_pac` | Enable PAC/WPAD evaluation; adds the pure-Go [`dop251/goja`](https://github.com/dop251/goja) JS engine. **Off by default.** |
| `proxykit_nokerberos` | Drop the `jcmturner/gokrb5` dependency; `auth.Negotiate` then returns `errors.ErrUnsupported` on non-Windows. Kerberos is **on by default.** |

The default build pulls in no JS engine and no cgo, staying fully static (CI guards that `goja` never enters the default dependency graph). CI runs `go vet`, `go test -race`, and `go build` in both build modes across Windows, Linux, and macOS, plus cross-builds and a Dockerised-KDC Kerberos integration test.

## Architecture

- `proxykit` (root) — public API (`Config`, `Dialer`, `NewDialer`, `NewHTTPTransport`, `ParseProxyURL`) and the PAC/WPAD integration (`pac.go`: the per-destination `pacDialer` that assembles transports from a PAC decision).
- `proxykit/internal/pac` — the opt-in PAC/WPAD engine: `FindProxyForURL` evaluation (goja behind `-tags proxykit_pac`, a stub otherwise), PAC fetching, and DNS-WPAD discovery. A leaf package, so the JS engine never enters the default dependency graph.
- `proxykit/transport` — concrete dialers: `Direct`, `Connect` (HTTP CONNECT), `SOCKS5`. Each implements the `Dialer` shape directly and is composable.
- `proxykit/auth` — `Authenticator` interface plus `Basic`, `None`, `NTLM`, `Negotiate` (Windows SSPI; Linux/macOS via `jcmturner/gokrb5`, opt out with `-tags proxykit_nokerberos`).
- `proxykit/detect` — `Detector` framework, `EnvDetector` (always), `WinINETDetector` (HKCU) + `WinHTTPDetector` (HKLM + IE) (Windows-only), the Linux-only `EtcEnvironmentDetector`, `GNOMEDetector`, `KDEDetector`, and the macOS-only `MacOSDetector` (`scutil --proxy`).

## License

[MIT](LICENSE).
