# proxykit — Project Context

> Self-contained brief for an AI agent or new contributor starting cold in this directory. Read this first, then `docs/PLAN.md` for the implementation roadmap and `docs/EXTRACT_FROM_RSSH.md` for the source code references.

## Goal

A small, dependency-light Go library for outbound connections through HTTP/HTTPS CONNECT and SOCKS5 proxies, with optional system-proxy auto-detection and pluggable authentication.

Designed for static-binary clients (reverse shells, agents, CLIs) that need to traverse corporate proxies. Targets the same niche as `golang.org/x/net/http/httpproxy` but with proper auth and detection.

## Status

`v0.0.x` — early development, API unstable until `v1.0`. Last committed step is tracked in `docs/PLAN.md` ("Current step" section).

## Scope

### In scope (v0.1 MVP)

| Area | Support |
|------|---------|
| Transports | HTTP CONNECT (TCP+TLS), SOCKS5, Direct |
| Auth | None, Basic, NTLM, Negotiate/Kerberos (Windows SSPI) |
| Detection | `*_PROXY` env vars, Windows WinINET (HKCU) |
| API | `Dialer` (net.Dial-compatible) + `http.RoundTripper` adapter, `context.Context` everywhere |
| Platforms | Windows, Linux |
| Build | No cgo. Static binaries. |

### Out of scope (v0.1)

PAC/WPAD, SOCKS4/4a, Digest auth, server-side SOCKS, TLS interception/MITM, connection pooling, retry/circuit breaker, macOS/BSD detection.

### Roadmap

- **v0.2** — Linux detection (`/etc/environment`, GNOME GSettings, KDE kioslaverc); Linux/macOS Kerberos via `jcmturner/gokrb5`.
- **v0.3+** — community-driven (SOCKS5 user/pass, WinHTTP detection, macOS detection if requested).

## Architecture

### Public API sketch

```go
package proxykit

type Config struct {
    Manual     string                  // explicit URL ("http://proxy:8080")
    AutoDetect bool                    // enable detectors
    Auth       []auth.Authenticator    // try in order: basic → ntlm → negotiate
    Timeout    time.Duration           // per dial attempt
    OnLog      func(level, msg string) // hook instead of stdlib log
}

type Dialer interface {
    DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

func NewDialer(cfg Config) Dialer
func ParseProxyURL(s string) (*url.URL, error)
func NewHTTPTransport(cfg Config) http.RoundTripper

// detect — sub-package for direct use
package detect
type Candidate struct {
    URL  string
    User string
    Pass string
    From string  // "env", "wininet", "linux/gnome", ...
}
func All() ([]Candidate, error)
```

### Directory layout

```
proxykit/
├── doc.go               package documentation
├── config.go            Config, options
├── dialer.go            Dialer, NewDialer, DialContext
├── parse.go             ParseProxyURL
├── transport.go         NewHTTPTransport
├── transport/
│   ├── direct.go        net.Dialer wrapper
│   ├── connect.go       HTTP CONNECT (TCP+TLS)
│   └── socks5.go        x/net/proxy.SOCKS5 wrapper
├── auth/
│   ├── auth.go          Authenticator interface (negotiate flow)
│   ├── none.go basic.go ntlm.go
│   ├── negotiate_windows.go  SSPI (extracted/inspired by reverse_ssh/pkg/wauth)
│   └── negotiate_other.go    !windows stub
├── detect/
│   ├── detect.go        Detector interface, aggregator
│   ├── env.go           x/net/http/httpproxy
│   ├── wininet_windows.go
│   └── wininet_other.go
├── examples/{basic,autodetect,http_client}/main.go
└── cmd/proxytest/main.go    CLI: dump candidates + smoke-test dial
```

## Decisions (locked)

| # | Decision | Why |
|---|----------|-----|
| 1 | License: **MIT** | Maximally permissive, common for Go libs. |
| 2 | Module path: `github.com/durck/proxykit` | Owner's GitHub. |
| 3 | **No cgo** | Static binaries, easy cross-compile (`GOOS=windows go build` from Linux). Matches `reverse_ssh` philosophy. Loses libproxy / macOS Keychain — acceptable. |
| 4 | NTLM library: **`github.com/bodgit/ntlmssp`** | Stable. Owner switched away from `Azure/go-ntlmssp` due to bugs. |
| 5 | Windows SSPI via `syscall` to `secur32.dll` | No cgo. Pattern from `reverse_ssh/pkg/wauth`. |
| 6 | API takes `context.Context` everywhere | Modern Go convention; `reverse_ssh` uses `time.Duration` only — we improve. |
| 7 | Logging via injected hook (`OnLog`) | Library must not call `log.Println` directly. Consumer decides. |
| 8 | Detection: separate sub-package `detect` | Allows direct use without instantiating Dialer (e.g., for diagnostics CLI). |
| 9 | Reference source: `reverse_ssh` (BSD-3) at `../reverse_ssh/` | Primary inspiration. License compatible. See `docs/EXTRACT_FROM_RSSH.md` for what to lift. |
| 10 | Phase 2 (Linux detect + Kerberos) is **separate work**, not v0.1 | Scope discipline. |

## Conventions

- **Commits:** Conventional Commits (`feat:`, `fix:`, `chore:`, `docs:`, `refactor:`, `test:`).
- **No AI co-author lines** in commits/PRs/comments.
- **Tests:** unit tests for parsers, `httptest`-based mock proxy for transport+auth flows. Integration with real Squid is post-v0.1.
- **Code style:** standard Go, `go vet` and `go test -race` must pass on every commit.
- **Build:** every commit must `go build ./...` cleanly on both `GOOS=linux` and `GOOS=windows`.

## Dependencies (allowed)

- `golang.org/x/net` — `proxy` (SOCKS5), `http/httpproxy` (env parsing).
- `golang.org/x/sys/windows/registry` — WinINET registry (Windows-only build tag).
- `github.com/bodgit/ntlmssp` — NTLM authenticator.

Avoid adding new deps without a clear reason. Stdlib first.

## Operational notes

### Git author for this repo

```
user.name  = durck
user.email = poiulkjhmnv50@gmail.com
```

### Pre-commit hook gotcha (Claude Code only)

The owner runs Claude Code with a `PreToolUse:Bash` hook (`pre-commit-gate.js`) that runs `go test ./...` before any `git commit` and blocks the commit on any FAIL. The hook executes from Claude's primary working directory, **not** the cwd of the chained `cd ... && git commit ...` command. If Claude's primary cwd is `reverse_ssh`, the hook will see a pre-existing failing test (`TestQuoteHandling` in `internal/terminal/`) and block all commits regardless of the target repo.

**Workaround:** owner runs commits manually in a separate terminal. AI agents should prepare the staged state and the commit message, then ask the owner to commit.

If Claude is started directly in this `proxykit/` directory, the hook will only see proxykit's tests, and commits should pass once tests are green.

### Cross-compile sanity

Every meaningful change should be checked with:

```sh
go vet ./...
go test -race ./...
GOOS=linux   GOARCH=amd64 go build ./...
GOOS=windows GOARCH=amd64 go build ./...
```

CI in `.github/workflows/ci.yml` does this on every push/PR.

## Where to look next

1. **`docs/PLAN.md`** — 12-step commit plan, current step marker, acceptance criteria.
2. **`docs/EXTRACT_FROM_RSSH.md`** — table of source files in `../reverse_ssh/` to draw from, with file:line refs and what to do with each.
3. **`README.md`** — public-facing project description.
4. **`doc.go`** — package-level Go documentation.

## Reference repo

Primary source of patterns and code to lift:

```
../reverse_ssh/             # BSD-3, NHAS fork by durck
  internal/client/client.go               Connect(), GetProxyDetails()
  internal/client/proxy_ntlm.go           NTLM helpers
  internal/client/proxy_windows.go        Negotiate via wauth
  internal/client/proxy_autodetect_*.go   WinINET detector + parser
  pkg/wauth/wauth.go                      SSPI syscall wrapper (Windows)
```

The proxy-related changes in `reverse_ssh` were authored in the same conversation that bootstrapped this project; they represent the state of the art the owner is comfortable with. **Use them as reference, not as a hard contract** — `proxykit` aims for cleaner abstractions and a stable public API.
