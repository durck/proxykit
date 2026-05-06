# proxykit v0.1 — Implementation Plan

12 atomic commits. Each must leave the tree green: `go vet ./...`, `go test -race ./...`, and cross-build for windows/linux all pass.

## Current step

> **Next: step 8 (SOCKS5 transport).** Steps 1-7 committed.

Update this section after each merged commit.

## Conventions

- Conventional Commits (`feat:`, `chore:`, `docs:`, `test:`, etc.).
- Subject ≤ 72 chars, body wraps at 72.
- One commit = one logical change. Tests for new code in the same commit unless prohibitively coupled.
- No AI co-author lines.
- Public symbols get a short godoc comment. No multi-paragraph docstrings.

## Steps

### 1. `chore: init module skeleton` ✓

Bootstrap: `go.mod`, `LICENSE` (MIT), `README.md`, `doc.go`, `.gitignore`, `.github/workflows/ci.yml`, empty package directories. Verify `go vet` and `go build` pass on a tree with no Go files yet.

### 2. `feat: add Config and ParseProxyURL` ✓

**Files:**

- `config.go` — `type Config`, `type Option func(*Config)` (or struct-only — pick one and stick).
- `parse.go` — `ParseProxyURL(s string) (*url.URL, error)`. Logic adapted from `reverse_ssh/internal/client/client.go:50-86` (`GetProxyDetails`):
  - normalize bare `host:port` to `http://host:port`
  - validate scheme in `{http, https, socks, socks5}` (reject `socks4` for now — out of scope)
  - fill default ports per scheme
  - return parsed `*url.URL`, not a string (cleaner API than rssh)
- `parse_test.go` — table-driven tests for each scheme, default ports, bare host, malformed input, schemes we explicitly reject.

**Acceptance:** `go test ./...` green. Public symbols documented.

### 3. `feat: add Direct dialer and Dialer interface` ✓

**Files:**

- `dialer.go` — `type Dialer interface { DialContext(ctx, network, addr) (net.Conn, error) }`, `func NewDialer(cfg Config) Dialer`. For now Dialer falls through to direct.
- `transport/direct.go` — thin wrapper over `net.Dialer` with `cfg.Timeout` honoured.
- `dialer_test.go` — `httptest.NewServer` + smoke test that direct dial connects.

**Acceptance:** `Dialer` works for `cfg.Manual == ""` (direct mode).

### 4. `feat: add HTTP CONNECT transport` ✓

**Files:**

- `transport/connect.go` — implements CONNECT for `http://` and `https://` proxy URLs. Logic adapted from `reverse_ssh/internal/client/client.go:104-256`:
  - `net.DialTimeout` for `http`, `tls.DialWithDialer` for `https` (with `InsecureSkipVerify: true`, this is a feature for our threat model — document explicitly)
  - send `CONNECT host:port HTTP/1.1\r\nHost: host:port\r\n\r\n`
  - parse first response line; on `200` return the conn
  - on `407`: hand off to authenticator chain (next commit)
  - on other status: return error with the status line
- `transport/connect_test.go` — `httptest.NewServer` configured to handle CONNECT, returning 200 / 407 / arbitrary errors.

**Acceptance:** Transport works for unauthenticated proxies. 407 returns a typed error so the auth layer can hook in.

### 5. `feat: add Basic authenticator` ✓

**Files:**

- `auth/auth.go` — `type Authenticator interface` with method like `Headers(challenge []byte) (headers []string, done bool, err error)`. Designed for multi-round auth (NTLM needs 3 rounds).
- `auth/none.go` — no-op authenticator.
- `auth/basic.go` — `Basic(user, pass string) Authenticator`. Single round: `Authorization: Basic <base64>`.
- `auth/basic_test.go` — encoding correctness, special chars in user/pass.
- Integrate into `transport/connect.go`: on 407, iterate `cfg.Auth`, retry with each authenticator until 200 or all exhausted.
- Update `transport/connect_test.go` with a 407+Basic mock.

### 6. `feat: add NTLM authenticator` ✓

**Files:**

- `auth/ntlm.go` — `NTLM(domain, user, pass string) Authenticator`. Wraps `github.com/bodgit/ntlmssp`. Three-round dance. Reference: `reverse_ssh/internal/client/proxy_ntlm.go` and `client.go:156-226`.
- `auth/ntlm_test.go` — mock NTLM proxy (challenge fixed, verify Type 1/3 messages match expected base64).
- Add to `go.mod`: `github.com/bodgit/ntlmssp`.

### 7. `feat: add Negotiate authenticator (Windows SSPI)` ✓

**Files:**

- `auth/negotiate_windows.go` (`//go:build windows`) — `Negotiate() Authenticator` using `golang.org/x/sys/windows` + raw syscalls to `secur32.dll`. Lift logic from `reverse_ssh/pkg/wauth/wauth.go`. Single-round Negotiate header.
- `auth/negotiate_other.go` (`//go:build !windows`) — stub returning `errors.ErrUnsupported` or similar.
- `auth/negotiate_test.go` — Windows-only smoke test (skipped on other platforms).

### 8. `feat: add SOCKS5 transport`

**Files:**

- `transport/socks5.go` — wraps `golang.org/x/net/proxy.SOCKS5`. Honours context cancellation.
- `transport/socks5_test.go` — `armon/go-socks5` as test server (dev-only dep; vendor or use as test-only). Or write a minimal SOCKS5 stub by hand.

### 9. `feat: add env vars detector`

**Files:**

- `detect/detect.go` — `type Candidate`, `type Detector interface { Detect() ([]Candidate, error) }`, `func All() ([]Candidate, error)` aggregator.
- `detect/env.go` — uses `golang.org/x/net/http/httpproxy.FromEnvironment`. Honours both upper and lower case `*_PROXY`. Returns up to 2 candidates (http, https).
- `detect/env_test.go` — `t.Setenv` based table.

### 10. `feat: add WinINET detector (Windows)`

**Files:**

- `detect/wininet_windows.go` (`//go:build windows`) — reads HKCU `Software\Microsoft\Windows\CurrentVersion\Internet Settings`, `ProxyEnable`+`ProxyServer`. Adapt from `reverse_ssh/internal/client/proxy_autodetect_windows.go` and `proxy_autodetect.go`.
- `detect/wininet_other.go` (`//go:build !windows`) — empty implementation.
- `detect/wininet_test.go` — chooses pure-function tests (parser-only), no real registry mutation.

### 11. `feat: compose Dialer and add HTTP transport adapter`

**Files:**

- `dialer.go` — wire it all up: `NewDialer(cfg)` resolves proxy URL (manual → auto-detected), picks transport by scheme, threads authenticators. Implements fallback chain (manual → detected → env), preserving the `reverse_ssh` precedence model.
- `transport.go` — `NewHTTPTransport(cfg) http.RoundTripper` wrapping `&http.Transport{ DialContext: dialer.DialContext }`.
- `dialer_test.go` — end-to-end via mock: manual URL works, auto-detect works (with env set), fallback chain works.
- `transport_test.go` — HTTP request through proxy.

### 12. `docs: README usage, examples, proxytest CLI`

**Files:**

- `README.md` — full quickstart, feature table (mark v0.1 done), examples linkified.
- `examples/basic/main.go` — explicit `--proxy URL` dial.
- `examples/autodetect/main.go` — `cfg.AutoDetect = true`.
- `examples/http_client/main.go` — `http.Client{Transport: NewHTTPTransport(cfg)}`.
- `cmd/proxytest/main.go` — CLI: `proxytest detect` (lists candidates), `proxytest dial <addr>` (smoke test).

## Acceptance criteria for v0.1 release

- [ ] All 12 commits merged on `main`.
- [ ] `go test -race ./...` green on Windows and Linux.
- [ ] `go vet ./...` clean.
- [ ] Cross-build for `windows/amd64`, `linux/amd64`, `darwin/amd64`.
- [ ] CI workflow green on a representative push.
- [ ] Mock-proxy tests cover: 200, 407+Basic, 407+NTLM, error/timeout paths.
- [ ] Unit tests cover URL parser, env detector, WinINET parser.
- [ ] `examples/basic` connects through a real proxy (manual smoke test on owner's machine).
- [ ] `cmd/proxytest detect` lists candidates correctly on owner's machine.
- [ ] `README.md` lists supported features and explicit non-goals.

## Out-of-band tasks (after v0.1)

- Tag `v0.1.0`, push, verify on `pkg.go.dev`.
- File issues for v0.2 work (Linux detection, Kerberos via gokrb5).
- Consider a small benchmark suite (`BenchmarkDial`, `BenchmarkNTLMHandshake`).
