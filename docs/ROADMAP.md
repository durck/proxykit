# proxykit roadmap

Tracks deferred work after `v0.1`. Each entry is sized to fit a single
GitHub issue once the repo lands on a remote — copy-paste the body
verbatim.

## v0.1 (released)

12-commit plan executed; see [`PLAN.md`](PLAN.md). Tag: `v0.1.0`.

## v0.2 — Linux detection + cross-platform Kerberos

### Issue: detect Linux desktop proxy settings — done

**Status:** implemented — `EtcEnvironmentDetector`, `GNOMEDetector`, and
`KDEDetector` landed in the `detect` package, each Linux-gated with a
non-Linux stub and pure, table-tested parsers. GNOME additionally reads
stored credentials. `cmd/proxytest detect` lists the new sources.

**Title:** Detect Linux desktop proxy settings (env, GNOME, KDE)

**Body:**

`detect.EnvDetector` already covers `*_PROXY` environment variables.
Linux desktop users routinely configure proxies through the desktop
environment instead, and those values do not propagate to the shell
environment.

Implement three new detectors under `detect/` (each with its own
`//go:build linux` file plus a non-Linux stub):

- `EtcEnvironmentDetector` — parses `/etc/environment`, honouring the
  same case-insensitive `*_PROXY` matching as `EnvDetector`.
- `GNOMEDetector` — reads the `org.gnome.system.proxy` schema via
  `gsettings get` (shelling out, no D-Bus dependency); follows the
  `mode=manual|auto|none` switch.
- `KDEDetector` — parses `~/.config/kioslaverc`, honouring
  `ProxyType` and per-protocol `httpProxy`/`httpsProxy`/`socksProxy`
  values.

Acceptance:

- Each detector self-registers into `detect.Default` on Linux only.
- Pure-function parsers tested with embedded fixtures (no real
  desktop required).
- `cmd/proxytest detect` lists the new sources alongside `env`.

### Issue: Kerberos Negotiate on Linux/macOS via gokrb5

**Title:** Negotiate (Kerberos) on Linux/macOS via jcmturner/gokrb5

**Status:** core landed — `auth/negotiate_other.go` replaced by a `gokrb5`
backend (`negotiate_gokrb5.go`, gated `!windows && !proxykit_nokerberos`) with a
`proxykit_nokerberos` opt-out stub; the Windows SSPI file is unchanged. It
resolves `$KRB5_CONFIG`/`/etc/krb5.conf` and FILE/DIR credential caches
(default `/tmp/krb5cc_<uid>`), plus Linux KEYRING caches using the MIT
collection layout (`_krb*`, `krb_ccache:primary`, `user`/`big_key` credential
payloads). Kerberos is on by default on non-Windows. Remaining: the
Dockerised-KDC integration test mirroring `TestConnect_NTLM_FullDance`.

**Body** (original issue draft — the Status above records what landed):

`auth.Negotiate` currently returns `errors.ErrUnsupported` outside
Windows because SSPI is the only Kerberos backend wired in. Add a
non-Windows path using `github.com/jcmturner/gokrb5/v8`, reading
`/etc/krb5.conf` and the user's credential cache (KEYRING / FILE /
ccache).

Acceptance:

- `auth/negotiate_other.go` replaced by a `gokrb5`-backed
  implementation guarded by build tags; the Windows file is
  unchanged.
- New build tag for users who explicitly opt out of the Kerberos
  dependency: `proxykit_nokerberos` (build with `-tags proxykit_nokerberos`).
- Integration test mirroring `TestConnect_NTLM_FullDance` against a
  mock proxy that emits an SPNEGO challenge.

## v0.3+ — community-driven

- SOCKS5 user/pass exposed as a typed option on `transport.SOCKS5`
  (currently inferred from `ProxyURL.User`).
- WinHTTP detection (`HKLM` per-machine path + `WinHttpGetIEProxy
  ConfigForCurrentUser`).
- macOS detection (`SCDynamicStore` / `scutil --proxy`).
- PAC / WPAD evaluation (probably gated behind a JS engine
  dependency — opt-in build tag).

## Out-of-band

- `git tag v0.1.0` and push the tag once the repo has a public
  remote so `pkg.go.dev` indexes the module.
- Add a `BenchmarkSOCKS5_Dial` companion to the existing
  `BenchmarkConnect_Dial` / `BenchmarkNTLM_Handshake`.
