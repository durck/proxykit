# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims
to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html). The public
API is unstable until `v1.0`.

## [Unreleased]

## [0.3.0] - 2026-06-04

### Added

- **PAC / WPAD** (opt-in `-tags proxykit_pac`): per-destination proxy selection
  by evaluating a `FindProxyForURL(url, host)` script with the Netscape host
  functions, on the pure-Go [`dop251/goja`](https://github.com/dop251/goja)
  engine. PAC is sourced from `Config.PAC` (inline), `Config.PACURL` (fetched),
  the OS-configured AutoConfigURL (via `AutoDetect`), or active DNS-WPAD
  discovery (`Config.WPAD`, a separate opt-in). New `Config.PAC`, `Config.PACURL`
  and `Config.WPAD` fields; `detect.Candidate.PACURL` surfaces OS PAC URLs. (#14)
- **macOS** system-proxy detection via `scutil --proxy` (`detect.MacOSDetector`);
  CI now also runs on `macos-latest`. (#13)
- **Windows WinHTTP** per-machine detection: the HKLM Internet Settings hive plus
  `WinHttpGetIEProxyConfigForCurrentUser` (`detect.WinHTTPDetector`),
  complementing the per-user `WinINETDetector`. (#12)
- **Linux desktop** detection: `/etc/environment`, GNOME (GSettings) and KDE
  (kioslaverc) — `EtcEnvironmentDetector`, `GNOMEDetector`, `KDEDetector`. (#1)
- **Negotiate / Kerberos on Linux & macOS** via `jcmturner/gokrb5` (FILE/DIR and
  Linux `KEYRING:` credential caches), with a Dockerised-KDC integration test.
  Opt out with `-tags proxykit_nokerberos`. (#2, #9, #10)
- **Typed SOCKS5 credentials**: `transport.SOCKS5.Auth`
  (`SOCKS5Auth{Username, Password}`), taking precedence over `ProxyURL.User`, so
  callers need not embed credentials in the URL. (#11)
- `BenchmarkSOCKS5_Dial` companion benchmark. (#4)

### Changed

- The default build remains cgo-free and JS-engine-free; `goja` is linked only
  with `-tags proxykit_pac`, and CI fails if it leaks into the default build.
- `redactProxyURL` hardened to mask credentials even in control-character-
  malformed proxy URLs. (#5)

### Fixed

- `ParseProxyURL` now rejects malformed input it previously accepted (returning
  a bogus URL with a nil error): an empty hostname (e.g. `http://:8080`, which
  Go's dialer treats as localhost) and a scheme-carrying but unparseable URL
  (e.g. `http://[::1`, `http:// `).
- `fallbackDialer` now short-circuits when the context is already cancelled. (#6)

## [0.1.0] - 2026-05-06

Initial release.

### Added

- Core API: `Dialer`, `NewDialer`, `NewHTTPTransport`, `ParseProxyURL`, `Config`.
- Transports: `Direct`, `Connect` (HTTP CONNECT over TCP and TLS), `SOCKS5`.
- Authenticators: `None`, `Basic`, `NTLM`, and `Negotiate` (Windows SSPI).
- Detection: `*_PROXY` environment variables (all platforms) and the Windows
  WinINET (HKCU) registry.
- `cmd/proxytest` diagnostic CLI and runnable `examples/`.

[Unreleased]: https://github.com/durck/proxykit/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/durck/proxykit/compare/v0.1.0...v0.3.0
[0.1.0]: https://github.com/durck/proxykit/releases/tag/v0.1.0
