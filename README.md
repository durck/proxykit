# proxykit

Small Go library for outbound connections through HTTP/HTTPS CONNECT and SOCKS5 proxies, with optional system-proxy auto-detection and pluggable authentication.

> **Status:** early development. API is unstable until v1.0. Tracking version: `v0.0.x`.

## Features (planned for v0.1)

| Area              | Support                                                           |
|-------------------|-------------------------------------------------------------------|
| Transports        | HTTP CONNECT (TCP+TLS), SOCKS5, Direct                            |
| Authentication    | None, Basic, NTLM, Negotiate/Kerberos (Windows SSPI)              |
| Auto-detection    | `*_PROXY` env vars, Windows WinINET (HKCU)                        |
| API               | `Dialer` (`net.Dial`-compatible), `http.RoundTripper` adapter     |
| Platforms         | Windows, Linux (no cgo)                                           |

### Out of scope

PAC/WPAD, SOCKS4/4a, Digest auth, server-side SOCKS, TLS interception.

### Roadmap

- **v0.1** — items above (MVP)
- **v0.2** — Linux detection (`/etc/environment`, GNOME GSettings, KDE kioslaverc) and Linux/macOS Kerberos via `jcmturner/gokrb5`
- **v0.3+** — community feedback driven

## Install

```sh
go get github.com/durck/proxykit
```

## Quickstart

Coming soon. See [`examples/`](examples/) once published.

## License

[MIT](LICENSE)
