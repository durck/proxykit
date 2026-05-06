# Extracting patterns from reverse_ssh

The `reverse_ssh` repository at `../reverse_ssh/` (BSD-3 licensed, primary inspiration) contains the working proxy code that seeded this project. This document maps each piece to its destination in `proxykit` and notes what to keep, change, or drop.

> **Approach:** treat rssh as **reference**, not as a contract. `proxykit` is a clean rewrite with stable API and proper abstractions. Lift logic, not signatures.

## Overview table

| reverse_ssh location | proxykit destination | Action |
|----------------------|----------------------|--------|
| `internal/client/client.go:50-86` (`GetProxyDetails`) | `parse.go` | Rewrite. Return `*url.URL` not string. Reject `socks4`. |
| `internal/client/client.go:104-256` (`Connect` HTTP CONNECT branch) | `transport/connect.go` | Rewrite. Split CONNECT loop from auth dispatch. Add context. |
| `internal/client/client.go:257-270` (`Connect` SOCKS5 branch) | `transport/socks5.go` | Trivial wrap. |
| `internal/client/client.go:32-46` (`WriteHTTPReq`) | `transport/connect.go` (private helper) | Lift as-is, rename. |
| `internal/client/client.go:88-102` (`ScanRequest`) | `transport/connect.go` (private helper) | Lift as-is. |
| `internal/client/client.go:285-301` (`getCaseInsensitiveEnv`) | drop | Replaced by `golang.org/x/net/http/httpproxy.FromEnvironment`. |
| `internal/client/proxy_ntlm.go` | `auth/ntlm.go` | Refactor into `Authenticator` interface. |
| `internal/client/proxy_windows.go` (`addHostKerberosHeaders`) | `auth/negotiate_windows.go` | Refactor into `Authenticator`. Drop the rssh-specific signature. |
| `internal/client/proxy_shim.go` | `auth/negotiate_other.go` | Same shape (shim for non-Windows). |
| `pkg/wauth/wauth.go` | `auth/negotiate_windows.go` (or `internal/wauth/`) | Lift the SSPI syscall layer. Probably keep it inside `auth/` package since it has only one consumer. |
| `internal/client/proxy_autodetect.go` (`parseWinINETProxyString`) | `detect/wininet.go` (no build tag) | Lift as-is. |
| `internal/client/proxy_autodetect_windows.go` (`DetectSystemProxy`) | `detect/wininet_windows.go` | Refactor signature to `Detect() ([]Candidate, error)`. |
| `internal/client/proxy_autodetect_other.go` | `detect/wininet_other.go` | Same shape. |
| `internal/client/proxy_autodetect_test.go` | `detect/wininet_test.go` | Lift as-is (parser tests). |
| `internal/client/client.go:347-371` (proxy negotiation in `Run`) | `dialer.go` | Reimplement as the composed `Dialer` (see PLAN step 11). |

## Specific notes

### `Connect()` — the central function in rssh

`reverse_ssh/internal/client/client.go:104` is a 180-line function that does:

1. Parse + dispatch by scheme.
2. Dial proxy (TCP or TLS).
3. Send CONNECT request.
4. Parse first response line.
5. Branch on `407`:
   - if `staticNTLMCreds != nil` → 3-round NTLM dance
   - else if `hostKerberos` → 1-round Negotiate
6. Validate `200`.
7. Or alternatively: SOCKS5 path.
8. Or fall through to direct dial.

For `proxykit`, split this into:

- `transport/connect.go` — pure CONNECT (steps 2-4, 6-7) with one entry point that returns either a usable `net.Conn` or a typed error indicating "needs auth, server says these schemes".
- `auth/auth.go` — the `Authenticator` interface that knows how to mutate request headers given the previous challenge.
- `dialer.go` — the loop that says "try without auth → if 407, walk through `cfg.Auth` chain".

### NTLM in rssh

`internal/client/proxy_ntlm.go` defines two helpers and a constant:

```go
const NTLM = "NTLM"
const AskingForNTLMProxy = "ntlm"  // lowercase substring match against response header
func parseNTLMCreds(creds string) (domain, user, pass string, err error)
func getNTLMAuthHeader(client *ntlmssp.Client, challenge []byte) (string, error)
```

In `proxykit`:

- Move `parseNTLMCreds` into `auth/ntlm.go`. Probably make `NTLM(creds string)` accept `"DOMAIN\\USER:PASS"` for compatibility with rssh's CLI conventions.
- Wrap the 3-round logic in the `Authenticator` interface contract from `auth/auth.go`.

### Windows SSPI (`pkg/wauth`)

`pkg/wauth/wauth.go` is ~200 lines of:

- `AcquireCredentialsHandleW` (`secur32.dll`)
- `InitializeSecurityContextW`
- helpers to wrap output buffers
- `GetAuthorizationHeader(targetURL string) string`

This is **already a small library**. Two options for `proxykit`:

- **(preferred)** Lift `wauth.go` verbatim into `auth/internal/wauth/` and have `auth/negotiate_windows.go` consume it. Keeps the SSPI surface isolated for testing/replacement.
- Inline into `auth/negotiate_windows.go`. Simpler but less testable.

Choose (1) unless `wauth.go` shrinks under refactor.

### WinINET parser

`internal/client/proxy_autodetect.go` is already a clean, build-tag-free pure function. Lift as-is into `detect/wininet.go`. The Windows-side `DetectSystemProxy` becomes `Detect()` returning `[]detect.Candidate{{URL: parsed, From: "wininet"}}`.

The 13 test cases in `proxy_autodetect_test.go` apply unchanged to the new package.

## What NOT to lift

- `getCaseInsensitiveEnv` — `golang.org/x/net/http/httpproxy.FromEnvironment` is the right tool.
- The whole `Run()` reconnect loop (`internal/client/client.go:337-637`) — that's application logic for rssh, not library logic.
- Linker bake-in pattern (`var proxy string` + `-X main.proxy=...`) — that's an rssh CLI feature, not a library concern.
- TLS upgrade after CONNECT (`client.go:438-461`) — out of scope; the consumer wraps `net.Conn` themselves.
- WebSocket transport (`client.go:463-483`) — out of scope.
- HTTP-polling transport (`client.go:484-495`, `NewHTTPConn`) — out of scope.

## Cross-references

When in doubt, run:

```sh
grep -rn 'proxy\|Proxy\|PROXY' ../reverse_ssh/internal/client/
grep -rn 'wauth' ../reverse_ssh/
```

The full proxy-related catalog is also documented in the conversation history that produced these files; if revisiting an architectural decision, search the project's git log for messages referencing `auto-proxy` or `WinINET`.
