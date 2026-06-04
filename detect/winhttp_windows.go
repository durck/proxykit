//go:build windows

package detect

import (
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// WinHTTPDetector reads the per-machine WinHTTP proxy configuration on
// Windows from two sources that complement the per-user HKCU
// WinINETDetector:
//
//  1. The HKLM "Internet Settings" hive (ProxyEnable + ProxyServer) —
//     the per-machine manual proxy.
//  2. WinHttpGetIEProxyConfigForCurrentUser — the WinHTTP view of the
//     current user's IE proxy (its lpszProxy field).
//
// AutoConfigURL (PAC) and AutoDetect (WPAD) are out of scope (see #14).
type WinHTTPDetector struct{}

func init() {
	Default = append(Default, WinHTTPDetector{})
}

// Detect returns at most one candidate per source — the HKLM hive and
// the WinHTTP IE config — de-duplicated by URL and tagged "winhttp". A
// missing key, disabled proxy, or absent IE config is "nothing
// configured", not an error. The two sources are independent; see
// mergeWinHTTPSources for how a genuine HKLM read error is handled.
func (WinHTTPDetector) Detect() ([]Candidate, error) {
	hklm, hklmErr := readInternetSettingsProxy(registry.LOCAL_MACHINE, "winhttp/hklm")
	return mergeWinHTTPSources(hklm, hklmErr, winHTTPIEProxy())
}

var (
	modwinhttp                  = windows.NewLazySystemDLL("winhttp.dll")
	procWinHTTPGetIEProxyConfig = modwinhttp.NewProc("WinHttpGetIEProxyConfigForCurrentUser")

	modkernel32    = windows.NewLazySystemDLL("kernel32.dll")
	procGlobalFree = modkernel32.NewProc("GlobalFree")
)

// winHTTPCurrentUserIEProxyConfig mirrors the C
// WINHTTP_CURRENT_USER_IE_PROXY_CONFIG. fAutoDetect is a 32-bit BOOL;
// the following pointers are naturally aligned, matching the C layout on
// both 386 and amd64.
type winHTTPCurrentUserIEProxyConfig struct {
	fAutoDetect       int32
	lpszAutoConfigURL *uint16
	lpszProxy         *uint16
	lpszProxyBypass   *uint16
}

// winHTTPIEProxy returns the parsed proxy URL from the lpszProxy field of
// WinHttpGetIEProxyConfigForCurrentUser. A FALSE return — typically
// ERROR_FILE_NOT_FOUND when no per-user IE config exists — yields "".
// The API allocates the LPWSTR fields, which the caller frees with
// GlobalFree.
func winHTTPIEProxy() string {
	var cfg winHTTPCurrentUserIEProxyConfig
	r1, _, _ := procWinHTTPGetIEProxyConfig.Call(uintptr(unsafe.Pointer(&cfg)))
	if r1 == 0 {
		return ""
	}
	defer globalFree(unsafe.Pointer(cfg.lpszAutoConfigURL))
	defer globalFree(unsafe.Pointer(cfg.lpszProxy))
	defer globalFree(unsafe.Pointer(cfg.lpszProxyBypass))

	return proxyURLFromUTF16(cfg.lpszProxy)
}

// proxyURLFromUTF16 decodes a proxy LPWSTR and parses it. The IE proxy
// config returned by WinHttpGetIEProxyConfigForCurrentUser uses the same
// "host:port" / "scheme=host:port;..." format as the WinINET ProxyServer
// registry value, so parseWinINETProxyString applies unchanged. A nil
// pointer (no proxy configured) yields "".
func proxyURLFromUTF16(p *uint16) string {
	if p == nil {
		return ""
	}
	return parseWinINETProxyString(windows.UTF16PtrToString(p))
}

// globalFree releases a buffer allocated by a Win32 API. A nil pointer
// is a no-op.
func globalFree(p unsafe.Pointer) {
	if p == nil {
		return
	}
	_, _, _ = procGlobalFree.Call(uintptr(p))
}
