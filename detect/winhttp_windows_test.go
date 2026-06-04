//go:build windows

package detect

import (
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// TestProxyConfigStructLayout guards the riskiest part of the syscall
// binding: winHTTPCurrentUserIEProxyConfig must match the C ABI of
// WINHTTP_CURRENT_USER_IE_PROXY_CONFIG — a 4-byte BOOL padded to pointer
// alignment, then three pointers, i.e. four pointer-sized words (32 bytes
// on amd64, 16 on 386). A field reorder or type change would break the
// API call silently; this fails the build instead.
func TestProxyConfigStructLayout(t *testing.T) {
	ptr := unsafe.Sizeof(uintptr(0))
	want := 4 * ptr
	if got := unsafe.Sizeof(winHTTPCurrentUserIEProxyConfig{}); got != want {
		t.Errorf("sizeof(winHTTPCurrentUserIEProxyConfig) = %d, want %d (ptr=%d)", got, want, ptr)
	}
}

// TestProxyURLFromUTF16 exercises the decode+parse success path of the
// WinHttpGetIEProxyConfigForCurrentUser branch without a live API call: a
// UTF-16 lpszProxy string is decoded and run through the WinINET-format
// parser. A no-proxy machine (the usual CI box) never reaches this path
// via the smoke test, so it is covered explicitly here.
func TestProxyURLFromUTF16(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"single host:port", "10.0.0.1:8080", "http://10.0.0.1:8080"},
		{"per-scheme http preferred", "http=10.0.0.1:8080;https=10.0.0.1:8443", "http://10.0.0.1:8080"},
		{"per-scheme socks", "socks=10.0.0.1:1080", "socks5://10.0.0.1:1080"},
		{"empty string", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := windows.UTF16PtrFromString(tc.in)
			if err != nil {
				t.Fatalf("UTF16PtrFromString(%q): %v", tc.in, err)
			}
			if got := proxyURLFromUTF16(p); got != tc.want {
				t.Errorf("proxyURLFromUTF16(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}

	if got := proxyURLFromUTF16(nil); got != "" {
		t.Errorf("proxyURLFromUTF16(nil) = %q, want \"\"", got)
	}
}
