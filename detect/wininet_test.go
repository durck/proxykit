package detect

import (
	"runtime"
	"testing"
)

func TestParseWinINETProxyString(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", ""},
		{"whitespace only", "   ", ""},
		{"single host:port", "127.0.0.1:8080", "http://127.0.0.1:8080"},
		{"single with whitespace", "  proxy.local:3128  ", "http://proxy.local:3128"},
		{"per-scheme http preferred", "http=10.0.0.1:8080;https=10.0.0.1:8443", "http://10.0.0.1:8080"},
		{"per-scheme https when no http", "https=10.0.0.1:8443;ftp=10.0.0.1:21", "http://10.0.0.1:8443"},
		{"per-scheme socks", "socks=10.0.0.1:1080", "socks5://10.0.0.1:1080"},
		{"per-scheme socks fallback", "ftp=10.0.0.1:21;socks=10.0.0.1:1080", "socks5://10.0.0.1:1080"},
		{"per-scheme order preserves http over socks", "socks=10.0.0.1:1080;http=10.0.0.1:8080", "http://10.0.0.1:8080"},
		{"per-scheme only ftp ignored", "ftp=10.0.0.1:21", ""},
		{"per-scheme malformed segment", "http=;https=10.0.0.1:8443", "http://10.0.0.1:8443"},
		{"per-scheme uppercase keys", "HTTP=10.0.0.1:8080", "http://10.0.0.1:8080"},
		{"per-scheme stray semicolons", ";;http=10.0.0.1:8080;;", "http://10.0.0.1:8080"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseWinINETProxyString(tc.in)
			if got != tc.want {
				t.Errorf("parseWinINETProxyString(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestWinINETDetector_NonWindowsNoop verifies the !windows stub
// silently returns no candidates and no error.
func TestWinINETDetector_NonWindowsNoop(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows host — exercises the registry path in another test")
	}
	cs, err := WinINETDetector{}.Detect()
	if err != nil {
		t.Errorf("Detect err = %v, want nil", err)
	}
	if len(cs) != 0 {
		t.Errorf("Detect = %v, want empty", cs)
	}
}

// TestWinINETDetector_WindowsSmoke asserts the registry path runs
// without panicking on Windows. The host's actual proxy state is
// implementation-defined — anything from "no key" through
// "ProxyEnable=0" through a populated ProxyServer is acceptable.
// We just verify the call returns either zero or one candidate and
// no error.
func TestWinINETDetector_WindowsSmoke(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-only")
	}
	cs, err := WinINETDetector{}.Detect()
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(cs) > 1 {
		t.Errorf("got %d candidates, want at most 1: %v", len(cs), cs)
	}
	for _, c := range cs {
		if c.From != "wininet" {
			t.Errorf("From = %q, want wininet", c.From)
		}
		if c.URL == "" {
			t.Errorf("empty URL in candidate %+v", c)
		}
	}
}

// TestWinINETDetector_DefaultRegistration confirms the build-tag
// machinery — WinINETDetector is in detect.Default on Windows but
// not on other platforms.
func TestWinINETDetector_DefaultRegistration(t *testing.T) {
	found := false
	for _, d := range Default {
		if _, ok := d.(WinINETDetector); ok {
			found = true
			break
		}
	}
	want := runtime.GOOS == "windows"
	if found != want {
		t.Errorf("WinINETDetector in detect.Default = %v, want %v (GOOS=%s)", found, want, runtime.GOOS)
	}
}
