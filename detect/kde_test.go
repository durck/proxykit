package detect

import (
	"runtime"
	"slices"
	"strings"
	"testing"
)

func TestParseKDEProxyValue(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", ""},
		{"whitespace only", "   ", ""},
		{"scheme space form", "http://127.0.0.1 8080", "127.0.0.1:8080"},
		{"scheme colon form", "http://127.0.0.1:8080", "127.0.0.1:8080"},
		{"no scheme space form", "127.0.0.1 8080", "127.0.0.1:8080"},
		{"no scheme colon form", "127.0.0.1:8080", "127.0.0.1:8080"},
		{"socks scheme", "socks://10.0.0.1 1080", "10.0.0.1:1080"},
		{"bare host no port", "myproxy", "myproxy"},
		{"ipv6 colon form", "http://[::1]:8080", "[::1]:8080"},
		{"ipv6 space form", "http://[::1] 8080", "[::1]:8080"},
		{"userinfo space form", "http://user:pass@host 8080", "user:pass@host:8080"},
		{"userinfo colon form", "http://user:pass@host:8080", "user:pass@host:8080"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := parseKDEProxyValue(tc.in); got != tc.want {
				t.Errorf("parseKDEProxyValue(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestParseKioslaverc(t *testing.T) {
	cases := []struct {
		name     string
		in       string
		wantURLs []string
	}{
		{"proxytype 0 (none)", "[Proxy Settings]\nProxyType=0\nhttpProxy=http://h 8080", nil},
		{"proxytype 2 (PAC)", "[Proxy Settings]\nProxyType=2\nhttpProxy=http://h 8080", nil},
		{"proxytype 3 (WPAD)", "[Proxy Settings]\nProxyType=3\nhttpProxy=http://h 8080", nil},
		{"proxytype 4 (env)", "[Proxy Settings]\nProxyType=4\nhttpProxy=http://h 8080", nil},
		{"proxytype missing", "[Proxy Settings]\nhttpProxy=http://h 8080", nil},
		{"no proxy section", "[General]\nfoo=bar", nil},
		{
			"manual http only space form",
			"[Proxy Settings]\nProxyType=1\nhttpProxy=http://127.0.0.1 8080",
			[]string{"http://127.0.0.1:8080"},
		},
		{
			"manual all three distinct",
			"[Proxy Settings]\nProxyType=1\nhttpProxy=http://h1 8080\nhttpsProxy=http://h2 8443\nsocksProxy=socks://h3 1080",
			[]string{"http://h1:8080", "http://h2:8443", "socks5://h3:1080"},
		},
		{
			"manual http and https same coalesced",
			"[Proxy Settings]\nProxyType=1\nhttpProxy=http://p 8080\nhttpsProxy=http://p 8080",
			[]string{"http://p:8080"},
		},
		{
			"manual socks only",
			"[Proxy Settings]\nProxyType=1\nsocksProxy=socks://10.0.0.1 1080",
			[]string{"socks5://10.0.0.1:1080"},
		},
		{
			"manual socks colon form",
			"[Proxy Settings]\nProxyType=1\nsocksProxy=socks://10.0.0.1:1080",
			[]string{"socks5://10.0.0.1:1080"},
		},
		{
			"httpProxy in non-matching section ignored",
			"[General]\nhttpProxy=http://bad 9999\n[Proxy Settings]\nProxyType=1\nhttpProxy=http://good 8080",
			[]string{"http://good:8080"},
		},
		{
			"manual colon form",
			"[Proxy Settings]\nProxyType=1\nhttpProxy=http://127.0.0.1:8080",
			[]string{"http://127.0.0.1:8080"},
		},
		{
			"manual empty values",
			"[Proxy Settings]\nProxyType=1\nhttpProxy=\nhttpsProxy=\nsocksProxy=",
			nil,
		},
		{
			"section among other groups",
			"[General]\nfoo=bar\n\n[Proxy Settings]\nProxyType=1\nhttpProxy=http://proxy 3128\n\n[Other]\nbaz=qux",
			[]string{"http://proxy:3128"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cs := parseKioslaverc(tc.in)
			gotURLs := make([]string, len(cs))
			for i, c := range cs {
				gotURLs[i] = c.URL
				if c.From != "linux/kde" {
					t.Errorf("From = %q, want linux/kde", c.From)
				}
			}
			if !slices.Equal(gotURLs, tc.wantURLs) {
				t.Errorf("URLs = %v, want %v", gotURLs, tc.wantURLs)
			}
		})
	}
}

func TestParseKioslaverc_UserInfo(t *testing.T) {
	cs := parseKioslaverc("[Proxy Settings]\nProxyType=1\nhttpProxy=http://alice:s3cret@proxy 8080")
	if len(cs) != 1 {
		t.Fatalf("got %d candidates, want 1: %v", len(cs), cs)
	}
	c := cs[0]
	if c.User != "alice" || c.Pass != "s3cret" {
		t.Errorf("User/Pass = %q/%q, want alice/s3cret", c.User, c.Pass)
	}
	if c.URL != "http://proxy:8080" {
		t.Errorf("URL = %q, want http://proxy:8080 (userinfo stripped)", c.URL)
	}
	if strings.Contains(c.URL, "s3cret") {
		t.Errorf("URL %q still contains the password", c.URL)
	}
}

// TestParseKioslaverc_CRLF confirms Windows-style line endings (a file
// edited on another OS) are handled — TrimSpace strips the trailing \r.
func TestParseKioslaverc_CRLF(t *testing.T) {
	cs := parseKioslaverc("[Proxy Settings]\r\nProxyType=1\r\nhttpProxy=http://127.0.0.1 8080\r\n")
	if len(cs) != 1 || cs[0].URL != "http://127.0.0.1:8080" {
		t.Fatalf("CRLF content: got %v, want one http://127.0.0.1:8080", cs)
	}
}

// TestKDEDetector_NonLinuxNoop verifies the !linux stub silently
// returns no candidates and no error.
func TestKDEDetector_NonLinuxNoop(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("Linux host — exercises the kioslaverc path instead")
	}
	cs, err := KDEDetector{}.Detect()
	if err != nil {
		t.Errorf("Detect err = %v, want nil", err)
	}
	if len(cs) != 0 {
		t.Errorf("Detect = %v, want empty", cs)
	}
}

// TestKDEDetector_DefaultRegistration confirms the build-tag machinery —
// KDEDetector is in detect.Default on Linux but not on other platforms.
func TestKDEDetector_DefaultRegistration(t *testing.T) {
	found := false
	for _, d := range Default {
		if _, ok := d.(KDEDetector); ok {
			found = true
			break
		}
	}
	want := runtime.GOOS == "linux"
	if found != want {
		t.Errorf("KDEDetector in detect.Default = %v, want %v (GOOS=%s)", found, want, runtime.GOOS)
	}
}
