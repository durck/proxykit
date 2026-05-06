package detect_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/durck/proxykit/detect"
)

// envKeys lists all *_PROXY variables that affect EnvDetector. The
// tests clear them all before applying their own settings to keep
// the matrix isolated from the host environment.
var envKeys = []string{
	"HTTP_PROXY", "http_proxy",
	"HTTPS_PROXY", "https_proxy",
	"NO_PROXY", "no_proxy",
	"REQUEST_METHOD", // suppresses CGI-mode handling in httpproxy
}

func clearEnv(t *testing.T) {
	t.Helper()
	for _, k := range envKeys {
		t.Setenv(k, "")
	}
}

func TestEnvDetector_Matrix(t *testing.T) {
	tests := []struct {
		name     string
		env      map[string]string
		wantURLs []string
	}{
		{
			name:     "no env",
			env:      map[string]string{},
			wantURLs: nil,
		},
		{
			name: "HTTP_PROXY only",
			env: map[string]string{
				"HTTP_PROXY": "http://proxy:8080",
			},
			wantURLs: []string{"http://proxy:8080"},
		},
		{
			name: "HTTPS_PROXY only",
			env: map[string]string{
				"HTTPS_PROXY": "http://proxy:8443",
			},
			wantURLs: []string{"http://proxy:8443"},
		},
		{
			name: "different upstream proxies",
			env: map[string]string{
				"HTTP_PROXY":  "http://p1:80",
				"HTTPS_PROXY": "http://p2:443",
			},
			wantURLs: []string{"http://p1:80", "http://p2:443"},
		},
		{
			name: "same URL coalesced",
			env: map[string]string{
				"HTTP_PROXY":  "http://proxy:8080",
				"HTTPS_PROXY": "http://proxy:8080",
			},
			wantURLs: []string{"http://proxy:8080"},
		},
		{
			name: "lowercase only",
			env: map[string]string{
				"http_proxy": "http://lower:8080",
			},
			wantURLs: []string{"http://lower:8080"},
		},
		// Note: relative precedence between HTTP_PROXY and http_proxy
		// when both are set is platform-dependent — Windows env vars
		// are case-insensitive (the second Setenv overwrites the
		// first regardless of case), so testing it here would be
		// flaky. httpproxy.FromEnvironment uses upper first, lower
		// fallback per the libcurl convention.
		{
			name: "socks5 in HTTPS_PROXY",
			env: map[string]string{
				"HTTPS_PROXY": "socks5://socks:1080",
			},
			wantURLs: []string{"socks5://socks:1080"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clearEnv(t)
			for k, v := range tt.env {
				t.Setenv(k, v)
			}

			cs, err := detect.EnvDetector{}.Detect()
			if err != nil {
				t.Fatalf("Detect: %v", err)
			}

			gotURLs := make([]string, len(cs))
			for i, c := range cs {
				gotURLs[i] = c.URL
				if c.From != "env" {
					t.Errorf("From = %q, want env", c.From)
				}
			}
			if !slices.Equal(gotURLs, tt.wantURLs) {
				t.Errorf("URLs = %v, want %v", gotURLs, tt.wantURLs)
			}
		})
	}
}

func TestEnvDetector_UserInfo(t *testing.T) {
	clearEnv(t)
	t.Setenv("HTTP_PROXY", "http://alice:s3cret@proxy:8080")

	cs, err := detect.EnvDetector{}.Detect()
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(cs) != 1 {
		t.Fatalf("got %d candidates, want 1: %v", len(cs), cs)
	}
	c := cs[0]
	if c.User != "alice" {
		t.Errorf("User = %q, want alice", c.User)
	}
	if c.Pass != "s3cret" {
		t.Errorf("Pass = %q, want s3cret", c.Pass)
	}
	if strings.Contains(c.URL, "alice") || strings.Contains(c.URL, "s3cret") {
		t.Errorf("URL %q still contains userinfo", c.URL)
	}
	if c.URL != "http://proxy:8080" {
		t.Errorf("URL = %q, want http://proxy:8080", c.URL)
	}
}

func TestEnvDetector_UserOnlyNoPassword(t *testing.T) {
	clearEnv(t)
	t.Setenv("HTTP_PROXY", "http://alice@proxy:8080")

	cs, err := detect.EnvDetector{}.Detect()
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(cs) != 1 {
		t.Fatalf("got %d candidates, want 1: %v", len(cs), cs)
	}
	c := cs[0]
	if c.User != "alice" {
		t.Errorf("User = %q, want alice", c.User)
	}
	if c.Pass != "" {
		t.Errorf("Pass = %q, want empty", c.Pass)
	}
	if c.URL != "http://proxy:8080" {
		t.Errorf("URL = %q, want http://proxy:8080", c.URL)
	}
}

func TestAll_IncludesEnv(t *testing.T) {
	clearEnv(t)
	t.Setenv("HTTP_PROXY", "http://only-via-all:8080")

	cs, err := detect.All()
	if err != nil {
		t.Fatalf("All: %v", err)
	}

	for _, c := range cs {
		if c.URL == "http://only-via-all:8080" && c.From == "env" {
			return
		}
	}
	t.Errorf("env-detected candidate not present in All output: %v", cs)
}

func TestAll_DefaultIncludesEnvDetector(t *testing.T) {
	found := false
	for _, d := range detect.Default {
		if _, ok := d.(detect.EnvDetector); ok {
			found = true
			break
		}
	}
	if !found {
		t.Error("EnvDetector not registered in detect.Default")
	}
}
