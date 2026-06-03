package detect

import (
	"runtime"
	"slices"
	"testing"
)

func TestParseEtcEnvironment(t *testing.T) {
	cases := []struct {
		name     string
		in       string
		wantURLs []string
	}{
		{"empty", "", nil},
		{"comments and blanks only", "# a comment\n\n   \n# another\n", nil},
		{
			"http_proxy double-quoted",
			`http_proxy="http://proxy:8080"`,
			[]string{"http://proxy:8080"},
		},
		{
			"HTTPS_PROXY unquoted uppercase",
			"HTTPS_PROXY=http://proxy:8443",
			[]string{"http://proxy:8443"},
		},
		{
			"both different",
			"http_proxy=http://p1:80\nhttps_proxy=http://p2:443",
			[]string{"http://p1:80", "http://p2:443"},
		},
		{
			"same URL coalesced",
			"http_proxy=http://proxy:8080\nhttps_proxy=http://proxy:8080",
			[]string{"http://proxy:8080"},
		},
		{
			"single-quoted value",
			"http_proxy='http://proxy:3128'",
			[]string{"http://proxy:3128"},
		},
		{
			"mixed-case key",
			"Http_Proxy=http://mixed:8080",
			[]string{"http://mixed:8080"},
		},
		{
			"no_proxy ignored",
			"no_proxy=localhost,127.0.0.1\nNO_PROXY=example.com",
			nil,
		},
		{
			"unrelated vars and bare lines ignored",
			"PATH=/usr/bin:/bin\nLANG=en_US.UTF-8\njust-a-bare-line\nhttp_proxy=http://proxy:8080",
			[]string{"http://proxy:8080"},
		},
		{
			"surrounding whitespace",
			"  http_proxy =  http://proxy:8080  ",
			[]string{"http://proxy:8080"},
		},
		{
			"whitespace inside quotes trimmed",
			`http_proxy="  http://proxy:8080  "`,
			[]string{"http://proxy:8080"},
		},
		{
			"socks5 in https_proxy preserved",
			"https_proxy=socks5://socks:1080",
			[]string{"socks5://socks:1080"},
		},
		{
			"last occurrence wins",
			"http_proxy=http://first:80\nhttp_proxy=http://second:80",
			[]string{"http://second:80"},
		},
		{
			"value with embedded equals (split on first =)",
			"http_proxy=http://proxy:8080/path?key=val",
			[]string{"http://proxy:8080/path?key=val"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cs := parseEtcEnvironment(tc.in)
			gotURLs := make([]string, len(cs))
			for i, c := range cs {
				gotURLs[i] = c.URL
				if c.From != "linux/etc-environment" {
					t.Errorf("From = %q, want linux/etc-environment", c.From)
				}
			}
			if !slices.Equal(gotURLs, tc.wantURLs) {
				t.Errorf("URLs = %v, want %v", gotURLs, tc.wantURLs)
			}
		})
	}
}

func TestParseEtcEnvironment_UserInfo(t *testing.T) {
	cs := parseEtcEnvironment(`http_proxy="http://alice:s3cret@proxy:8080"`)
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
}

// TestEtcEnvironmentDetector_NonLinuxNoop verifies the !linux stub
// silently returns no candidates and no error.
func TestEtcEnvironmentDetector_NonLinuxNoop(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("Linux host — exercises the /etc/environment path instead")
	}
	cs, err := EtcEnvironmentDetector{}.Detect()
	if err != nil {
		t.Errorf("Detect err = %v, want nil", err)
	}
	if len(cs) != 0 {
		t.Errorf("Detect = %v, want empty", cs)
	}
}

// TestEtcEnvironmentDetector_DefaultRegistration confirms the build-tag
// machinery — EtcEnvironmentDetector is in detect.Default on Linux but
// not on other platforms.
func TestEtcEnvironmentDetector_DefaultRegistration(t *testing.T) {
	found := false
	for _, d := range Default {
		if _, ok := d.(EtcEnvironmentDetector); ok {
			found = true
			break
		}
	}
	want := runtime.GOOS == "linux"
	if found != want {
		t.Errorf("EtcEnvironmentDetector in detect.Default = %v, want %v (GOOS=%s)", found, want, runtime.GOOS)
	}
}
