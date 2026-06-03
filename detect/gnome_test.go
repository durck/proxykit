package detect

import (
	"runtime"
	"slices"
	"testing"
)

func TestUnquoteGSettings(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"single-quoted string", "'manual'", "manual"},
		{"trailing newline", "'manual'\n", "manual"},
		{"empty quoted", "''", ""},
		{"host", "'proxy.example.com'", "proxy.example.com"},
		{"bare int", "8080", "8080"},
		{"uint32 tag", "uint32 8080", "8080"},
		{"int32 tag", "int32 8080", "8080"},
		{"uint64 tag", "uint64 8080", "8080"},
		{"double tag", "double 1.5", "1.5"},
		{"explicit boolean tag", "boolean true", "true"},
		{"boolean true", "true", "true"},
		{"boolean false", "false", "false"},
		{"surrounding whitespace", "  'spaced'  ", "spaced"},
		{"escaped single quote", `'it\'s'`, "it's"},
		{"double-quoted with apostrophe", `"a'b"`, "a'b"},
		{"escaped backslash", `'pa\\ss'`, `pa\ss`},
		{"escaped double quote in double-quoted", `"a\"b"`, `a"b`},
		{"empty input", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := unquoteGSettings(tc.in); got != tc.want {
				t.Errorf("unquoteGSettings(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestGnomeCandidates(t *testing.T) {
	cases := []struct {
		name string
		in   gnomeProxy
		want []Candidate
	}{
		{"mode none", gnomeProxy{Mode: "none", HTTPHost: "h", HTTPPort: "8080"}, nil},
		{"mode auto", gnomeProxy{Mode: "auto", HTTPHost: "h", HTTPPort: "8080"}, nil},
		{"mode empty", gnomeProxy{Mode: "", HTTPHost: "h", HTTPPort: "8080"}, nil},
		{
			"manual http only",
			gnomeProxy{Mode: "manual", HTTPHost: "proxy", HTTPPort: "8080"},
			[]Candidate{{URL: "http://proxy:8080", From: "linux/gnome"}},
		},
		{
			"manual all three distinct",
			gnomeProxy{
				Mode:     "manual",
				HTTPHost: "h1", HTTPPort: "8080",
				HTTPSHost: "h2", HTTPSPort: "8443",
				SOCKSHost: "h3", SOCKSPort: "1080",
			},
			[]Candidate{
				{URL: "http://h1:8080", From: "linux/gnome"},
				{URL: "http://h2:8443", From: "linux/gnome"},
				{URL: "socks5://h3:1080", From: "linux/gnome"},
			},
		},
		{
			"manual http and https same endpoint coalesced",
			gnomeProxy{
				Mode:     "manual",
				HTTPHost: "p", HTTPPort: "8080",
				HTTPSHost: "p", HTTPSPort: "8080",
			},
			[]Candidate{{URL: "http://p:8080", From: "linux/gnome"}},
		},
		{
			"manual http with auth",
			gnomeProxy{
				Mode:     "manual",
				HTTPHost: "proxy", HTTPPort: "8080",
				UseAuth: true, AuthUser: "alice", AuthPass: "s3cret",
			},
			[]Candidate{{URL: "http://proxy:8080", User: "alice", Pass: "s3cret", From: "linux/gnome"}},
		},
		{
			"auth values present but use-authentication off",
			gnomeProxy{
				Mode:     "manual",
				HTTPHost: "proxy", HTTPPort: "8080",
				UseAuth: false, AuthUser: "alice", AuthPass: "s3cret",
			},
			[]Candidate{{URL: "http://proxy:8080", From: "linux/gnome"}},
		},
		{
			"use-authentication on but no user",
			gnomeProxy{
				Mode:     "manual",
				HTTPHost: "proxy", HTTPPort: "8080",
				UseAuth: true, AuthUser: "",
			},
			[]Candidate{{URL: "http://proxy:8080", From: "linux/gnome"}},
		},
		{
			"http port zero skipped, https kept",
			gnomeProxy{
				Mode:     "manual",
				HTTPHost: "h", HTTPPort: "0",
				HTTPSHost: "h", HTTPSPort: "8443",
			},
			[]Candidate{{URL: "http://h:8443", From: "linux/gnome"}},
		},
		{
			"http host empty skipped",
			gnomeProxy{Mode: "manual", HTTPHost: "", HTTPPort: "8080"},
			nil,
		},
		{
			"http port empty skipped",
			gnomeProxy{Mode: "manual", HTTPHost: "h", HTTPPort: ""},
			nil,
		},
		{
			"socks only",
			gnomeProxy{Mode: "manual", SOCKSHost: "socks", SOCKSPort: "1080"},
			[]Candidate{{URL: "socks5://socks:1080", From: "linux/gnome"}},
		},
		{
			"ipv6 host bracketed",
			gnomeProxy{Mode: "manual", HTTPHost: "::1", HTTPPort: "8080"},
			[]Candidate{{URL: "http://[::1]:8080", From: "linux/gnome"}},
		},
		{
			"authed http and same https endpoint keeps authed",
			gnomeProxy{
				Mode:     "manual",
				HTTPHost: "p", HTTPPort: "8080",
				HTTPSHost: "p", HTTPSPort: "8080",
				UseAuth: true, AuthUser: "alice", AuthPass: "s3cret",
			},
			[]Candidate{{URL: "http://p:8080", User: "alice", Pass: "s3cret", From: "linux/gnome"}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := gnomeCandidates(tc.in)
			if !slices.Equal(got, tc.want) {
				t.Errorf("gnomeCandidates() = %+v, want %+v", got, tc.want)
			}
		})
	}
}

// TestGNOMEDetector_NonLinuxNoop verifies the !linux stub silently
// returns no candidates and no error.
func TestGNOMEDetector_NonLinuxNoop(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("Linux host — exercises the gsettings path instead")
	}
	cs, err := GNOMEDetector{}.Detect()
	if err != nil {
		t.Errorf("Detect err = %v, want nil", err)
	}
	if len(cs) != 0 {
		t.Errorf("Detect = %v, want empty", cs)
	}
}

// TestGNOMEDetector_DefaultRegistration confirms the build-tag
// machinery — GNOMEDetector is in detect.Default on Linux but not on
// other platforms.
func TestGNOMEDetector_DefaultRegistration(t *testing.T) {
	found := false
	for _, d := range Default {
		if _, ok := d.(GNOMEDetector); ok {
			found = true
			break
		}
	}
	want := runtime.GOOS == "linux"
	if found != want {
		t.Errorf("GNOMEDetector in detect.Default = %v, want %v (GOOS=%s)", found, want, runtime.GOOS)
	}
}
