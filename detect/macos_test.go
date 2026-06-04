package detect

import (
	"runtime"
	"slices"
	"testing"
)

func TestParseSCUtilProxy(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []Candidate
	}{
		{"empty", "", nil},
		{
			"no proxy, all disabled, nested exceptions ignored",
			`<dictionary> {
  ExceptionsList : <array> {
    0 : *.local
    1 : 169.254/16
  }
  FTPPassive : 1
  HTTPEnable : 0
  HTTPSEnable : 0
  SOCKSEnable : 0
}`,
			nil,
		},
		{
			"http only",
			`<dictionary> {
  HTTPEnable : 1
  HTTPProxy : proxy.example.com
  HTTPPort : 8080
}`,
			[]Candidate{{URL: "http://proxy.example.com:8080", From: "macos"}},
		},
		{
			"https only maps to http scheme",
			`<dictionary> {
  HTTPSEnable : 1
  HTTPSProxy : proxy.example.com
  HTTPSPort : 8443
}`,
			[]Candidate{{URL: "http://proxy.example.com:8443", From: "macos"}},
		},
		{
			"socks only",
			`<dictionary> {
  SOCKSEnable : 1
  SOCKSProxy : socks.example.com
  SOCKSPort : 1080
}`,
			[]Candidate{{URL: "socks5://socks.example.com:1080", From: "macos"}},
		},
		{
			"all three distinct, exceptions block ignored",
			`<dictionary> {
  ExceptionsList : <array> {
    0 : *.local
  }
  HTTPEnable : 1
  HTTPProxy : h1
  HTTPPort : 8080
  HTTPSEnable : 1
  HTTPSProxy : h2
  HTTPSPort : 8443
  SOCKSEnable : 1
  SOCKSProxy : h3
  SOCKSPort : 1080
}`,
			[]Candidate{
				{URL: "http://h1:8080", From: "macos"},
				{URL: "http://h2:8443", From: "macos"},
				{URL: "socks5://h3:1080", From: "macos"},
			},
		},
		{
			"http and https same endpoint coalesced",
			`<dictionary> {
  HTTPEnable : 1
  HTTPProxy : p
  HTTPPort : 8080
  HTTPSEnable : 1
  HTTPSProxy : p
  HTTPSPort : 8080
}`,
			[]Candidate{{URL: "http://p:8080", From: "macos"}},
		},
		{
			"PAC enabled only is out of scope",
			`<dictionary> {
  HTTPEnable : 0
  ProxyAutoConfigEnable : 1
  ProxyAutoConfigURLString : http://wpad.example.com/wpad.dat
}`,
			nil,
		},
		{
			"enabled but host missing",
			`<dictionary> {
  HTTPEnable : 1
  HTTPPort : 8080
}`,
			nil,
		},
		{
			"enabled but port zero",
			`<dictionary> {
  HTTPEnable : 1
  HTTPProxy : h
  HTTPPort : 0
}`,
			nil,
		},
		{
			"enabled but port value empty",
			`<dictionary> {
  HTTPEnable : 1
  HTTPProxy : h
  HTTPPort :
}`,
			nil,
		},
		{
			// Proxy keys exist ONLY inside a doubly-nested block (depth 3);
			// a parser that ignored brace depth would wrongly capture them.
			"keys inside nested block are not captured",
			`<dictionary> {
  Outer : <array> {
    0 : <dictionary> {
      HTTPEnable : 1
      HTTPProxy : nested
      HTTPPort : 8080
    }
  }
}`,
			nil,
		},
		{
			"host present but enable flag off",
			`<dictionary> {
  HTTPEnable : 0
  HTTPProxy : proxy.example.com
  HTTPPort : 8080
}`,
			nil,
		},
		{
			"ipv6 host bracketed",
			`<dictionary> {
  HTTPEnable : 1
  HTTPProxy : ::1
  HTTPPort : 8080
}`,
			[]Candidate{{URL: "http://[::1]:8080", From: "macos"}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseSCUtilProxy(tc.in)
			if !slices.Equal(got, tc.want) {
				t.Errorf("parseSCUtilProxy() = %+v, want %+v", got, tc.want)
			}
		})
	}
}

// TestMacOSDetector_NonDarwinNoop verifies the !darwin stub silently
// returns no candidates and no error.
func TestMacOSDetector_NonDarwinNoop(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skip("macOS host — exercises the scutil path instead")
	}
	cs, err := MacOSDetector{}.Detect()
	if err != nil {
		t.Errorf("Detect err = %v, want nil", err)
	}
	if len(cs) != 0 {
		t.Errorf("Detect = %v, want empty", cs)
	}
}

// TestMacOSDetector_DefaultRegistration confirms the build-tag machinery —
// MacOSDetector is in detect.Default on macOS but not on other platforms.
func TestMacOSDetector_DefaultRegistration(t *testing.T) {
	found := false
	for _, d := range Default {
		if _, ok := d.(MacOSDetector); ok {
			found = true
			break
		}
	}
	want := runtime.GOOS == "darwin"
	if found != want {
		t.Errorf("MacOSDetector in detect.Default = %v, want %v (GOOS=%s)", found, want, runtime.GOOS)
	}
}
