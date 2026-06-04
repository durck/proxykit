package detect

import (
	"errors"
	"reflect"
	"runtime"
	"testing"
)

// TestWinHTTPDetector_NonWindowsNoop verifies the !windows stub silently
// returns no candidates and no error.
func TestWinHTTPDetector_NonWindowsNoop(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows host — exercises the registry/API path in another test")
	}
	cs, err := WinHTTPDetector{}.Detect()
	if err != nil {
		t.Errorf("Detect err = %v, want nil", err)
	}
	if len(cs) != 0 {
		t.Errorf("Detect = %v, want empty", cs)
	}
}

// TestWinHTTPDetector_WindowsSmoke asserts the HKLM registry read and the
// WinHttpGetIEProxyConfigForCurrentUser call run without panicking on
// Windows. The host's actual proxy state is implementation-defined, so we
// only verify the contract: at most four candidates (HKLM/IE × proxy/PAC),
// de-duplicated, each tagged "winhttp" with exactly one of URL/PACURL set,
// and no error.
func TestWinHTTPDetector_WindowsSmoke(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-only")
	}
	cs, err := WinHTTPDetector{}.Detect()
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(cs) > 4 {
		t.Errorf("got %d candidates, want at most 4: %v", len(cs), cs)
	}
	seen := map[string]struct{}{}
	for _, c := range cs {
		if c.From != "winhttp" {
			t.Errorf("From = %q, want winhttp", c.From)
		}
		if (c.URL == "") == (c.PACURL == "") {
			t.Errorf("candidate must set exactly one of URL/PACURL: %+v", c)
		}
		key := "proxy:" + c.URL
		if c.PACURL != "" {
			key = "pac:" + c.PACURL
		}
		if _, dup := seen[key]; dup {
			t.Errorf("duplicate candidate %q not de-duplicated: %v", key, cs)
		}
		seen[key] = struct{}{}
	}
}

// TestWinHTTPDetector_DefaultRegistration confirms the build-tag
// machinery — WinHTTPDetector is in detect.Default on Windows but not on
// other platforms.
func TestWinHTTPDetector_DefaultRegistration(t *testing.T) {
	found := false
	for _, d := range Default {
		if _, ok := d.(WinHTTPDetector); ok {
			found = true
			break
		}
	}
	want := runtime.GOOS == "windows"
	if found != want {
		t.Errorf("WinHTTPDetector in detect.Default = %v, want %v (GOOS=%s)", found, want, runtime.GOOS)
	}
}

// TestMergeWinHTTPSources covers the platform-agnostic orchestration of
// the WinHTTP sources: proxy ordering (HKLM first), PAC surfacing,
// per-kind de-duplication, and the error-precedence rule (an HKLM read
// error is surfaced only when nothing at all was produced).
func TestMergeWinHTTPSources(t *testing.T) {
	errBoom := errors.New("boom")
	cases := []struct {
		name    string
		hklm    string
		hklmErr error
		ieProxy string
		hklmPAC string
		iePAC   string
		want    []Candidate
		wantErr error
	}{
		{"both empty", "", nil, "", "", "", nil, nil},
		{"hklm proxy only", "http://m:8080", nil, "", "", "",
			[]Candidate{{URL: "http://m:8080", From: "winhttp"}}, nil},
		{"ie proxy only", "", nil, "http://u:8080", "", "",
			[]Candidate{{URL: "http://u:8080", From: "winhttp"}}, nil},
		{"both proxies distinct, hklm first", "http://m:8080", nil, "http://u:8080", "", "",
			[]Candidate{{URL: "http://m:8080", From: "winhttp"}, {URL: "http://u:8080", From: "winhttp"}}, nil},
		{"duplicate proxy deduped", "http://same:8080", nil, "http://same:8080", "", "",
			[]Candidate{{URL: "http://same:8080", From: "winhttp"}}, nil},
		{"pac from hklm", "", nil, "", "http://wpad/h.pac", "",
			[]Candidate{{PACURL: "http://wpad/h.pac", From: "winhttp"}}, nil},
		{"pac from ie", "", nil, "", "", "http://wpad/i.pac",
			[]Candidate{{PACURL: "http://wpad/i.pac", From: "winhttp"}}, nil},
		{"duplicate pac deduped", "", nil, "", "http://wpad/x.pac", "http://wpad/x.pac",
			[]Candidate{{PACURL: "http://wpad/x.pac", From: "winhttp"}}, nil},
		{"proxy then pac (proxies first)", "http://m:8080", nil, "", "http://wpad/h.pac", "",
			[]Candidate{{URL: "http://m:8080", From: "winhttp"}, {PACURL: "http://wpad/h.pac", From: "winhttp"}}, nil},
		{"hklm error suppressed when ie proxy present", "", errBoom, "http://u:8080", "", "",
			[]Candidate{{URL: "http://u:8080", From: "winhttp"}}, nil},
		{"hklm error suppressed when pac present", "", errBoom, "", "", "http://wpad/i.pac",
			[]Candidate{{PACURL: "http://wpad/i.pac", From: "winhttp"}}, nil},
		{"hklm error and nothing found, error surfaced", "", errBoom, "", "", "", nil, errBoom},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := mergeWinHTTPSources(tc.hklm, tc.hklmErr, tc.ieProxy, tc.hklmPAC, tc.iePAC)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("candidates = %v, want %v", got, tc.want)
			}
		})
	}
}
