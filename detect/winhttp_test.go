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
// only verify the contract: at most one candidate per source (≤2),
// de-duplicated, each tagged "winhttp" with a non-empty URL, and no error.
func TestWinHTTPDetector_WindowsSmoke(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-only")
	}
	cs, err := WinHTTPDetector{}.Detect()
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(cs) > 2 {
		t.Errorf("got %d candidates, want at most 2: %v", len(cs), cs)
	}
	seen := map[string]struct{}{}
	for _, c := range cs {
		if c.From != "winhttp" {
			t.Errorf("From = %q, want winhttp", c.From)
		}
		if c.URL == "" {
			t.Errorf("empty URL in candidate %+v", c)
		}
		if _, dup := seen[c.URL]; dup {
			t.Errorf("duplicate URL %q not de-duplicated: %v", c.URL, cs)
		}
		seen[c.URL] = struct{}{}
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
// the two WinHTTP sources: ordering (HKLM first), de-duplication, and the
// error-precedence rule (an HKLM read error is surfaced only when neither
// source produced a URL, so an IE candidate is never discarded).
func TestMergeWinHTTPSources(t *testing.T) {
	errBoom := errors.New("boom")
	cases := []struct {
		name    string
		hklm    string
		hklmErr error
		ie      string
		want    []Candidate
		wantErr error
	}{
		{"both empty", "", nil, "", nil, nil},
		{"hklm only", "http://m:8080", nil, "",
			[]Candidate{{URL: "http://m:8080", From: "winhttp"}}, nil},
		{"ie only", "", nil, "http://u:8080",
			[]Candidate{{URL: "http://u:8080", From: "winhttp"}}, nil},
		{"both distinct, hklm first", "http://m:8080", nil, "http://u:8080",
			[]Candidate{{URL: "http://m:8080", From: "winhttp"}, {URL: "http://u:8080", From: "winhttp"}}, nil},
		{"duplicate deduped", "http://same:8080", nil, "http://same:8080",
			[]Candidate{{URL: "http://same:8080", From: "winhttp"}}, nil},
		{"hklm error suppressed when ie present", "", errBoom, "http://u:8080",
			[]Candidate{{URL: "http://u:8080", From: "winhttp"}}, nil},
		{"hklm error and nothing found, error surfaced", "", errBoom, "", nil, errBoom},
		// Defensive: readInternetSettingsProxy never returns ("url", err)
		// today, but the contract must still prefer the URL and suppress
		// the error if it ever does.
		{"hklm url and error, url wins", "http://m:8080", errBoom, "",
			[]Candidate{{URL: "http://m:8080", From: "winhttp"}}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := mergeWinHTTPSources(tc.hklm, tc.hklmErr, tc.ie)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("candidates = %v, want %v", got, tc.want)
			}
		})
	}
}
