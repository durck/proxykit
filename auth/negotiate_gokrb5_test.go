//go:build !windows && !proxykit_nokerberos

package auth

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

func TestSplitCCacheName(t *testing.T) {
	cases := []struct {
		in       string
		wantType string
		wantRes  string
	}{
		{"/tmp/krb5cc_1000", "FILE", "/tmp/krb5cc_1000"},                    // bare absolute path
		{"FILE:/tmp/krb5cc_1000", "FILE", "/tmp/krb5cc_1000"},              // explicit FILE
		{"file:/tmp/x", "FILE", "/tmp/x"},                                  // lower-case prefix
		{"DIR:/run/user/1000/krb5cc", "DIR", "/run/user/1000/krb5cc"},      // DIR collection
		{"DIR::/run/user/1000/krb5cc/tktAB", "DIR", ":/run/user/1000/krb5cc/tktAB"}, // DIR:: subsidiary
		{"KEYRING:persistent:1000:1000", "KEYRING", "persistent:1000:1000"},
		{"KCM:1000", "KCM", "1000"},                                        // recognised but unsupported type
		{"relative/path/no/colon", "FILE", "relative/path/no/colon"},       // no colon at all
		{"weird:value", "FILE", "weird:value"},                            // unknown TYPE: prefix → treated as a FILE path
	}
	for _, c := range cases {
		gotType, gotRes := splitCCacheName(c.in)
		if gotType != c.wantType || gotRes != c.wantRes {
			t.Errorf("splitCCacheName(%q) = (%q, %q), want (%q, %q)", c.in, gotType, gotRes, c.wantType, c.wantRes)
		}
	}
}

func TestResolveCCache_UnsupportedType(t *testing.T) {
	t.Setenv("KRB5CCNAME", "KCM:1000")
	_, err := resolveCCache()
	if err == nil || !strings.Contains(err.Error(), "unsupported ccache type") {
		t.Fatalf("resolveCCache() error = %v, want unsupported ccache type", err)
	}
}

func TestResolveCCache_MissingFile(t *testing.T) {
	t.Setenv("KRB5CCNAME", "FILE:"+filepath.Join(t.TempDir(), "nonexistent"))
	if _, err := resolveCCache(); err == nil {
		t.Fatal("resolveCCache() = nil error, want missing-file error")
	}
}

func TestResolveCCache_DirMissingPrimary(t *testing.T) {
	t.Setenv("KRB5CCNAME", "DIR:"+t.TempDir())
	_, err := resolveCCache()
	if err == nil || !strings.Contains(err.Error(), "primary") {
		t.Fatalf("resolveCCache() error = %v, want DIR primary error", err)
	}
}

// TestResolveCCache_DirSubsidiary covers the DIR:: form, which names a
// specific subsidiary file directly: loadDirCCache must strip the leading
// ':' and load that path without the /primary indirection.
func TestResolveCCache_DirSubsidiary(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "tktMISSING")
	t.Setenv("KRB5CCNAME", "DIR::"+missing)
	_, err := resolveCCache()
	if err == nil {
		t.Fatal("resolveCCache() = nil error, want missing-subsidiary error")
	}
	if strings.Contains(err.Error(), "primary") {
		t.Errorf("DIR:: form must not consult primary; error = %q", err.Error())
	}
}

// TestNegotiate_NoCredentials proves the gokrb5 backend is wired in (not
// the ErrUnsupported stub) yet fails cleanly without a krb5.conf or
// ccache: a single-round (done=true), "negotiate:"-prefixed error that
// does NOT wrap errors.ErrUnsupported.
func TestNegotiate_NoCredentials(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KRB5_CONFIG", filepath.Join(dir, "no-krb5.conf"))
	t.Setenv("KRB5CCNAME", "FILE:"+filepath.Join(dir, "no-ccache"))

	_, done, err := Negotiate("HTTP/proxy.example.com").Headers(nil)
	if err == nil {
		t.Fatal("Headers() = nil error, want failure without credentials")
	}
	if !done {
		t.Error("done = false, want true (Negotiate is single-round)")
	}
	if !strings.HasPrefix(err.Error(), "negotiate:") {
		t.Errorf("error %q lacks the negotiate: prefix", err.Error())
	}
	if errors.Is(err, errors.ErrUnsupported) {
		t.Errorf("error wraps ErrUnsupported, but the gokrb5 backend is built in: %v", err)
	}
}
