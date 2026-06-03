//go:build linux && !proxykit_nokerberos

package auth

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/jcmturner/gokrb5/v8/credentials"
)

// ccacheTestHex is the gokrb5 CCACHE_TEST vector (v4, one KDC-offset header
// field, principal testuser1@TEST.GOKRB5, 3 credentials).  It is inlined here
// to avoid a test-only import of github.com/jcmturner/gokrb5/v8/test/testdata.
const ccacheTestHex = "0504000c00010008000000060000000000000001000000010000000b544553542e474f4b5242350000000974657374757365723100000001000000010000000b544553542e474f4b5242350000000974657374757365723100000002000000020000000b544553542e474f4b524235000000066b72627467740000000b544553542e474f4b52423500120000002088b94319f2dcd1de20ebd3bf3174778769323bce76ef71fb37a8ba4be93c38df59665b8e59665b8e5967044e5967ad080040c1000000000000000000000000015a6182015630820152a003020105a10d1b0b544553542e474f4b524235a220301ea003020102a11730151b066b72627467741b0b544553542e474f4b524235a382011830820114a003020112a103020101a282010604820102ee32bb7e27ad6f71869be098c4002b291f370d26302c87ffa3eb670345a11fc113a9e5ab9e26ea659104b29e2a60c07dda559654c58aaf5f48bbb3bb9a238745861be336a0672554dac9b38126b2929ce9df2add185d1043c6dd89c7308b9def7b98ba7bcdcd1c00eeb5d99e273e1fe53b88c057106ec3dbcf2a86c38a4c1372418f1afb0227975747edf2172e23716ab5f6fa9a2ee5c0d94e9f66936df767498677861926812d1f887de6f44e5ebd93b63fd8313a499372ea9e889620bd0842bc8a8f8a17e5dea328c77b771cfcd49ac7afa4a9c7236efa30fec1b2072255543aee48cd935ece367e08d24f51bea4b407ace8ed7e67a8d5e1cb528eb16c7ebe7ac50000000000000001000000010000000b544553542e474f4b5242350000000974657374757365723100000000000000030000000c582d4341434845434f4e463a000000156b7262355f6363616368655f636f6e665f646174610000000a666173745f617661696c0000001e6b72627467742f544553542e474f4b52423540544553542e474f4b5242350000000000000000000000000000000000000000000000000000000000000000000000000000037965730000000000000001000000010000000b544553542e474f4b5242350000000974657374757365723100000001000000020000000b544553542e474f4b524235000000044854545000000010686f73742e746573742e676f6b726235001200000020fd325da3f905d743894e828de41b21af7876b6281b66d9e4bb2eefd64078b47659665b8e59665bce5967044e5967ad0800408900000000000000000000000001706182016c30820168a003020105a10d1b0b544553542e474f4b524235a2233021a003020101a11a30181b04485454501b10686f73742e746573742e676f6b726235a382012b30820127a003020112a103020101a282011904820115ad55d79858ce41647e835769b40540bc32ff4debe101217a7a024016697ee5ff758829940ca576905a260732c43c2996d96b83f9bff010fdbfc8f3bff51cef202a956f8d73d18c2c8865553f55229075270f42dca23d7618ff35e578a972d40746398efd478cf4f1094d99371273b3fbe5b95707011b446ff605ea8cb0e6631ea0ffdd7b562b5aa2de5dd455388e1aa18d8a3a8e81dab058e1b223410a752e5ec82797164dabafdbec8eeef7b072304e46d7d15b575f44cce69a368a9004612ba179b41d4655964933f7eb114a457aa1127291fc6d63deb271e5504de6fccca33260645ef5bd1ea301d74a8dbf751aa181ed92f5edb493d68222e1a34892035b88b6fb0ce104db23f7da22a8e73359d9c322b8e1cc00000000"

// TestAssembleCCacheBytes_NoCreds tests the pure assembly function with a
// hand-crafted principal ("user1@REALM") and no credentials.
func TestAssembleCCacheBytes_NoCreds(t *testing.T) {
	// Principal wire format (no file preamble): name_type=1, n=1,
	// realm="REALM"(5), comp[0]="user1"(5) — big-endian int32 lengths.
	princData := []byte{
		0x00, 0x00, 0x00, 0x01, // name_type = 1 (KRB_NT_PRINCIPAL)
		0x00, 0x00, 0x00, 0x01, // n_components = 1
		0x00, 0x00, 0x00, 0x05, // realm_len = 5
		'R', 'E', 'A', 'L', 'M',
		0x00, 0x00, 0x00, 0x05, // comp[0]_len = 5
		'u', 's', 'e', 'r', '1',
	}

	got := assembleCCacheBytes(princData, nil)

	// Result must begin with the v4 FILE ccache magic+version+hdr_len=0.
	wantPrefix := []byte{0x05, 0x04, 0x00, 0x00}
	if !bytes.HasPrefix(got, wantPrefix) {
		t.Fatalf("assembled[0:4] = % x, want % x", got[:4], wantPrefix)
	}
	// Remaining bytes must equal princData.
	if !bytes.Equal(got[4:], princData) {
		t.Errorf("assembled[4:] differs from princData")
	}

	cc := new(credentials.CCache)
	if err := cc.Unmarshal(got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if cc.DefaultPrincipal.Realm != "REALM" {
		t.Errorf("realm = %q, want REALM", cc.DefaultPrincipal.Realm)
	}
	if cc.DefaultPrincipal.PrincipalName.PrincipalNameString() != "user1" {
		t.Errorf("principal = %q, want user1", cc.DefaultPrincipal.PrincipalName.PrincipalNameString())
	}
	if len(cc.Credentials) != 0 {
		t.Errorf("len(credentials) = %d, want 0", len(cc.Credentials))
	}
}

// TestAssembleCCacheBytes_Concatenation verifies that assembleCCacheBytes
// correctly concatenates multiple credential slices in order.
func TestAssembleCCacheBytes_Concatenation(t *testing.T) {
	princ := []byte{1, 2, 3}
	cred1 := []byte{4, 5}
	cred2 := []byte{6, 7, 8}
	got := assembleCCacheBytes(princ, [][]byte{cred1, cred2})
	want := []byte{0x05, 0x04, 0x00, 0x00, 1, 2, 3, 4, 5, 6, 7, 8}
	if !bytes.Equal(got, want) {
		t.Errorf("got % x, want % x", got, want)
	}
}

// TestAssembleCCacheBytes_WithCredentials splits the gokrb5 CCACHE_TEST
// fixture at the two key boundaries and verifies that Unmarshal recovers the
// correct principal and all 3 credentials.
//
// Fixture layout (all big-endian, v4 format):
//
//	[0]      0x05   magic
//	[1]      0x04   version
//	[2-3]    0x000c header_len = 12
//	[4-15]   KDC-offset header field (tag=1, len=8, value)
//	[16-51]  default principal wire format — this is what MIT stores as the
//	         "__krb5_princ__" keyring key payload (no file-level preamble)
//	[52+]    3 credential wire records
func TestAssembleCCacheBytes_WithCredentials(t *testing.T) {
	fullBytes, err := hex.DecodeString(ccacheTestHex)
	if err != nil {
		t.Fatalf("decode fixture: %v", err)
	}

	// principalOffset: 2 (magic+version) + 2 (hdr_len field) + 12 (hdr) = 16
	// credentialOffset: 16 + 36 (principal wire bytes for testuser1@TEST.GOKRB5)
	const (
		principalOffset  = 16
		credentialOffset = 52
	)

	if len(fullBytes) < credentialOffset {
		t.Fatalf("fixture too short: %d bytes", len(fullBytes))
	}

	principalData := fullBytes[principalOffset:credentialOffset]
	// Pass all credential bytes as a single slice to validate that Unmarshal
	// parses them correctly after the reassembled preamble+principal.
	// Multi-element concatenation order is covered by TestAssembleCCacheBytes_Concatenation.
	credentialData := [][]byte{fullBytes[credentialOffset:]}

	assembled := assembleCCacheBytes(principalData, credentialData)

	cc := new(credentials.CCache)
	if err := cc.Unmarshal(assembled); err != nil {
		t.Fatalf("Unmarshal assembled bytes: %v", err)
	}

	if cc.DefaultPrincipal.Realm != "TEST.GOKRB5" {
		t.Errorf("realm = %q, want TEST.GOKRB5", cc.DefaultPrincipal.Realm)
	}
	if cc.DefaultPrincipal.PrincipalName.PrincipalNameString() != "testuser1" {
		t.Errorf("principal = %q, want testuser1", cc.DefaultPrincipal.PrincipalName.PrincipalNameString())
	}
	if len(cc.Credentials) != 3 {
		t.Errorf("len(credentials) = %d, want 3", len(cc.Credentials))
	}
}

// TestLoadCCacheFromKeyring_SessionNotFound verifies that requesting a
// non-existent collection in the session keyring returns a
// "keyring ccache:"-prefixed error without panicking.
func TestLoadCCacheFromKeyring_SessionNotFound(t *testing.T) {
	residual := "proxykit-no-such-ccache-XYZ-UNIQUE"
	_, err := loadCCacheFromKeyring(residual)
	if err == nil {
		t.Fatal("expected error for non-existent session keyring, got nil")
	}
	if !strings.HasPrefix(err.Error(), "keyring ccache:") {
		t.Errorf("error %q lacks keyring ccache: prefix", err.Error())
	}
}

// TestLoadCCacheFromKeyring_PersistentNotFound verifies the same for a
// non-existent named collection in the current process's persistent keyring.
func TestLoadCCacheFromKeyring_PersistentNotFound(t *testing.T) {
	residual := fmt.Sprintf("persistent:%d:proxykit-no-such-ccache-XYZ", os.Getuid())
	_, err := loadCCacheFromKeyring(residual)
	if err == nil {
		t.Fatal("expected error for non-existent persistent keyring, got nil")
	}
	if !strings.HasPrefix(err.Error(), "keyring ccache:") {
		t.Errorf("error %q lacks keyring ccache: prefix", err.Error())
	}
}
