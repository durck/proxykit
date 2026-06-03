//go:build linux && !proxykit_nokerberos

package auth

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/jcmturner/gokrb5/v8/credentials"
	"golang.org/x/sys/unix"
)

// loadCCacheFromKeyring reads an MIT-format credential cache from the Linux
// kernel keyring. residual is the KRB5CCNAME value after the "KEYRING:"
// prefix, in one of these forms:
//
//   - "NAME"                  search for keyring NAME in the session keyring
//   - "persistent:UID:NAME"   search for keyring NAME inside the persistent
//                             keyring for UID
//   - "persistent:UID"        use the persistent keyring for UID directly as
//                             the collection (common in SSSD/RHEL setups)
//
// MIT stores the credential cache as a kernel keyring collection. Within the
// collection there is one subsidiary keyring per principal. The subsidiary
// holds a "user" key "__krb5_princ__" whose payload is the default principal
// in MIT FILE ccache wire format, and zero or more "user" keys whose payloads
// are individual credentials in the same wire format. Prepending the v4 FILE
// ccache magic/version/header bytes to those payloads yields a byte stream
// that credentials.CCache.Unmarshal can parse.
func loadCCacheFromKeyring(residual string) (*credentials.CCache, error) {
	collID, err := resolveKeyringCollection(residual)
	if err != nil {
		return nil, fmt.Errorf("keyring ccache: resolve collection %q: %w", residual, err)
	}

	subID, err := keyringDefaultSubsidiary(collID)
	if err != nil {
		return nil, fmt.Errorf("keyring ccache: find default ccache: %w", err)
	}

	fileBytes, err := readKeyringAsFileBytes(subID)
	if err != nil {
		return nil, fmt.Errorf("keyring ccache: read keys: %w", err)
	}

	cc := new(credentials.CCache)
	if err := cc.Unmarshal(fileBytes); err != nil {
		return nil, fmt.Errorf("keyring ccache: parse: %w", err)
	}
	return cc, nil
}

// resolveKeyringCollection resolves a KEYRING residual to the keyring ID of
// the ccache collection.
func resolveKeyringCollection(residual string) (int, error) {
	if strings.HasPrefix(residual, "persistent:") {
		rest := strings.TrimPrefix(residual, "persistent:")
		uid, name, _ := strings.Cut(rest, ":")
		uidInt, err := strconv.Atoi(uid)
		if err != nil {
			return 0, fmt.Errorf("invalid UID in KEYRING residual: %q", residual)
		}
		anchorID, err := unix.KeyctlInt(unix.KEYCTL_GET_PERSISTENT, uidInt, unix.KEY_SPEC_SESSION_KEYRING, 0, 0)
		if err != nil {
			return 0, fmt.Errorf("get persistent keyring for uid %d: %w", uidInt, err)
		}
		if name == "" {
			return anchorID, nil
		}
		collID, err := unix.KeyctlSearch(anchorID, "keyring", name, 0)
		if err != nil {
			return 0, fmt.Errorf("search keyring %q in persistent/%d: %w", name, uidInt, err)
		}
		return collID, nil
	}

	collID, err := unix.KeyctlSearch(unix.KEY_SPEC_SESSION_KEYRING, "keyring", residual, 0)
	if err != nil {
		return 0, fmt.Errorf("search keyring %q in session: %w", residual, err)
	}
	return collID, nil
}

// keyringDefaultSubsidiary returns the keyring ID that contains the
// "__krb5_princ__" and credential keys. MIT uses a two-level layout (a
// collection keyring pointing to per-principal subsidiary keyrings via a
// "__krb5_cc_anchor" user key), but also supports a flat single-level layout
// where "__krb5_princ__" lives directly in the collection.
func keyringDefaultSubsidiary(collID int) (int, error) {
	// Flat layout: collection is the ccache itself.
	if _, err := unix.KeyctlSearch(collID, "user", "__krb5_princ__", 0); err == nil {
		return collID, nil
	}

	// Two-level layout: find the default subsidiary via __krb5_cc_anchor.
	anchorKeyID, err := unix.KeyctlSearch(collID, "user", "__krb5_cc_anchor", 0)
	if err == nil {
		subName, err := keyctlReadString(anchorKeyID)
		if err != nil {
			return 0, fmt.Errorf("read __krb5_cc_anchor: %w", err)
		}
		subID, err := unix.KeyctlSearch(collID, "keyring", subName, 0)
		if err != nil {
			return 0, fmt.Errorf("find subsidiary keyring %q: %w", subName, err)
		}
		return subID, nil
	}

	// No anchor key: pick the first subsidiary keyring linked in the collection.
	keyIDs, err := listKeyringKeyIDs(collID)
	if err != nil {
		return 0, fmt.Errorf("list collection keys: %w", err)
	}
	for _, kid := range keyIDs {
		ktype, _, err := keyctlDescribe(kid)
		if err != nil {
			continue
		}
		if ktype == "keyring" {
			return kid, nil
		}
	}
	return 0, errors.New("no ccache found in keyring collection")
}

// readKeyringAsFileBytes reads the "__krb5_princ__" key and all credential
// "user" keys from ringID, then returns the assembled byte slice ready for
// credentials.CCache.Unmarshal.
func readKeyringAsFileBytes(ringID int) ([]byte, error) {
	keyIDs, err := listKeyringKeyIDs(ringID)
	if err != nil {
		return nil, fmt.Errorf("list keyring keys: %w", err)
	}

	var princData []byte
	var credData [][]byte
	var firstCredErr error

	for _, kid := range keyIDs {
		ktype, desc, err := keyctlDescribe(kid)
		if err != nil || ktype != "user" {
			continue
		}
		data, err := keyctlReadKey(kid)
		if err != nil {
			if firstCredErr == nil {
				firstCredErr = err
			}
			continue
		}
		if desc == "__krb5_princ__" {
			princData = data
		} else {
			credData = append(credData, data)
		}
	}

	if princData == nil {
		return nil, errors.New("__krb5_princ__ key not found")
	}
	// Report a key-read error only when no credentials could be read at all
	// and we know at least one read failed; a partial failure (some readable,
	// some not) is left to the caller to handle via gokrb5's client logic.
	if len(credData) == 0 && firstCredErr != nil {
		return nil, fmt.Errorf("no credentials readable: %w", firstCredErr)
	}
	return assembleCCacheBytes(princData, credData), nil
}

// assembleCCacheBytes assembles MIT keyring key payloads into a byte stream
// suitable for credentials.CCache.Unmarshal. principalData is the payload of
// the "__krb5_princ__" key (principal wire format, no file-level preamble);
// each element of credData is the payload of one credential key (credential
// wire format, no preamble). A minimal v4 FILE ccache header is prepended.
//
// This function contains no syscalls and is tested independently of the live
// keyring path.
func assembleCCacheBytes(principalData []byte, credData [][]byte) []byte {
	// Minimal v4 FILE ccache preamble: magic=5, version=4, header_len=0.
	const preambleLen = 4
	n := preambleLen + len(principalData)
	for _, c := range credData {
		n += len(c)
	}
	out := make([]byte, 0, n)
	out = append(out, 0x05, 0x04, 0x00, 0x00)
	out = append(out, principalData...)
	for _, c := range credData {
		out = append(out, c...)
	}
	return out
}

// listKeyringKeyIDs returns the key serial numbers of all keys directly linked
// to ringID. KEYCTL_READ on a keyring returns the serials as a packed array of
// native-endian int32 values.
//
// The two-step probe/read pattern is subject to a TOCTOU race if keys are
// added between calls; on ENOBUFS the call is retried with the buffer size
// reported by the kernel until it succeeds.
func listKeyringKeyIDs(ringID int) ([]int, error) {
	const initialCap = 32 // room for 8 key IDs to start
	buf := make([]byte, initialCap)
	for {
		n, err := unix.KeyctlBuffer(unix.KEYCTL_READ, ringID, buf, 0)
		if err == unix.ENOBUFS {
			buf = make([]byte, n+4)
			continue
		}
		if err != nil {
			return nil, err
		}
		if n == 0 {
			return nil, nil
		}
		ids := make([]int, n/4)
		for i := range ids {
			ids[i] = int(int32(binary.NativeEndian.Uint32(buf[i*4:])))
		}
		return ids, nil
	}
}

// keyctlDescribe returns the type and description of a key using KEYCTL_DESCRIBE.
// The kernel produces "type;uid;gid;perm;description".
func keyctlDescribe(keyID int) (keyType, description string, err error) {
	s, err := unix.KeyctlString(unix.KEYCTL_DESCRIBE, keyID)
	if err != nil {
		return "", "", err
	}
	// Format: "type;uid;gid;perm;description" — SplitN(n=5) keeps any semicolons
	// in the description intact.
	parts := strings.SplitN(s, ";", 5)
	if len(parts) != 5 {
		return "", "", fmt.Errorf("unexpected KEYCTL_DESCRIBE output: %q", s)
	}
	return parts[0], parts[4], nil
}

// keyctlReadKey reads and returns the payload of a key.
func keyctlReadKey(keyID int) ([]byte, error) {
	n, err := unix.KeyctlBuffer(unix.KEYCTL_READ, keyID, nil, 0)
	if err != nil {
		return nil, err
	}
	if n == 0 {
		return nil, nil
	}
	buf := make([]byte, n)
	if _, err = unix.KeyctlBuffer(unix.KEYCTL_READ, keyID, buf, 0); err != nil {
		return nil, err
	}
	return buf, nil
}

// keyctlReadString reads the string payload of a key, stripping any trailing
// NUL that the kernel may append.
func keyctlReadString(keyID int) (string, error) {
	data, err := keyctlReadKey(keyID)
	if err != nil {
		return "", err
	}
	return strings.TrimRight(string(data), "\x00"), nil
}
