//go:build linux && !proxykit_nokerberos

package auth

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/jcmturner/gokrb5/v8/credentials"
	"golang.org/x/sys/unix"
)

const (
	keyringAnchorLegacy     = "legacy"
	keyringAnchorPersistent = "persistent"
	keyringAnchorProcess    = "process"
	keyringAnchorSession    = "session"
	keyringAnchorThread     = "thread"
	keyringAnchorUser       = "user"

	keyringTypeBigKey  = "big_key"
	keyringTypeKeyring = "keyring"
	keyringTypeUser    = "user"

	keyringCollectionPrefix         = "_krb_"
	keyringPersistentCollectionName = "_krb"
	keyringCollectionPrimary        = "krb_ccache:primary"
	keyringSpecCCacheSet            = "__krb5_cc_set__"
	keyringSpecPrinc                = "__krb5_princ__"
	keyringTimeOffsets              = "__krb5_time_offsets__"
)

type keyringResidual struct {
	anchor     string
	collection string
	subsidiary string
}

type keyringTarget struct {
	collectionID int
	cacheID      int
}

type keyringPayload struct {
	keyType     string
	description string
	data        []byte
	err         error
}

// loadCCacheFromKeyring reads an MIT-format credential cache from the Linux
// kernel keyring. residual is the KRB5CCNAME value after the "KEYRING:"
// prefix, in one of these forms:
//
//   - "NAME"                  legacy session-keyring collection/cache
//   - "session:NAME"          session keyring collection
//   - "user:NAME"             user keyring collection
//   - "process:NAME"          process keyring collection
//   - "thread:NAME"           thread keyring collection
//   - "persistent:UID"        persistent per-UID collection
//   - "ANCHOR:NAME:SUBSIDIARY" selects a specific ccache in the collection
//
// MIT stores the credential cache as a kernel keyring collection. Within the
// collection there is one subsidiary keyring per principal. The subsidiary
// holds a "user" key "__krb5_princ__" whose payload is the default principal in
// MIT FILE ccache wire format, plus one "user" or "big_key" key per credential.
// Prepending the v4 FILE ccache magic/version/header bytes to those payloads
// yields a byte stream that credentials.CCache.Unmarshal can parse.
func loadCCacheFromKeyring(residual string) (*credentials.CCache, error) {
	target, err := resolveKeyringTarget(residual)
	if err != nil {
		return nil, fmt.Errorf("keyring ccache: resolve %q: %w", residual, err)
	}

	fileBytes, err := readKeyringAsFileBytes(target.cacheID)
	if err != nil {
		return nil, fmt.Errorf("keyring ccache: read keys: %w", err)
	}

	cc := new(credentials.CCache)
	if err := cc.Unmarshal(fileBytes); err != nil {
		return nil, fmt.Errorf("keyring ccache: parse: %w", err)
	}
	return cc, nil
}

// parseKeyringResidual splits a KEYRING residual using MIT krb5's three forms:
// anchor:collection:subsidiary, anchor:collection, and legacy collection.
func parseKeyringResidual(residual string) (keyringResidual, error) {
	if residual == "" {
		return keyringResidual{}, errors.New("empty KEYRING residual")
	}
	if !strings.Contains(residual, ":") {
		return keyringResidual{anchor: keyringAnchorLegacy, collection: residual}, nil
	}

	anchor, rest, _ := strings.Cut(residual, ":")
	collection, subsidiary, _ := strings.Cut(rest, ":")
	switch anchor {
	case keyringAnchorLegacy, keyringAnchorPersistent, keyringAnchorProcess, keyringAnchorSession, keyringAnchorThread, keyringAnchorUser:
	default:
		return keyringResidual{}, fmt.Errorf("unsupported KEYRING anchor %q", anchor)
	}
	if anchor != keyringAnchorPersistent && collection == "" {
		return keyringResidual{}, fmt.Errorf("empty collection in KEYRING residual %q", residual)
	}
	return keyringResidual{anchor: anchor, collection: collection, subsidiary: subsidiary}, nil
}

// resolveKeyringTarget resolves a KEYRING residual to the keyring ID holding
// "__krb5_princ__" and credential keys.
func resolveKeyringTarget(residual string) (keyringTarget, error) {
	parsed, err := parseKeyringResidual(residual)
	if err != nil {
		return keyringTarget{}, err
	}

	collID, err := resolveKeyringCollection(parsed)
	if err != nil {
		if parsed.anchor == keyringAnchorLegacy && parsed.subsidiary == "" {
			cacheID, legacyErr := unix.KeyctlSearch(unix.KEY_SPEC_SESSION_KEYRING, keyringTypeKeyring, parsed.collection, 0)
			if legacyErr == nil {
				return keyringTarget{cacheID: cacheID}, nil
			}
		}
		return keyringTarget{}, err
	}

	if parsed.subsidiary != "" {
		cacheID, err := unix.KeyctlSearch(collID, keyringTypeKeyring, parsed.subsidiary, 0)
		if err != nil {
			return keyringTarget{}, fmt.Errorf("find subsidiary keyring %q: %w", parsed.subsidiary, err)
		}
		return keyringTarget{collectionID: collID, cacheID: cacheID}, nil
	}

	cacheID, err := keyringDefaultSubsidiary(collID, parsed)
	if err != nil {
		return keyringTarget{}, fmt.Errorf("find default ccache: %w", err)
	}
	return keyringTarget{collectionID: collID, cacheID: cacheID}, nil
}

// resolveKeyringCollection resolves a parsed KEYRING residual to the keyring ID
// of the MIT ccache collection.
func resolveKeyringCollection(parsed keyringResidual) (int, error) {
	if parsed.anchor == keyringAnchorPersistent {
		return resolvePersistentKeyringCollection(parsed.collection)
	}

	anchorID, err := keyringAnchorID(parsed.anchor)
	if err != nil {
		return 0, err
	}
	collName := keyringCollectionPrefix + parsed.collection
	collID, err := unix.KeyctlSearch(anchorID, keyringTypeKeyring, collName, 0)
	if err != nil {
		return 0, fmt.Errorf("search collection keyring %q in %s anchor: %w", collName, parsed.anchor, err)
	}
	return collID, nil
}

func resolvePersistentKeyringCollection(uidText string) (int, error) {
	uid := os.Getuid()
	if uidText != "" {
		var err error
		uid, err = strconv.Atoi(uidText)
		if err != nil {
			return 0, fmt.Errorf("invalid persistent KEYRING UID %q", uidText)
		}
	}

	persistentID, err := unix.KeyctlInt(unix.KEYCTL_GET_PERSISTENT, uid, unix.KEY_SPEC_PROCESS_KEYRING, 0, 0)
	if err != nil {
		if errors.Is(err, unix.ENOTSUP) && uid == os.Getuid() {
			persistentID = unix.KEY_SPEC_USER_KEYRING
		} else {
			return 0, fmt.Errorf("get persistent keyring for uid %d: %w", uid, err)
		}
	}
	collID, err := unix.KeyctlSearch(persistentID, keyringTypeKeyring, keyringPersistentCollectionName, 0)
	if err != nil {
		return 0, fmt.Errorf("search persistent collection keyring %q for uid %d: %w", keyringPersistentCollectionName, uid, err)
	}
	return collID, nil
}

func keyringAnchorID(anchor string) (int, error) {
	switch anchor {
	case keyringAnchorLegacy, keyringAnchorSession:
		return unix.KEY_SPEC_SESSION_KEYRING, nil
	case keyringAnchorProcess:
		return unix.KEY_SPEC_PROCESS_KEYRING, nil
	case keyringAnchorThread:
		return unix.KEY_SPEC_THREAD_KEYRING, nil
	case keyringAnchorUser:
		return unix.KEY_SPEC_USER_KEYRING, nil
	default:
		return 0, fmt.Errorf("unsupported KEYRING anchor %q", anchor)
	}
}

// keyringDefaultSubsidiary returns the keyring ID that contains the
// "__krb5_princ__" and credential keys. MIT uses a collection keyring with a
// "krb_ccache:primary" user key pointing at the primary subsidiary keyring, but
// we also support old flat single-level caches where "__krb5_princ__" lives
// directly in the collection.
func keyringDefaultSubsidiary(collID int, parsed keyringResidual) (int, error) {
	// Flat layout: collection is the ccache itself.
	if _, err := unix.KeyctlSearch(collID, keyringTypeUser, keyringSpecPrinc, 0); err == nil {
		return collID, nil
	}

	primaryKeyID, err := unix.KeyctlSearch(collID, keyringTypeUser, keyringCollectionPrimary, 0)
	if err == nil {
		payload, err := keyctlReadKey(primaryKeyID)
		if err != nil {
			return 0, fmt.Errorf("read %s: %w", keyringCollectionPrimary, err)
		}
		name, err := parseKeyringPrimary(payload)
		if err != nil {
			return 0, fmt.Errorf("parse %s: %w", keyringCollectionPrimary, err)
		}
		subID, err := unix.KeyctlSearch(collID, keyringTypeKeyring, name, 0)
		if err != nil {
			return 0, fmt.Errorf("find primary subsidiary keyring %q: %w", name, err)
		}
		return subID, nil
	}

	// MIT initializes a missing legacy primary to the collection name. We avoid
	// creating keys here, but can still read an existing cache with that name.
	if parsed.anchor == keyringAnchorLegacy {
		subID, err := unix.KeyctlSearch(collID, keyringTypeKeyring, parsed.collection, 0)
		if err == nil {
			return subID, nil
		}
	}

	// Compatibility fallback for older non-MIT layouts seen in the field.
	anchorKeyID, err := unix.KeyctlSearch(collID, keyringTypeUser, "__krb5_cc_anchor", 0)
	if err == nil {
		subName, err := keyctlReadString(anchorKeyID)
		if err != nil {
			return 0, fmt.Errorf("read __krb5_cc_anchor: %w", err)
		}
		subID, err := unix.KeyctlSearch(collID, keyringTypeKeyring, subName, 0)
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
		if ktype == keyringTypeKeyring {
			return kid, nil
		}
	}
	return 0, errors.New("no ccache found in keyring collection")
}

func parseKeyringPrimary(payload []byte) (string, error) {
	if len(payload) < 8 {
		return "", errors.New("payload too short")
	}
	version := binary.BigEndian.Uint32(payload[:4])
	if version != 1 {
		return "", fmt.Errorf("unsupported collection version %d", version)
	}
	nameLen := binary.BigEndian.Uint32(payload[4:8])
	if nameLen > uint32(len(payload)-8) {
		return "", fmt.Errorf("invalid primary name length %d", nameLen)
	}
	if nameLen == 0 {
		return "", errors.New("empty primary name")
	}
	return string(payload[8 : 8+int(nameLen)]), nil
}

// readKeyringAsFileBytes reads the "__krb5_princ__" key and all credential keys
// from ringID, then returns the assembled byte slice ready for
// credentials.CCache.Unmarshal.
func readKeyringAsFileBytes(ringID int) ([]byte, error) {
	keyIDs, err := listKeyringKeyIDs(ringID)
	if err != nil {
		return nil, fmt.Errorf("list keyring keys: %w", err)
	}

	payloads := make([]keyringPayload, 0, len(keyIDs))
	for _, kid := range keyIDs {
		ktype, desc, err := keyctlDescribe(kid)
		if err != nil {
			continue
		}
		if ktype != keyringTypeUser && ktype != keyringTypeBigKey {
			continue
		}
		data, err := keyctlReadKey(kid)
		payloads = append(payloads, keyringPayload{
			keyType:     ktype,
			description: desc,
			data:        data,
			err:         err,
		})
	}
	return keyringPayloadsAsFileBytes(payloads)
}

func keyringPayloadsAsFileBytes(payloads []keyringPayload) ([]byte, error) {
	var princData []byte
	var credData [][]byte
	var timeOffsets []byte
	var firstCredErr error

	for _, p := range payloads {
		if p.keyType != keyringTypeUser && p.keyType != keyringTypeBigKey {
			continue
		}
		if p.err != nil {
			if firstCredErr == nil {
				firstCredErr = p.err
			}
			continue
		}
		switch p.description {
		case keyringSpecPrinc:
			princData = p.data
		case keyringTimeOffsets:
			timeOffsets = p.data
		case keyringCollectionPrimary, keyringSpecCCacheSet:
			continue
		default:
			credData = append(credData, p.data)
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
	return assembleCCacheBytesWithOffsets(princData, credData, timeOffsets), nil
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
	return assembleCCacheBytesWithOffsets(principalData, credData, nil)
}

func assembleCCacheBytesWithOffsets(principalData []byte, credData [][]byte, timeOffsets []byte) []byte {
	header := ccacheHeaderBytes(timeOffsets)
	n := 2 + len(header) + len(principalData)
	for _, c := range credData {
		n += len(c)
	}
	out := make([]byte, 0, n)
	out = append(out, 0x05, 0x04)
	out = append(out, header...)
	out = append(out, principalData...)
	for _, c := range credData {
		out = append(out, c...)
	}
	return out
}

func ccacheHeaderBytes(timeOffsets []byte) []byte {
	if len(timeOffsets) != 8 {
		return []byte{0x00, 0x00}
	}
	out := make([]byte, 14)
	binary.BigEndian.PutUint16(out[0:2], 12) // header length
	binary.BigEndian.PutUint16(out[2:4], 1)  // KDC offset tag
	binary.BigEndian.PutUint16(out[4:6], 8)
	copy(out[6:14], timeOffsets)
	return out
}

// listKeyringKeyIDs returns the key serial numbers of all keys directly linked
// to ringID. KEYCTL_READ on a keyring returns the serials as a packed array of
// native-endian int32 values.
//
// The kernel returns the total payload size even when the provided buffer is
// too small, so keyctlReadKey loops until the buffer is large enough.
func listKeyringKeyIDs(ringID int) ([]int, error) {
	buf, err := keyctlReadKey(ringID)
	if err != nil {
		return nil, err
	}
	if len(buf) == 0 {
		return nil, nil
	}
	if len(buf)%4 != 0 {
		return nil, fmt.Errorf("keyring payload length %d is not a multiple of key_serial_t size", len(buf))
	}
	ids := make([]int, len(buf)/4)
	for i := range ids {
		ids[i] = int(int32(binary.NativeEndian.Uint32(buf[i*4:])))
	}
	return ids, nil
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
	var buf []byte
	for {
		n, err := unix.KeyctlBuffer(unix.KEYCTL_READ, keyID, buf, 0)
		if err != nil {
			return nil, err
		}
		if n == 0 {
			return nil, nil
		}
		if n <= len(buf) {
			return buf[:n], nil
		}
		buf = make([]byte, n)
	}
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
