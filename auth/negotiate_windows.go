//go:build windows

package auth

import (
	"encoding/base64"
	"errors"
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Negotiate returns an HTTP Negotiate (SPNEGO/Kerberos) Authenticator
// that uses the Windows SSPI subsystem to obtain a token under the
// identity the binary runs as. spn is the proxy's service principal
// name, e.g. "http/PROXY.CORP.LOCAL"; pass an empty string to disable
// Kerberos and rely on the package default (typically NTLM fallback
// inside Negotiate).
//
// The Authenticator is single-round: it emits the SPNEGO blob in the
// first Proxy-Authorization and either the proxy accepts (200) or it
// rejects (407 → permanent failure for this Authenticator). NTLM-via-
// Negotiate fallback inside SSPI may still succeed in a single round
// because the server-side challenge is opaque to us.
//
// On non-Windows builds Negotiate returns an Authenticator whose
// Headers always returns errors.ErrUnsupported.
func Negotiate(spn string) Authenticator {
	return negotiateAuth{spn: spn}
}

type negotiateAuth struct {
	spn string
}

func (negotiateAuth) Scheme() string { return "negotiate" }

func (n negotiateAuth) Headers(_ []byte) ([]string, bool, error) {
	if n.spn == "" {
		return nil, true, errors.New("negotiate: empty SPN")
	}

	cred, err := acquireNegotiateCredentials()
	if err != nil {
		return nil, true, fmt.Errorf("negotiate: acquire credentials: %w", err)
	}
	defer cred.free()

	token, err := cred.initialToken(n.spn)
	if err != nil {
		return nil, true, fmt.Errorf("negotiate: initialize context: %w", err)
	}

	return []string{"Proxy-Authorization: Negotiate " + base64.StdEncoding.EncodeToString(token)}, true, nil
}

// --- Windows SSPI bindings ----------------------------------------------
// Lifted and cleaned up from reverse_ssh/pkg/wauth (BSD-3). Uses
// golang.org/x/sys/windows for proc handle resolution; the SSPI
// structures themselves are declared here because x/sys does not
// expose the secur32 surface.

var (
	modSecur32                     = windows.NewLazySystemDLL("secur32.dll")
	procAcquireCredentialsHandleW  = modSecur32.NewProc("AcquireCredentialsHandleW")
	procFreeCredentialsHandle      = modSecur32.NewProc("FreeCredentialsHandle")
	procInitializeSecurityContextW = modSecur32.NewProc("InitializeSecurityContextW")
	procDeleteSecurityContext      = modSecur32.NewProc("DeleteSecurityContext")
)

// SSPI flag and constant definitions (subset used here).
const (
	secpkgCredOutbound  = 0x00000002
	securityNetworkDREP = 0x00000000

	iscReqConnection      = 0x00000800
	iscReqConfidentiality = 0x00000010
	iscReqReplayDetect    = 0x00000004

	secbufferToken = 2

	tokenBufferSize = 16384 // Kerberos tickets can be ~12K with PAC.
)

// SecHandle/CredHandle/CtxtHandle layout: two pointer-sized fields.
type secHandle struct {
	Lower uintptr
	Upper uintptr
}

type secBuffer struct {
	Count  uint32
	Type   uint32
	Buffer *byte
}

type secBufferDesc struct {
	Version uint32
	Count   uint32
	Buffers *secBuffer
}

type negotiateCredentials struct {
	handle secHandle
}

func acquireNegotiateCredentials() (*negotiateCredentials, error) {
	pkg, err := syscall.UTF16PtrFromString("Negotiate")
	if err != nil {
		return nil, err
	}
	var h secHandle
	r0, _, _ := procAcquireCredentialsHandleW.Call(
		0,                                // pszPrincipal (NULL — current user)
		uintptr(unsafe.Pointer(pkg)),     // pszPackage
		uintptr(secpkgCredOutbound),      // fCredentialUse
		0,                                // pvLogonId
		0,                                // pAuthData
		0,                                // pGetKeyFn
		0,                                // pvGetKeyArgument
		uintptr(unsafe.Pointer(&h)),      // phCredential
		0,                                // ptsExpiry
	)
	if status := int32(r0); status < 0 {
		return nil, sspiError(status)
	}
	return &negotiateCredentials{handle: h}, nil
}

func (c *negotiateCredentials) free() {
	_, _, _ = procFreeCredentialsHandle.Call(uintptr(unsafe.Pointer(&c.handle)))
}

// initialToken issues a single InitializeSecurityContext call and
// returns the SPNEGO token bytes for inclusion in
// Proxy-Authorization: Negotiate <base64>.
func (c *negotiateCredentials) initialToken(spn string) ([]byte, error) {
	target, err := syscall.UTF16PtrFromString(spn)
	if err != nil {
		return nil, err
	}

	buf := make([]byte, tokenBufferSize)
	sb := secBuffer{
		Count:  uint32(len(buf)),
		Type:   secbufferToken,
		Buffer: &buf[0],
	}
	desc := secBufferDesc{
		Version: 0,
		Count:   1,
		Buffers: &sb,
	}

	var ctx secHandle
	var attrs uint32

	r0, _, _ := procInitializeSecurityContextW.Call(
		uintptr(unsafe.Pointer(&c.handle)), // phCredential
		0,                                   // phContext (nil for first call)
		uintptr(unsafe.Pointer(target)),     // pszTargetName
		uintptr(iscReqConfidentiality|iscReqReplayDetect|iscReqConnection),
		0,                                   // Reserved1
		uintptr(securityNetworkDREP),        // TargetDataRep
		0,                                   // pInput
		0,                                   // Reserved2
		uintptr(unsafe.Pointer(&ctx)),       // phNewContext
		uintptr(unsafe.Pointer(&desc)),      // pOutput
		uintptr(unsafe.Pointer(&attrs)),     // pfContextAttr
		0,                                   // ptsExpiry
	)
	// Always release the partial context handle, whatever the status.
	defer func() {
		_, _, _ = procDeleteSecurityContext.Call(uintptr(unsafe.Pointer(&ctx)))
	}()

	if status := int32(r0); status < 0 {
		return nil, sspiError(status)
	}
	if sb.Count == 0 {
		return nil, errors.New("SSPI returned empty token")
	}
	if sb.Count > uint32(len(buf)) {
		return nil, fmt.Errorf("SSPI token too large: %d > %d", sb.Count, len(buf))
	}
	out := make([]byte, sb.Count)
	copy(out, buf[:sb.Count])
	return out, nil
}

// sspiError translates a negative SECURITY_STATUS into a named error.
// Status codes are documented in MS-LDAP and MS-NLMP.
func sspiError(status int32) error {
	if name, ok := sspiErrorNames[uint32(status)]; ok {
		return fmt.Errorf("SSPI %s (0x%x)", name, uint32(status))
	}
	return fmt.Errorf("SSPI error 0x%x", uint32(status))
}

var sspiErrorNames = map[uint32]string{
	0x80090300: "SEC_E_INSUFFICIENT_MEMORY",
	0x80090301: "SEC_E_INVALID_HANDLE",
	0x80090302: "SEC_E_UNSUPPORTED_FUNCTION",
	0x80090303: "SEC_E_TARGET_UNKNOWN",
	0x80090304: "SEC_E_INTERNAL_ERROR",
	0x80090305: "SEC_E_SECPKG_NOT_FOUND",
	0x80090306: "SEC_E_NOT_OWNER",
	0x80090308: "SEC_E_INVALID_TOKEN",
	0x8009030C: "SEC_E_LOGON_DENIED",
	0x8009030D: "SEC_E_UNKNOWN_CREDENTIALS",
	0x8009030E: "SEC_E_NO_CREDENTIALS",
	0x80090311: "SEC_E_NO_AUTHENTICATING_AUTHORITY",
	0x80090322: "SEC_E_WRONG_PRINCIPAL",
}
