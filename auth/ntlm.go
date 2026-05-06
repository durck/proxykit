package auth

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"

	"github.com/bodgit/ntlmssp"
)

// NTLM returns an NTLM Authenticator (MS-NLMP / RFC 4559) that drives
// the standard 3-message Negotiate / Challenge / Authenticate exchange
// against an HTTP CONNECT proxy.
//
// domain is the NT domain — pass "" for workgroup or implicit-domain
// hosts. user and pass are the credentials. The workstation name
// reported in the Type 1 message is taken from os.Hostname(); set the
// NTLM_WORKSTATION environment variable to override (handy for static
// binaries with empty hostnames).
//
// NTLM transmits an NTLMv2 hashed response, never the plain password,
// but is vulnerable to relay attacks; prefer Negotiate (Kerberos)
// where the proxy advertises it.
//
// The returned Authenticator is stateful and not safe for concurrent
// use. Sequential reuse across dials is fine — internal state is
// reset every time Headers is called with a nil challenge.
func NTLM(domain, user, pass string) Authenticator {
	return &ntlmAuth{domain: domain, user: user, pass: pass}
}

type ntlmAuth struct {
	domain, user, pass string
	client             *ntlmssp.Client
}

func (*ntlmAuth) Scheme() string { return "ntlm" }

// Headers drives the 3-round NTLM dance. Round 1 is invoked with a nil
// challenge and emits the Type 1 (Negotiate) message with done=false.
// Round 2 receives the Type 2 (Challenge) bytes and emits the Type 3
// (Authenticate) message with done=true.
func (n *ntlmAuth) Headers(challenge []byte) ([]string, bool, error) {
	if challenge == nil {
		return n.negotiate()
	}
	return n.authenticate(challenge)
}

func (n *ntlmAuth) negotiate() ([]string, bool, error) {
	workstation := os.Getenv("NTLM_WORKSTATION")
	if workstation == "" {
		if h, err := os.Hostname(); err == nil && h != "" {
			workstation = h
		} else {
			workstation = "WORKSTATION"
		}
	}

	client, err := ntlmssp.NewClient(
		ntlmssp.SetDomain(n.domain),
		ntlmssp.SetUserInfo(n.user, n.pass),
		ntlmssp.SetWorkstation(workstation),
	)
	if err != nil {
		return nil, false, fmt.Errorf("ntlm: new client: %w", err)
	}
	n.client = client

	msg, err := client.Authenticate(nil, nil)
	if err != nil {
		return nil, false, fmt.Errorf("ntlm: type 1 message: %w", err)
	}
	return []string{"Proxy-Authorization: NTLM " + base64.StdEncoding.EncodeToString(msg)}, false, nil
}

func (n *ntlmAuth) authenticate(challenge []byte) ([]string, bool, error) {
	if n.client == nil {
		return nil, true, errors.New("ntlm: authenticate called before negotiate")
	}
	msg, err := n.client.Authenticate(challenge, nil)
	if err != nil {
		return nil, true, fmt.Errorf("ntlm: type 3 message: %w", err)
	}
	return []string{"Proxy-Authorization: NTLM " + base64.StdEncoding.EncodeToString(msg)}, true, nil
}
