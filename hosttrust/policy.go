// Package hosttrust binds one DNS host name to one SSH host-certificate CA.
// All decisions are recorded before the SSH client can authenticate.
package hosttrust

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

const Version = "0.1.0"

type Code string

const (
	Accepted        Code = "ACCEPT"
	AddressMismatch Code = "ADDRESS_MISMATCH"
	RawHostKey      Code = "RAW_HOST_KEY"
	WrongCertType   Code = "WRONG_CERT_TYPE"
	UntrustedCA     Code = "UNTRUSTED_CA"
	WrongPrincipal  Code = "WRONG_PRINCIPAL"
	NotYetValid     Code = "NOT_YET_VALID"
	Expired         Code = "EXPIRED"
	Revoked         Code = "REVOKED"
	InvalidCert     Code = "INVALID_CERT"
)

// Audit receives a decision with no passwords, private keys, or message bodies.
type Audit interface {
	Record(Decision) error
}

type Decision struct {
	AtUTC                  string `json:"at_utc"`
	ExpectedHost           string `json:"expected_host"`
	Remote                 string `json:"remote"`
	CertificateFingerprint string `json:"certificate_fingerprint,omitempty"`
	AuthorityFingerprint   string `json:"authority_fingerprint,omitempty"`
	Code                   Code   `json:"code"`
}

type TrustError struct {
	Code Code
}

func (e *TrustError) Error() string {
	return "SSH host certificate rejected: " + string(e.Code)
}

// Policy is immutable after construction. The caller supplies a trusted CA
// public key and a connection log before any network handshake begins.
type Policy struct {
	host      string
	authority ssh.PublicKey
	revoked   map[uint64]struct{}
	audit     Audit
	checker   ssh.CertChecker
}

func NewPolicy(host string, authority ssh.PublicKey, revokedSerials []uint64, audit Audit) (*Policy, error) {
	if err := validateHost(host); err != nil {
		return nil, err
	}
	if authority == nil || authority.Type() != ssh.KeyAlgoED25519 {
		return nil, errors.New("an Ed25519 CA public key is required")
	}
	if audit == nil {
		return nil, errors.New("a decision audit is required")
	}
	revoked := make(map[uint64]struct{}, len(revokedSerials))
	for _, serial := range revokedSerials {
		revoked[serial] = struct{}{}
	}
	p := &Policy{host: host, authority: authority, revoked: revoked, audit: audit}
	p.checker = ssh.CertChecker{
		IsHostAuthority: func(key ssh.PublicKey, _ string) bool {
			return key != nil && subtle.ConstantTimeCompare(key.Marshal(), authority.Marshal()) == 1
		},
		IsRevoked: func(cert *ssh.Certificate) bool {
			_, found := revoked[cert.Serial]
			return found
		},
		// A raw host key, a user certificate, and every unknown critical option
		// remain rejected by CertChecker.
	}
	return p, nil
}

func validateHost(host string) error {
	if len(host) == 0 || len(host) > 253 || host != strings.ToLower(host) || net.ParseIP(host) != nil {
		return errors.New("expected host must be a lowercase DNS name")
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return errors.New("invalid DNS label in expected host")
		}
		for _, b := range []byte(label) {
			if (b < 'a' || b > 'z') && (b < '0' || b > '9') && b != '-' {
				return errors.New("invalid DNS character in expected host")
			}
		}
	}
	return nil
}

// HostKeyCallback is wired directly into ssh.ClientConfig. The logical SSH
// address must name the expected host; the TCP endpoint may be a local test
// listener or a caller-controlled route to that host.
func (p *Policy) HostKeyCallback() ssh.HostKeyCallback {
	return func(addr string, remote net.Addr, key ssh.PublicKey) error {
		decision := Decision{AtUTC: time.Now().UTC().Format(time.RFC3339Nano), ExpectedHost: p.host}
		if remote != nil {
			decision.Remote = remote.String()
		}
		if key != nil {
			decision.CertificateFingerprint = ssh.FingerprintSHA256(key)
		}
		cert, isCert := key.(*ssh.Certificate)
		if isCert && cert.SignatureKey != nil {
			decision.AuthorityFingerprint = ssh.FingerprintSHA256(cert.SignatureKey)
		}
		code := p.classify(addr, remote, key, cert, isCert)
		decision.Code = code
		if err := p.audit.Record(decision); err != nil {
			return fmt.Errorf("SSH host decision audit unavailable: %w", err)
		}
		if code != Accepted {
			return &TrustError{Code: code}
		}
		return nil
	}
}

func (p *Policy) classify(addr string, remote net.Addr, key ssh.PublicKey, cert *ssh.Certificate, isCert bool) Code {
	host, _, err := net.SplitHostPort(addr)
	if err != nil || host != p.host {
		return AddressMismatch
	}
	if !isCert {
		return RawHostKey
	}
	if cert.CertType != ssh.HostCert {
		return WrongCertType
	}
	if cert.SignatureKey == nil || subtle.ConstantTimeCompare(cert.SignatureKey.Marshal(), p.authority.Marshal()) != 1 {
		return UntrustedCA
	}
	// CertChecker accepts an empty principal list as unrestricted. This
	// bounded policy instead requires exactly the intended DNS identity.
	if len(cert.ValidPrincipals) != 1 || cert.ValidPrincipals[0] != p.host {
		return WrongPrincipal
	}
	if _, found := p.revoked[cert.Serial]; found {
		return Revoked
	}
	now := time.Now().Unix()
	if cert.ValidAfter > uint64(now) {
		return NotYetValid
	}
	if cert.ValidBefore != uint64(ssh.CertTimeInfinity) && cert.ValidBefore <= uint64(now) {
		return Expired
	}
	if err := p.checker.CheckHostKey(addr, remote, key); err != nil {
		return InvalidCert
	}
	return Accepted
}
