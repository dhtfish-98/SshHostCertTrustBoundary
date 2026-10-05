package hosttrust_test

import (
	"bufio"
	"crypto/rand"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dhtfish-98/SshHostCertTrustBoundary/hosttrust"
	"github.com/dhtfish-98/SshHostCertTrustBoundary/internal/loopback"
	"golang.org/x/crypto/ssh"
)

const expectedHost = "alpha.ssh.test"

func signer(t *testing.T) ssh.Signer {
	t.Helper()
	s, err := loopback.NewSigner()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func hostCertSigner(t *testing.T, ca, host ssh.Signer, principals []string, start, end time.Time, serial uint64) ssh.Signer {
	t.Helper()
	cert, err := loopback.SignHost(ca, host, principals, start, end, serial)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewCertSigner(cert, host)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func probe(t *testing.T, hostSigner ssh.Signer, logicalHost string, callback ssh.HostKeyCallback) loopback.ProbeResult {
	t.Helper()
	result, err := loopback.Probe(hostSigner, logicalHost, callback)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func decisions(t *testing.T, path string) []hosttrust.Decision {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out []hosttrust.Decision
	scan := bufio.NewScanner(f)
	for scan.Scan() {
		var d hosttrust.Decision
		if err := json.Unmarshal(scan.Bytes(), &d); err != nil {
			t.Fatal(err)
		}
		out = append(out, d)
	}
	if err := scan.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestRealLoopbackHostCertificateBoundary(t *testing.T) {
	ca, otherCA, host := signer(t), signer(t), signer(t)
	auditPath := filepath.Join(t.TempDir(), "decisions.jsonl")
	policy, err := hosttrust.NewPolicy(expectedHost, ca.PublicKey(), []uint64{7}, &hosttrust.FileAudit{Path: auditPath})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	wrongPrincipal := hostCertSigner(t, ca, host, []string{"beta.ssh.test"}, now.Add(-time.Minute), now.Add(time.Minute), 2)
	// The only deliberately weak callback is this test fixture. It allows a
	// certificate for beta.ssh.test to reach client authentication as alpha.
	t.Run("weak-baseline", func(t *testing.T) {
		baseline := probe(t, wrongPrincipal, expectedHost, func(_ string, _ net.Addr, _ ssh.PublicKey) error { return nil })
		if !baseline.HandshakeSucceeded || baseline.ServerAuthCalls != 1 {
			t.Fatalf("weak baseline did not expose the target boundary: %+v", baseline)
		}
	})
	check := func(name string, presented ssh.Signer, logicalHost string, want hosttrust.Code, wantOK bool) {
		t.Run(name, func(t *testing.T) {
			got := probe(t, presented, logicalHost, policy.HostKeyCallback())
			if got.HandshakeSucceeded != wantOK {
				t.Fatalf("handshake=%v, want %v; error=%q", got.HandshakeSucceeded, wantOK, got.ClientError)
			}
			wantAuth := int64(0)
			if wantOK {
				wantAuth = 1
			}
			if got.ServerAuthCalls != wantAuth {
				t.Fatalf("server auth callbacks=%d, want %d", got.ServerAuthCalls, wantAuth)
			}
			log := decisions(t, auditPath)
			if log[len(log)-1].Code != want {
				t.Fatalf("audit code=%s, want %s", log[len(log)-1].Code, want)
			}
		})
	}
	check("valid", hostCertSigner(t, ca, host, []string{expectedHost}, now.Add(-time.Minute), now.Add(time.Minute), 1), expectedHost, hosttrust.Accepted, true)
	check("wrong-principal", wrongPrincipal, expectedHost, hosttrust.WrongPrincipal, false)
	check("wrong-ca", hostCertSigner(t, otherCA, host, []string{expectedHost}, now.Add(-time.Minute), now.Add(time.Minute), 3), expectedHost, hosttrust.UntrustedCA, false)
	check("expired", hostCertSigner(t, ca, host, []string{expectedHost}, now.Add(-3*time.Minute), now.Add(-time.Minute), 4), expectedHost, hosttrust.Expired, false)
	check("not-yet-valid", hostCertSigner(t, ca, host, []string{expectedHost}, now.Add(time.Minute), now.Add(3*time.Minute), 5), expectedHost, hosttrust.NotYetValid, false)
	check("revoked", hostCertSigner(t, ca, host, []string{expectedHost}, now.Add(-time.Minute), now.Add(time.Minute), 7), expectedHost, hosttrust.Revoked, false)
	check("unrestricted-principals", hostCertSigner(t, ca, host, nil, now.Add(-time.Minute), now.Add(time.Minute), 8), expectedHost, hosttrust.WrongPrincipal, false)
	check("multiple-principals", hostCertSigner(t, ca, host, []string{expectedHost, "beta.ssh.test"}, now.Add(-time.Minute), now.Add(time.Minute), 9), expectedHost, hosttrust.WrongPrincipal, false)
	check("logical-address-mismatch", hostCertSigner(t, ca, host, []string{expectedHost}, now.Add(-time.Minute), now.Add(time.Minute), 10), "beta.ssh.test", hosttrust.AddressMismatch, false)
	check("raw-host-key", host, expectedHost, hosttrust.RawHostKey, false)
	userCert := &ssh.Certificate{
		Key: host.PublicKey(), Serial: 12, CertType: ssh.UserCert,
		ValidPrincipals: []string{expectedHost},
		ValidAfter:      uint64(now.Add(-time.Minute).Unix()), ValidBefore: uint64(now.Add(time.Minute).Unix()),
	}
	if err := userCert.SignCert(rand.Reader, ca); err != nil {
		t.Fatal(err)
	}
	userSigner, err := ssh.NewCertSigner(userCert, host)
	if err != nil {
		t.Fatal(err)
	}
	check("user-certificate", userSigner, expectedHost, hosttrust.WrongCertType, false)
	critical, err := loopback.SignHost(ca, host, []string{expectedHost}, now.Add(-time.Minute), now.Add(time.Minute), 13)
	if err != nil {
		t.Fatal(err)
	}
	critical.Permissions.CriticalOptions = map[string]string{"unsupported-test-option": "1"}
	if err := critical.SignCert(rand.Reader, ca); err != nil {
		t.Fatal(err)
	}
	criticalSigner, err := ssh.NewCertSigner(critical, host)
	if err != nil {
		t.Fatal(err)
	}
	check("unknown-critical-option", criticalSigner, expectedHost, hosttrust.InvalidCert, false)
	// Changing a signed field after issuance preserves the apparent CA and
	// principal but invalidates the CA signature.
	tampered, err := loopback.SignHost(ca, host, []string{expectedHost}, now.Add(-time.Minute), now.Add(time.Minute), 11)
	if err != nil {
		t.Fatal(err)
	}
	tampered.KeyId = "changed-after-signing"
	tamperedSigner, err := ssh.NewCertSigner(tampered, host)
	if err != nil {
		t.Fatal(err)
	}
	check("tampered-signature", tamperedSigner, expectedHost, hosttrust.InvalidCert, false)
	info, err := os.Stat(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("audit mode is %o, want 600", info.Mode().Perm())
	}
	data, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "synthetic-only") {
		t.Fatal("audit contained the synthetic credential")
	}
	if got := len(decisions(t, auditPath)); got != 13 {
		t.Fatalf("audit entries=%d, want 13", got)
	}
}

func TestAuditFailureClosesConnectionBeforeAuthentication(t *testing.T) {
	ca, host := signer(t), signer(t)
	now := time.Now()
	certSigner := hostCertSigner(t, ca, host, []string{expectedHost}, now.Add(-time.Minute), now.Add(time.Minute), 21)
	dir := t.TempDir()
	tooOpen := filepath.Join(dir, "overbroad.jsonl")
	if err := os.WriteFile(tooOpen, []byte("existing\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(tooOpen, 0o644); err != nil {
		t.Fatal(err)
	}
	paths := []string{tooOpen}
	link := filepath.Join(dir, "link.jsonl")
	if err := os.Symlink(tooOpen, link); err == nil {
		paths = append(paths, link)
	}
	for _, path := range paths {
		policy, err := hosttrust.NewPolicy(expectedHost, ca.PublicKey(), nil, &hosttrust.FileAudit{Path: path})
		if err != nil {
			t.Fatal(err)
		}
		got := probe(t, certSigner, expectedHost, policy.HostKeyCallback())
		if got.HandshakeSucceeded || got.ServerAuthCalls != 0 {
			t.Fatalf("unsafe audit path %s accepted handshake: %+v", path, got)
		}
	}
	data, err := os.ReadFile(tooOpen)
	if err != nil || string(data) != "existing\n" {
		t.Fatalf("overbroad audit was modified: data=%q err=%v", data, err)
	}
}

func TestPolicyRejectsInvalidSetup(t *testing.T) {
	ca := signer(t)
	audit := &hosttrust.FileAudit{Path: filepath.Join(t.TempDir(), "audit.jsonl")}
	for _, host := range []string{"", "Alpha.ssh.test", "-alpha.ssh.test", "127.0.0.1", "alpha..test", "alpha.test/other"} {
		if _, err := hosttrust.NewPolicy(host, ca.PublicKey(), nil, audit); err == nil {
			t.Errorf("accepted invalid host %q", host)
		}
	}
	if _, err := hosttrust.NewPolicy(expectedHost, nil, nil, audit); err == nil {
		t.Error("accepted a missing CA")
	}
	if _, err := hosttrust.NewPolicy(expectedHost, ca.PublicKey(), nil, nil); err == nil {
		t.Error("accepted a missing audit")
	}
}
