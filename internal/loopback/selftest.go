package loopback

import (
	"errors"
	"fmt"
	"time"

	"github.com/dhtfish-98/SshHostCertTrustBoundary/hosttrust"
	"golang.org/x/crypto/ssh"
)

type SelfTestReport struct {
	Project   string                 `json:"project"`
	Version   string                 `json:"version"`
	Status    string                 `json:"status"`
	Scenarios map[string]ProbeResult `json:"scenarios"`
	AuditFile string                 `json:"audit_file"`
}

// RunSelfTest exercises installed code with an ephemeral CA and real loopback
// SSH server. Deliberately weak comparison code exists only in tests.
func RunSelfTest(auditPath string) (SelfTestReport, error) {
	report := SelfTestReport{Project: "SshHostCertTrustBoundary", Version: hosttrust.Version, Status: "FAIL", Scenarios: map[string]ProbeResult{}, AuditFile: auditPath}
	if auditPath == "" {
		return report, errors.New("audit path is required")
	}
	ca, err := NewSigner()
	if err != nil {
		return report, err
	}
	host, err := NewSigner()
	if err != nil {
		return report, err
	}
	otherCA, err := NewSigner()
	if err != nil {
		return report, err
	}
	const expected = "alpha.ssh.test"
	audit := &hosttrust.FileAudit{Path: auditPath}
	policy, err := hosttrust.NewPolicy(expected, ca.PublicKey(), []uint64{7}, audit)
	if err != nil {
		return report, err
	}
	now := time.Now()
	type scenario struct {
		name       string
		ca         ssh.Signer
		principals []string
		start      time.Time
		end        time.Time
		serial     uint64
		wantOK     bool
	}
	cases := []scenario{
		{"valid", ca, []string{expected}, now.Add(-time.Minute), now.Add(time.Minute), 1, true},
		{"wrong_principal", ca, []string{"beta.ssh.test"}, now.Add(-time.Minute), now.Add(time.Minute), 2, false},
		{"wrong_ca", otherCA, []string{expected}, now.Add(-time.Minute), now.Add(time.Minute), 3, false},
		{"expired", ca, []string{expected}, now.Add(-3 * time.Minute), now.Add(-time.Minute), 4, false},
		{"revoked", ca, []string{expected}, now.Add(-time.Minute), now.Add(time.Minute), 7, false},
	}
	for _, tc := range cases {
		cert, err := SignHost(tc.ca, host, tc.principals, tc.start, tc.end, tc.serial)
		if err != nil {
			return report, err
		}
		certSigner, err := ssh.NewCertSigner(cert, host)
		if err != nil {
			return report, err
		}
		result, err := Probe(certSigner, expected, policy.HostKeyCallback())
		if err != nil {
			return report, err
		}
		report.Scenarios[tc.name] = result
		if result.HandshakeSucceeded != tc.wantOK {
			return report, fmt.Errorf("%s: unexpected client handshake result", tc.name)
		}
		if tc.wantOK && result.ServerAuthCalls != 1 || !tc.wantOK && result.ServerAuthCalls != 0 {
			return report, fmt.Errorf("%s: authentication callback boundary failed", tc.name)
		}
	}
	report.Status = "PASS_LOCAL_ONLY"
	return report, nil
}
