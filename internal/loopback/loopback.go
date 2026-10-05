// Package loopback provides synthetic SSH handshakes for this local lab.
// Private keys are generated in memory and never written to disk.
package loopback

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"
)

type ProbeResult struct {
	HandshakeSucceeded bool   `json:"handshake_succeeded"`
	ServerAuthCalls    int64  `json:"server_auth_calls"`
	ClientError        string `json:"client_error,omitempty"`
}

func NewSigner() (ssh.Signer, error) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return ssh.NewSignerFromKey(privateKey)
}

func SignHost(ca, host ssh.Signer, principals []string, validAfter, validBefore time.Time, serial uint64) (*ssh.Certificate, error) {
	cert := &ssh.Certificate{
		Key:             host.PublicKey(),
		Serial:          serial,
		CertType:        ssh.HostCert,
		KeyId:           "synthetic-host",
		ValidPrincipals: append([]string(nil), principals...),
		ValidAfter:      uint64(validAfter.Unix()),
		ValidBefore:     uint64(validBefore.Unix()),
	}
	if err := cert.SignCert(rand.Reader, ca); err != nil {
		return nil, err
	}
	return cert, nil
}

// Probe performs one real TCP and SSH handshake against a loopback listener.
// The server counts authentication callbacks, making pre-auth rejection
// observable without relying on text in a client error message.
func Probe(hostSigner ssh.Signer, logicalHost string, callback ssh.HostKeyCallback) (ProbeResult, error) {
	var result ProbeResult
	if hostSigner == nil || callback == nil {
		return result, errors.New("host signer and callback are required")
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return result, err
	}
	defer listener.Close()
	var authCalls atomic.Int64
	serverConfig := &ssh.ServerConfig{
		PasswordCallback: func(_ ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			authCalls.Add(1)
			if string(password) == "synthetic-only" {
				return nil, nil
			}
			return nil, errors.New("synthetic password rejected")
		},
		MaxAuthTries: 1,
	}
	serverConfig.AddHostKey(hostSigner)
	done := make(chan error, 1)
	release := make(chan struct{})
	go func() {
		wire, acceptErr := listener.Accept()
		if acceptErr != nil {
			done <- acceptErr
			return
		}
		defer wire.Close()
		_ = wire.SetDeadline(time.Now().Add(6 * time.Second))
		server, channels, requests, handshakeErr := ssh.NewServerConn(wire, serverConfig)
		if handshakeErr != nil {
			done <- handshakeErr
			return
		}
		go ssh.DiscardRequests(requests)
		go func() {
			for channel := range channels {
				_ = channel.Reject(ssh.Prohibited, "no channels in synthetic lab")
			}
		}()
		<-release
		_ = server.Close()
		done <- nil
	}()
	wire, err := net.DialTimeout("tcp", listener.Addr().String(), 5*time.Second)
	if err != nil {
		_ = listener.Close()
		close(release)
		<-done
		return result, err
	}
	_ = wire.SetDeadline(time.Now().Add(6 * time.Second))
	clientConfig := &ssh.ClientConfig{
		User:            "synthetic-user",
		Auth:            []ssh.AuthMethod{ssh.Password("synthetic-only")},
		HostKeyCallback: callback,
		Timeout:         5 * time.Second,
	}
	client, channels, requests, clientErr := ssh.NewClientConn(wire, net.JoinHostPort(logicalHost, "22"), clientConfig)
	if clientErr == nil {
		sshClient := ssh.NewClient(client, channels, requests)
		result.HandshakeSucceeded = true
		_ = sshClient.Close()
	} else {
		result.ClientError = clientErr.Error()
	}
	_ = wire.Close()
	close(release)
	<-done
	result.ServerAuthCalls = authCalls.Load()
	return result, nil
}
