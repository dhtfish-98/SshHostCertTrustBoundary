# Origin and scope

The trust policy, connection audit, synthetic loopback server, and tests in this repository were newly written by dhtfish98. The project does not copy, port, or claim to replace the SSH implementation in `golang.org/x/crypto`.

The research reference is fixed to [`golang/crypto@8f0f1112abdbc13b6e53068b813cc327e40f2f9f`](https://github.com/golang/crypto/commit/8f0f1112abdbc13b6e53068b813cc327e40f2f9f), dated 2026-10-04T12:11:23Z. Go resolves it as module `golang.org/x/crypto@v0.57.1-0.20261004121123-8f0f1112abdb`. The pinned commit checks SSH source for Unicode-aware string operations; it is not an identified host-certificate vulnerability. The lab depends on the pinned public SSH library for protocol handshakes and certificate signature verification, and adds an independently authored, deliberately narrow host-name, CA, expiry, serial-revocation, and audit policy.

The upstream `ssh/certs.go`, `ssh/knownhosts/knownhosts.go`, and `ssh/client.go` paths informed the topic selection. This package does not use ordinary `known_hosts` entries or change algorithm negotiation. A separate installed binary, when built locally, links the Go dependency; it is a local validation output in `Build`, not a release asset.

The fixed upstream source remains copyright its original contributors under [BSD-3-Clause](https://github.com/golang/crypto/blob/8f0f1112abdbc13b6e53068b813cc327e40f2f9f/LICENSE). Module and transitive dependency notices remain theirs. This project's own source is MIT-licensed by dhtfish98; see `LICENSE` and `THIRD_PARTY.md`.
