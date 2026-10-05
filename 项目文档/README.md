# SshHostCertTrustBoundary

An independently authored, bounded SSH **host certificate** trust experiment. The client binds one lowercase DNS host name to one Ed25519 CA public key, requires exactly that host principal, checks the certificate validity window and revoked serials, and delegates the CA signature and SSH protocol checks to a fixed `golang.org/x/crypto/ssh` dependency. Every host-key decision is written to an owner-only JSONL file before client authentication can proceed. Audit failure denies the connection.

The real loopback SSH test makes a deliberately weak callback accept a certificate for `beta.ssh.test` while connecting as `alpha.ssh.test`; the server's authentication callback runs. The guarded client rejects the same certificate before that callback. Additional real handshakes cover valid, wrong CA, expired, not-yet-valid, revoked, unrestricted/multiple principals, logical-address mismatch, raw key, wrong certificate type, unknown critical option, and changed-after-signing certificate. The deliberately weak callback exists only in a Go test file and is absent from the installed binary.

Run from the repository root with Go 1.26.2 and Python 3.11 or newer:

```sh
python3 scripts/run_validation.py --build-root Build/validation
```

The verifier tests the repository source, builds and unpacks a deterministic source `.tar` package, tests the unpacked package, then installs a binary to `Build/validation/install-bin` and runs its real loopback self-test. All Go caches, generated files, audit logs, test logs, archive and binary stay under `Build`; private keys exist only in memory. The machine-readable result is `Build/validation/validation.json`. CI runs this on Linux and macOS at the exact triggering commit and version tag.

The released source archive would contain source, tests and documents, not the locally built binary or dependency source. The source uses this project's MIT license; the pinned SSH library and its transitive dependencies retain their original rights, as recorded in `ORIGIN.md` and `THIRD_PARTY.md`.

This is a synthetic local control, not evidence of a defect in the upstream library or of a real authorized target. It does not cover non-certificate `known_hosts` keys, DNS routing trust, algorithm negotiation, CA custody, production revocation distribution, or a deployed SSH service. Real authorized-task evidence and CVP eligibility or approval remain open.
