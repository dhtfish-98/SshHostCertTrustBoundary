# Version 0.1.1

This version contains the host-certificate policy, owner-only decision audit, synthetic loopback SSH server, real client/server trust-boundary tests, deterministic source archive builder, and installed-binary self-test. Version 0.1.1 corrects stale publication wording from v0.1.0 and aligns the reported version across source, validation, and build configuration; the trust-decision behavior is unchanged. The package author is dhtfish98. The fixed external SSH dependency and its original rights are recorded in `ORIGIN.md` and `THIRD_PARTY.md`.

Public release records and source-archive checksums are listed on the [GitHub Releases page](https://github.com/dhtfish-98/SshHostCertTrustBoundary/releases). For any version, check that its tag resolves to the reviewed source commit, both Linux and macOS jobs completed for that commit, and the downloaded archive matches its checksum and source manifest. This document describes the source; the live publication checks establish its release status.

The experiments are confined to synthetic loopback SSH. Evidence from a real authorized target, any safeguard impact outside the lab, and CVP eligibility or approval remain open.
