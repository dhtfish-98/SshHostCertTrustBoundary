#!/usr/bin/env python3
"""Verify repository source, unpacked source package, and installed binary.

Every generated file, compiler cache, key-free audit, and log remains in Build.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import shutil
import stat
import subprocess
import tarfile
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VERSION = "0.1.1"
PACKAGE = f"SshHostCertTrustBoundary-{VERSION}"
PINNED_COMMIT = "8f0f1112abdbc13b6e53068b813cc327e40f2f9f"
PINNED_MODULE = "v0.57.1-0.20261004121123-8f0f1112abdb"
EXPECTED_CODES = ["ACCEPT", "WRONG_PRINCIPAL", "UNTRUSTED_CA", "EXPIRED", "REVOKED"]


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def run(args: list[str], cwd: Path, env: dict[str, str], log: Path) -> str:
    started = time.monotonic()
    proc = subprocess.run(args, cwd=cwd, env=env, text=True, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT, timeout=180, check=False)
    output = proc.stdout
    log.parent.mkdir(parents=True, exist_ok=True)
    log.write_text(output)
    if proc.returncode:
        raise RuntimeError(f"{' '.join(args)} failed ({proc.returncode}); see {log}: {output[-2000:]}")
    print(f"PASS {cwd.name}: {' '.join(args[:3])} ({time.monotonic()-started:.1f}s)")
    return output


def check_manifest() -> tuple[dict, list[str]]:
    path = ROOT / "项目文档/SOURCE_MANIFEST.json"
    manifest = json.loads(path.read_text())
    if manifest["project"] != "SshHostCertTrustBoundary" or manifest["version"] != VERSION or manifest["author"] != "dhtfish98":
        raise RuntimeError("source manifest identity mismatch")
    names: list[str] = []
    for item in manifest["files"]:
        name = item["path"]
        if name in names or name.startswith("/") or ".." in Path(name).parts or name.startswith("Build/") and name != "Build/.gitignore":
            raise RuntimeError(f"invalid manifest path: {name}")
        data = (ROOT / name).read_bytes()
        if len(data) != item["bytes"] or digest(data) != item["sha256"]:
            raise RuntimeError(f"manifest mismatch: {name}")
        names.append(name)
    return manifest, sorted(names + ["项目文档/SOURCE_MANIFEST.json"])


def make_archive(path: Path, names: list[str]) -> None:
    with tarfile.open(path, "w", format=tarfile.PAX_FORMAT) as archive:
        for name in names:
            content = (ROOT / name).read_bytes()
            info = tarfile.TarInfo(f"{PACKAGE}/{name}")
            info.size = len(content)
            info.mtime = 0
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            info.mode = 0o644
            archive.addfile(info, io.BytesIO(content))


def unpack_archive(archive_path: Path, destination: Path) -> Path:
    destination.mkdir(parents=True)
    with tarfile.open(archive_path, "r") as archive:
        for item in archive:
            if not item.isfile():
                raise RuntimeError(f"unexpected archive entry: {item.name}")
            parts = Path(item.name).parts
            if not parts or parts[0] != PACKAGE or ".." in parts or Path(item.name).is_absolute():
                raise RuntimeError(f"unsafe archive entry: {item.name}")
            out = destination / item.name
            out.parent.mkdir(parents=True, exist_ok=True)
            source = archive.extractfile(item)
            if source is None:
                raise RuntimeError(f"unreadable archive entry: {item.name}")
            out.write_bytes(source.read())
    return destination / PACKAGE


def check_selftest(report_text: str, audit_path: Path) -> dict:
    report = json.loads(report_text)
    if report["project"] != "SshHostCertTrustBoundary" or report["version"] != VERSION or report["status"] != "PASS_LOCAL_ONLY":
        raise RuntimeError("self-test identity or status mismatch")
    if set(report["scenarios"]) != {"valid", "wrong_principal", "wrong_ca", "expired", "revoked"}:
        raise RuntimeError("self-test scenarios incomplete")
    for name, row in report["scenarios"].items():
        expected_ok = name == "valid"
        if row["handshake_succeeded"] != expected_ok or row["server_auth_calls"] != int(expected_ok):
            raise RuntimeError(f"authentication boundary failed: {name}")
    mode = stat.S_IMODE(audit_path.stat().st_mode)
    if mode != 0o600:
        raise RuntimeError(f"audit mode {mode:o}, expected 600")
    raw = audit_path.read_bytes()
    if b"synthetic-only" in raw:
        raise RuntimeError("audit contains the synthetic password")
    events = [json.loads(line) for line in raw.splitlines()]
    if [e["code"] for e in events] != EXPECTED_CODES:
        raise RuntimeError("audit codes do not match connection outcomes")
    return {"scenarios": report["scenarios"], "audit_sha256": digest(raw), "audit_mode": "0600", "audit_codes": EXPECTED_CODES}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--build-root", default="Build/validation", type=Path)
    args = parser.parse_args()
    build_root = (ROOT / args.build_root).resolve()
    project_build = (ROOT / "Build").resolve()
    if build_root == project_build or not build_root.is_relative_to(project_build):
        raise SystemExit("--build-root must be a subdirectory of the repository Build directory")
    if build_root.exists():
        shutil.rmtree(build_root)
    build_root.mkdir(parents=True)
    cache = project_build / "tool-cache"
    for part in ["gopath", "gomodcache", "gocache", "tmp"]:
        (cache / part).mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env.update({
        "GOPATH": str(cache / "gopath"),
        "GOMODCACHE": str(cache / "gomodcache"),
        "GOCACHE": str(cache / "gocache"),
        "GOTMPDIR": str(cache / "tmp"),
        "TMPDIR": str(cache / "tmp"),
        "GOTOOLCHAIN": "local",
    })
    manifest, names = check_manifest()
    archive_path = build_root / f"{PACKAGE}.tar"
    make_archive(archive_path, names)
    unpacked = unpack_archive(archive_path, build_root / "unpacked")
    if sorted(str(p.relative_to(unpacked)) for p in unpacked.rglob("*") if p.is_file()) != names:
        raise RuntimeError("unpacked archive file set mismatch")
    go_version = run(["go", "version"], ROOT, env, build_root / "go-version.log").strip()
    run(["go", "mod", "download"], ROOT, env, build_root / "module-download.log")
    module = json.loads(run(["go", "list", "-m", "-json", f"golang.org/x/crypto@{PINNED_MODULE}"], ROOT, env, build_root / "module.log"))
    if module["Version"] != PINNED_MODULE or module["Origin"]["Hash"] != PINNED_COMMIT:
        raise RuntimeError("pinned Go module did not resolve to the candidate commit")
    surfaces = []
    for name, directory in [("repository_source", ROOT), ("unpacked_source_archive", unpacked)]:
        log = build_root / f"{name}-tests.log"
        test_output = run(["go", "test", "-count=1", "-v", "./..."], directory, env, log)
        passed = [line.strip().split()[2] for line in test_output.splitlines() if line.strip().startswith("--- PASS: Test")]
        groups = [item for item in passed if "/" not in item]
        expected_groups = {"TestRealLoopbackHostCertificateBoundary", "TestAuditFailureClosesConnectionBeforeAuthentication", "TestPolicyRejectsInvalidSetup", "TestNilCertificateRejectsWithoutPanic"}
        required_cases = {"weak-baseline", "valid", "wrong-principal", "wrong-ca", "expired", "not-yet-valid", "revoked",
                          "unrestricted-principals", "multiple-principals", "logical-address-mismatch", "raw-host-key",
                          "user-certificate", "unknown-critical-option", "tampered-signature"}
        cases = {item.split("/", 1)[1] for item in passed if "/" in item}
        if set(groups) != expected_groups or cases != required_cases:
            raise RuntimeError(f"Go test groups or handshake cases incomplete on {name}")
        audit_path = build_root / f"{name}-audit.jsonl"
        output = run(["go", "run", "./cmd/hostcert-lab", "--self-test", "--audit-file", str(audit_path)], directory, env,
                     build_root / f"{name}-selftest.log")
        surfaces.append({"name": name, "test_groups": groups, "real_handshake_test_cases": sorted(cases),
                         "selftest": check_selftest(output, audit_path)})
    install_bin = build_root / "install-bin"
    install_bin.mkdir()
    install_env = env | {"GOBIN": str(install_bin)}
    run(["go", "install", "./cmd/hostcert-lab"], unpacked, install_env, build_root / "install.log")
    binary = install_bin / "hostcert-lab"
    if not binary.is_file():
        raise RuntimeError("isolated installed binary missing")
    version = run([str(binary), "--version"], ROOT, env, build_root / "installed-version.log").strip()
    if version != VERSION:
        raise RuntimeError("installed version mismatch")
    metadata = run(["go", "version", "-m", str(binary)], ROOT, env, build_root / "installed-build-info.log")
    if PINNED_MODULE not in metadata:
        raise RuntimeError("installed binary does not record the pinned x/crypto module")
    installed_audit = build_root / "installed-binary-audit.jsonl"
    output = run([str(binary), "--self-test", "--audit-file", str(installed_audit)], ROOT, env, build_root / "installed-selftest.log")
    surfaces.append({"name": "isolated_installed_binary", "version": version, "selftest": check_selftest(output, installed_audit)})
    receipt = {
        "project": "SshHostCertTrustBoundary", "version": VERSION, "author": "dhtfish98", "status": "PASS_LOCAL_ONLY",
        "go_version": go_version, "pinned_upstream_commit": PINNED_COMMIT, "pinned_module": PINNED_MODULE,
        "source_manifest_sha256": digest((ROOT / "项目文档/SOURCE_MANIFEST.json").read_bytes()),
        "source_archive": {"file": archive_path.name, "sha256": digest(archive_path.read_bytes())},
        "installed_binary_sha256": digest(binary.read_bytes()),
        "surfaces": surfaces,
        "open": ["real_authorized_target_evidence", "CVP_eligibility_or_approval"],
    }
    (build_root / "validation.json").write_text(json.dumps(receipt, ensure_ascii=False, sort_keys=True, indent=2) + "\n")
    print(build_root / "validation.json")


if __name__ == "__main__":
    main()
