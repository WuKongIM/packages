#!/usr/bin/env python3
"""Verify an assembled production package site without network access."""

from __future__ import annotations

import argparse
from email.utils import format_datetime, parsedate_to_datetime
import hashlib
import importlib.util
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET
from pathlib import Path, PurePosixPath
from typing import Any


SCRIPT_DIR = Path(__file__).resolve().parent
COMPOSER_PATH = SCRIPT_DIR / "compose-package-site.py"
SPEC = importlib.util.spec_from_file_location("_production_site_composer", COMPOSER_PATH)
if SPEC is None or SPEC.loader is None:  # pragma: no cover - installation error
    raise RuntimeError("cannot load compose-package-site.py")
C = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(C)

VERIFICATION_SCHEMA = "wukongim/production-package-site-verification/v1"
SNAPSHOT_FIELDS = {
    "schema", "audit_release_id", "control_sha", "releases", "retirement",
    "payloads", "public_keys", "source_attestations", "toolchain",
}
STATUS_FIELDS = {
    "schema", "apt", "rpm", "reason", "audit_release_id", "control_sha",
    "snapshot_sha256", "operation", "target_version",
}
MAX_CERT_BYTES = 1024 * 1024
MAX_COMMAND_OUTPUT = 16 * 1024 * 1024
FINGERPRINT_RE = re.compile(r"^[0-9A-F]{40}$")
ISSUER_FPR_MENTION_RE = re.compile(r"issuer[ \t]+fpr", re.IGNORECASE)
HASHED_ISSUER_FPR_RE = re.compile(
    r"^[ \t]*hashed subpkt 33 len 21 \(issuer fpr v4 ([0-9A-F]{40})\)[ \t]*$",
    re.IGNORECASE | re.MULTILINE,
)
DIGEST_ALGO_RE = re.compile(r"(?:digest|hash) algo ([0-9]+)(?:[^0-9]|$)", re.IGNORECASE)
SIGNATURE_ALGO_RE = re.compile(r":signature packet: algo ([0-9]+)(?:[^0-9]|$)", re.IGNORECASE)


class VerificationError(ValueError):
    """The site failed a production publication invariant."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise VerificationError(message)


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"


def digest_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def exact(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    require(isinstance(value, dict), f"{label} must be an object")
    require(set(value) == fields, f"{label} fields must be exactly {sorted(fields)}")
    return value


def load_json(path: Path, label: str, *, canonical: bool = False) -> Any:
    try:
        return C.load_json(path, label, canonical=canonical)
    except (C.CompositionError, OSError) as error:
        raise VerificationError(str(error)) from error


def read_checked(path: Path, label: str, *, maximum: int | None = None) -> bytes:
    try:
        return C.read_checked(path, label, maximum_bytes=maximum)
    except (C.CompositionError, OSError) as error:
        raise VerificationError(str(error)) from error


def hash_file(path: Path, label: str, *, maximum: int | None = None) -> dict[str, Any]:
    try:
        return C.hash_file(path, label, maximum_bytes=maximum)
    except (C.CompositionError, OSError) as error:
        raise VerificationError(str(error)) from error


def collect_tree(root: Path, label: str) -> tuple[dict[str, dict[str, Any]], set[str]]:
    try:
        return C.collect_tree(root, label)
    except (C.CompositionError, OSError) as error:
        raise VerificationError(str(error)) from error


def require_tree_closure(
    files: dict[str, dict[str, Any]], directories: set[str], expected: set[str], label: str
) -> None:
    try:
        C.require_tree_closure(files, directories, expected, label)
    except C.CompositionError as error:
        raise VerificationError(str(error)) from error


def run_command(command: list[str], label: str, *, input_bytes: bytes | None = None) -> subprocess.CompletedProcess[bytes]:
    try:
        result = subprocess.run(
            command,
            input=input_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=120,
            env={**os.environ, "LC_ALL": "C", "LANG": "C"},
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise VerificationError(f"cannot run {label}: {error}") from error
    require(
        len(result.stdout) <= MAX_COMMAND_OUTPUT and len(result.stderr) <= MAX_COMMAND_OUTPUT,
        f"{label} output exceeds its size limit",
    )
    return result


def _tool(name: str) -> str:
    path = shutil.which(name)
    require(path is not None, f"required verifier tool is unavailable: {name}")
    return path


def inspect_public_certificate(path: Path) -> dict[str, Any]:
    """Return exact primary/subkey topology from one public-only certificate."""
    read_checked(path, "public certificate", maximum=MAX_CERT_BYTES)
    with tempfile.TemporaryDirectory(prefix="wk-site-cert-gpg-") as temporary_name:
        home = Path(temporary_name)
        packets = run_command(
            [
                _tool("gpg"), "--batch", "--no-options", "--homedir", str(home),
                "--list-packets", "--", str(path),
            ],
            "OpenPGP certificate packet inspection",
        )
        require(packets.returncode == 0,
                "gpg rejected the reviewed public certificate packets")
        packet_text = (packets.stdout + packets.stderr).decode("utf-8", "replace")
        require("secret key packet" not in packet_text and "secret sub key packet" not in packet_text,
                "public certificate contains secret key packets")
        shown = run_command(
            [
                _tool("gpg"), "--batch", "--no-options", "--homedir", str(home),
                "--with-colons", "--fixed-list-mode", "--with-fingerprint",
                "--with-subkey-fingerprint", "--list-options", "show-unusable-subkeys",
                "--show-keys", "--", str(path),
            ],
            "OpenPGP certificate topology inspection",
        )
    require(shown.returncode == 0, "gpg rejected the reviewed public certificate")
    records: list[dict[str, Any]] = []
    for raw in shown.stdout.decode("utf-8", "strict").splitlines():
        fields = raw.split(":")
        kind = fields[0]
        require(kind not in {"sec", "ssb"}, "public certificate exposes secret key material")
        if kind in {"pub", "sub"}:
            capabilities = fields[11] if len(fields) > 11 else ""
            records.append({
                "kind": kind,
                "fingerprint": None,
                "capabilities": sorted({item for item in capabilities if item.islower()}),
                "disabled": "D" in capabilities,
                "validity": fields[1] if len(fields) > 1 else "",
                "key_bits": int(fields[2]) if len(fields) > 2 and fields[2].isdigit() else 0,
                "public_key_algorithm": (
                    int(fields[3]) if len(fields) > 3 and fields[3].isdigit() else 0
                ),
                "created": int(fields[5]) if len(fields) > 5 and fields[5].isdigit() else 0,
                "expires": int(fields[6]) if len(fields) > 6 and fields[6].isdigit() else None,
            })
        elif kind == "fpr" and records and records[-1]["fingerprint"] is None:
            fingerprint = fields[9].upper() if len(fields) > 9 else ""
            require(FINGERPRINT_RE.fullmatch(fingerprint) is not None,
                    "public certificate contains a non-full fingerprint")
            records[-1]["fingerprint"] = fingerprint
    require(records and records[0]["kind"] == "pub", "public certificate lacks a primary key")
    require(sum(item["kind"] == "pub" for item in records) == 1,
            "public certificate must contain exactly one primary key")
    require(all(item["fingerprint"] is not None for item in records),
            "public certificate record lacks a full fingerprint")
    return {"primary": records[0], "subkeys": records[1:]}


def _make_gpgv_keyring(certificate: Path, temporary: Path) -> Path:
    home = temporary / "gnupg"
    home.mkdir(mode=0o700)
    imported = run_command(
        [
            _tool("gpg"), "--batch", "--no-options", "--homedir", str(home),
            "--no-auto-key-retrieve", "--import", "--", str(certificate),
        ],
        "OpenPGP public-key import",
    )
    require(imported.returncode == 0, "gpg rejected the signature certificate")
    exported = run_command(
        [_tool("gpg"), "--batch", "--no-options", "--homedir", str(home), "--export"],
        "OpenPGP public-key export",
    )
    require(exported.returncode == 0 and exported.stdout,
            "cannot construct the isolated verification keyring")
    keyring = temporary / "trustedkeys.gpg"
    descriptor = os.open(keyring, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        view = memoryview(exported.stdout)
        while view:
            written = os.write(descriptor, view)
            require(written > 0, "cannot write the isolated verification keyring")
            view = view[written:]
    finally:
        os.close(descriptor)
    return keyring


def verify_openpgp_signature(
    certificate: Path,
    signature: Path,
    data: Path | None,
) -> dict[str, Any]:
    """Cryptographically verify one detached or clear-signed OpenPGP object."""
    with tempfile.TemporaryDirectory(prefix="wk-site-gpgv-") as temporary_name:
        temporary = Path(temporary_name)
        keyring = _make_gpgv_keyring(certificate, temporary)
        output = temporary / "cleartext"
        command = [
            _tool("gpgv"), "--homedir", str(temporary), "--keyring", str(keyring),
            "--status-fd", "1",
        ]
        if data is None:
            command += ["--output", str(output), "--", str(signature)]
        else:
            command += ["--", str(signature), str(data)]
        result = run_command(command, "OpenPGP signature verification")
        status = result.stdout.decode("utf-8", "replace")
        fatal = (" BADSIG ", " ERRSIG ", " NO_PUBKEY ", " REVKEYSIG ")
        require(not any(token in f" {status} " for token in fatal),
                "OpenPGP signature is bad, revoked, or untrusted")
        valid_lines = [line.split() for line in status.splitlines()
                       if line.startswith("[GNUPG:] VALIDSIG ")]
        fingerprints = [fields[2].upper() for fields in valid_lines if len(fields) >= 10]
        require(len(fingerprints) == 1 and FINGERPRINT_RE.fullmatch(fingerprints[0]) is not None,
                "OpenPGP signature must expose exactly one full issuer fingerprint")
        require(result.returncode == 0, "OpenPGP cryptographic verification failed")
        cleartext = read_checked(output, "clear-signed payload", maximum=C.MAX_METADATA_BYTES) \
            if data is None else None
        require(len(valid_lines) == 1 and valid_lines[0][9].isdigit(),
                "OpenPGP signature status omits its digest algorithm")
        return {
            "fingerprint": fingerprints[0],
            "digest_algorithm": int(valid_lines[0][9]),
            "cleartext": cleartext,
        }


def rpm_signature_packet_issuer(package: Path) -> str:
    """Return the single signed issuer claim from an RPM RSAHEADER packet."""
    armor = run_command(
        [_tool("rpm"), "-qp", "--queryformat", "%{RSAHEADER:armor}\n", str(package)],
        "RPM RSAHEADER extraction",
    )
    require(
        armor.returncode == 0
        and armor.stdout.startswith(b"-----BEGIN PGP SIGNATURE-----")
        and armor.stdout.rstrip().endswith(b"-----END PGP SIGNATURE-----"),
        "RPM payload lacks one inspectable RSAHEADER OpenPGP signature",
    )
    with tempfile.TemporaryDirectory(prefix="wk-site-packet-gpg-") as temporary_name:
        packets = run_command(
            [
                _tool("gpg"), "--batch", "--no-options", "--homedir", temporary_name,
                "--list-packets",
            ],
            "RPM OpenPGP signature packet inspection",
            input_bytes=armor.stdout,
        )
    require(packets.returncode == 0, "gpg rejected the RPM RSAHEADER signature packet")
    packet_text = (packets.stdout + packets.stderr).decode("utf-8", "replace")
    require(packet_text.count(":signature packet:") == 1,
            "RPM RSAHEADER must contain exactly one OpenPGP signature packet")
    public_key_algorithms = {int(value) for value in SIGNATURE_ALGO_RE.findall(packet_text)}
    require(public_key_algorithms == {1},
            "RPM signature packet must use OpenPGP RSA algorithm (1)")
    issuer_mentions = ISSUER_FPR_MENTION_RE.findall(packet_text)
    hashed_issuers = HASHED_ISSUER_FPR_RE.findall(packet_text)
    require(len(issuer_mentions) == 1 and len(hashed_issuers) == 1,
            "RPM signature packet must contain exactly one hashed full issuer fingerprint")
    issuer = hashed_issuers[0].upper()
    require(FINGERPRINT_RE.fullmatch(issuer) is not None,
            "RPM signature packet hashed issuer fingerprint is invalid")
    digest_algorithms = [int(value) for value in DIGEST_ALGO_RE.findall(packet_text)]
    require(digest_algorithms == [8],
            "RPM signature packet must declare exactly OpenPGP SHA-256 (8)")
    return issuer


def export_rpm_candidate_certificates(
    certificate: Path,
    candidates: list[str],
) -> dict[str, bytes]:
    """Export one minimal primary+candidate certificate for each reviewed signer."""
    with tempfile.TemporaryDirectory(prefix="wk-site-rpm-gpg-") as temporary_name:
        home = Path(temporary_name) / "gnupg"
        home.mkdir(mode=0o700)
        imported = run_command(
            [
                _tool("gpg"), "--batch", "--no-options", "--homedir", str(home),
                "--no-auto-key-retrieve", "--import", str(certificate),
            ],
            "RPM candidate certificate import",
        )
        require(imported.returncode == 0, "gpg rejected the reviewed RPM certificate")
        exports: dict[str, bytes] = {}
        for candidate in candidates:
            exported = run_command(
                [
                    _tool("gpg"), "--batch", "--no-options", "--homedir", str(home),
                    "--armor",
                    "--export-options", "export-minimal",
                    # GnuPG uses <> for full-string inequality; != is numeric.
                    "--export-filter", f"drop-subkey=fpr <> {candidate}",
                    "--export",
                ],
                f"RPM candidate certificate export {candidate}",
            )
            require(exported.returncode == 0 and 0 < len(exported.stdout) <= MAX_CERT_BYTES,
                    f"cannot export isolated RPM candidate certificate {candidate}")
            candidate_path = Path(temporary_name) / f"{candidate}.gpg"
            try:
                C.write_exclusive(candidate_path, exported.stdout,
                                  f"isolated RPM candidate certificate {candidate}")
            except C.CompositionError as error:
                raise VerificationError(str(error)) from error
            topology = inspect_public_certificate(candidate_path)
            require(
                {record["fingerprint"] for record in topology["subkeys"]} == {candidate}
                and len(topology["subkeys"]) == 1,
                f"isolated RPM candidate export did not retain exactly {candidate}",
            )
            exports[candidate] = exported.stdout
        return exports


def rpm_candidate_signature_verifies(
    package: Path,
    certificate: bytes,
    candidate: str,
) -> bool:
    """Verify with an rpmdb containing only one reviewed signing candidate."""
    with tempfile.TemporaryDirectory(prefix="wk-site-rpmdb-") as temporary_name:
        temporary = Path(temporary_name)
        database = temporary / "rpmdb"
        database.mkdir()
        public_certificate = temporary / f"{candidate}.gpg"
        try:
            C.write_exclusive(public_certificate, certificate,
                              f"isolated RPM candidate certificate {candidate}")
        except C.CompositionError as error:
            raise VerificationError(str(error)) from error
        initialized = run_command(
            [_tool("rpm"), "--dbpath", str(database), "--initdb"],
            "RPM verification database initialization",
        )
        require(initialized.returncode == 0, "cannot initialize the isolated RPM database")
        imported = run_command(
            [_tool("rpm"), "--dbpath", str(database), "--import", str(public_certificate)],
            f"RPM candidate public-key import {candidate}",
        )
        if imported.returncode != 0:
            return False
        checked = run_command(
            [_tool("rpmkeys"), "--dbpath", str(database), "--verbose", "--checksig", str(package)],
            f"RPM candidate signature verification {candidate}",
        )
        checked_text = (checked.stdout + b"\n" + checked.stderr).decode("utf-8", "replace").lower()
        return (
            checked.returncode == 0 and "signature" in checked_text
            and "noke" not in checked_text and "not ok" not in checked_text
            and "bad" not in checked_text
        )


def verify_rpm_package_signature(
    package: Path,
    certificate: Path,
    allowed_candidates: set[str],
) -> str:
    """Bind the signed issuer claim to exactly one candidate-only rpmkeys success."""
    candidates = sorted(allowed_candidates)
    require(candidates and all(FINGERPRINT_RE.fullmatch(value) for value in candidates),
            "RPM signature verification requires full reviewed candidate fingerprints")
    issuer = rpm_signature_packet_issuer(package)
    exports = export_rpm_candidate_certificates(certificate, candidates)
    successful = [
        candidate for candidate in candidates
        if rpm_candidate_signature_verifies(package, exports[candidate], candidate)
    ]
    require(len(successful) == 1,
            "RPM signature must cryptographically verify with exactly one isolated candidate")
    require(successful[0] == issuer,
            "RPM signed issuer claim differs from the isolated cryptographic signer")
    return issuer


def validate_key_topology(
    family: str,
    reviewed: dict[str, Any],
    certificate: Path,
) -> set[str]:
    topology = inspect_public_certificate(certificate)
    primary = topology["primary"]
    require(primary["fingerprint"] == reviewed["primary_fingerprint"],
            f"{family} certificate primary fingerprint differs from reviewed control")
    require(set(primary["capabilities"]) == {"c"},
            f"{family} primary key must be certification-only")
    require(primary["validity"] not in {"d", "e", "i", "r"} and not primary["disabled"],
            f"{family} primary key is revoked, expired, disabled, or invalid")
    subkeys = topology["subkeys"]
    actual = {item["fingerprint"] for item in subkeys}
    expected = {
        reviewed["current_signing_subkey_fingerprint"],
        reviewed["next_signing_subkey_fingerprint"],
        *reviewed["historical_signing_subkey_fingerprints"],
    }
    require(actual == expected and len(subkeys) == len(expected),
            f"{family} certificate signing-subkey topology differs from reviewed control")
    require(all(set(item["capabilities"]) == {"s"} for item in subkeys),
            f"{family} certificate subkeys must be signing-only")
    by_fingerprint = {item["fingerprint"]: item for item in subkeys}
    current = by_fingerprint[reviewed["current_signing_subkey_fingerprint"]]
    require(current["validity"] not in {"d", "e", "i", "r"} and not current["disabled"],
            f"{family} current signing subkey is revoked, expired, disabled, or invalid")
    successor = by_fingerprint[reviewed["next_signing_subkey_fingerprint"]]
    now = int(time.time())
    require(successor["validity"] not in {"d", "e", "r"} and not successor["disabled"],
            f"{family} next signing subkey is revoked, expired, or disabled")
    require(successor["validity"] != "i" or successor["created"] > now,
            f"{family} next signing subkey is invalid without being future-created")
    historical = set(reviewed["historical_signing_subkey_fingerprints"])
    for fingerprint in historical:
        record = by_fingerprint[fingerprint]
        require(record["validity"] not in {"d", "i"} and not record["disabled"],
                f"{family} historical signing subkey was never a usable current key")
        require(0 < record["created"] <= now,
                f"{family} historical signing subkey was not previously usable")
    if family == "rpm":
        for record in (primary, *subkeys):
            require(record["public_key_algorithm"] == 1,
                    "RPM primary and signing subkeys must use OpenPGP RSA algorithm (1)")
            require(record["key_bits"] in {3072, 4096},
                    "RPM primary and signing subkeys must be exactly 3072 or 4096 bits")
    return {
        fingerprint for fingerprint in historical
        if by_fingerprint[fingerprint]["validity"] in {"d", "e", "i", "r"}
        or by_fingerprint[fingerprint]["disabled"]
        or by_fingerprint[fingerprint]["created"] > now
    }


def validate_snapshot_and_control(args: argparse.Namespace) -> dict[str, Any]:
    try:
        control = C.validate_channels(load_json(args.channels, "channels manifest"))
        reviewed_keys = C.validate_signing_manifest(
            load_json(args.signing, "preview signing manifest"),
            args.apt_public_cert,
            args.rpm_public_cert,
        )
    except C.CompositionError as error:
        raise VerificationError(str(error)) from error

    snapshot_raw = read_checked(args.snapshot, "snapshot", maximum=8 * 1024 * 1024)
    snapshot = exact(load_json(args.snapshot, "snapshot", canonical=True),
                     SNAPSHOT_FIELDS, "snapshot")
    require(snapshot["schema"] == C.SNAPSHOT_SCHEMA,
            f"snapshot schema must be {C.SNAPSHOT_SCHEMA}")
    publication = control["publication"]
    require(snapshot["audit_release_id"] == publication["audit_release_id"],
            "snapshot audit Release differs from reviewed channels")
    require(isinstance(snapshot["control_sha"], str) and C.SHA_RE.fullmatch(snapshot["control_sha"]),
            "snapshot control_sha is invalid")
    require(snapshot["releases"] == control["preview"]["releases"],
            "snapshot releases differ from reviewed channels")
    require(snapshot["retirement"] == control["retirement"],
            "snapshot retirement differs from reviewed channels")

    payload_families = exact(snapshot["payloads"], {"apt", "rpm"}, "snapshot payloads")
    release_versions = set(control["releases"])
    payloads: dict[str, dict[str, dict[str, Any]]] = {}
    for family, source_field in (("apt", "deb_sha256"), ("rpm", "rpm_sha256")):
        values = payload_families[family]
        require(isinstance(values, list), f"snapshot {family} payloads must be an array")
        mapped: dict[str, dict[str, Any]] = {}
        prior = ""
        for index, raw in enumerate(values):
            try:
                item = C.validate_snapshot_entry(raw, family, index)
            except C.CompositionError as error:
                raise VerificationError(str(error)) from error
            version = item["version"]
            require(version > prior and version not in mapped,
                    f"snapshot {family} payload versions must be unique and sorted")
            require(version in control["releases"],
                    f"snapshot {family} payload has an unreviewed version")
            release = control["releases"][version]
            require(item["source_sha256"] == release[source_field],
                    f"snapshot {family} source digest differs for {version}")
            require(item["indexed"] is (release["state"] == "active"),
                    f"snapshot {family} indexed state differs for {version}")
            if family == "apt":
                require(item["published_sha256"] == item["source_sha256"],
                        f"APT payload bytes differ from source release for {version}")
            mapped[version] = item
            prior = version
        require(set(mapped) == release_versions,
                f"snapshot {family} payloads do not close over reviewed releases")
        payloads[family] = mapped

    public_keys = exact(snapshot["public_keys"], {"apt", "rpm"}, "snapshot public keys")
    all_fingerprints: list[str] = []
    unusable_historical: dict[str, set[str]] = {"apt": set(), "rpm": set()}
    for family, external in (("apt", args.apt_public_cert), ("rpm", args.rpm_public_cert)):
        reviewed = reviewed_keys[family]
        try:
            archived = C.validate_public_key_snapshot(public_keys[family], family, args.site_root)
        except C.CompositionError as error:
            raise VerificationError(str(error)) from error
        require(archived == reviewed,
                f"snapshot {family} public key differs from reviewed signing control")
        require(read_checked(args.site_root / reviewed["path"], f"site {family} certificate",
                             maximum=MAX_CERT_BYTES)
                == read_checked(external, f"reviewed {family} certificate", maximum=MAX_CERT_BYTES),
                f"site {family} certificate is not byte-identical to reviewed control")
        unusable_historical[family] = validate_key_topology(family, reviewed, external)
        all_fingerprints.extend([
            reviewed["primary_fingerprint"],
            reviewed["current_signing_subkey_fingerprint"],
            reviewed["next_signing_subkey_fingerprint"],
            *reviewed["historical_signing_subkey_fingerprints"],
        ])
    require(len(all_fingerprints) == len(set(all_fingerprints)),
            "reviewed APT/RPM fingerprints must be globally distinct")
    require(len({value[-16:] for value in all_fingerprints}) == len(all_fingerprints)
            and len({value[-8:] for value in all_fingerprints}) == len(all_fingerprints),
            "reviewed APT/RPM fingerprints must have globally distinct full key-ID suffixes")

    root = args.snapshot.parent.parent
    require(args.snapshot.name == "snapshot.json" and args.snapshot.parent.name == "audit"
            and args.site_root.name == "site" and args.site_root.parent == root,
            "site and snapshot must be siblings in one extracted archive root")
    toolchain_path = root / "audit/signing-toolchain.json"
    toolchain_facts = hash_file(toolchain_path, "archived signing toolchain", maximum=MAX_CERT_BYTES)
    toolchain_manifest = load_json(toolchain_path, "archived signing toolchain")
    try:
        expected_toolchain = C.validate_signing_toolchain(toolchain_manifest, toolchain_facts)
    except C.CompositionError as error:
        raise VerificationError(str(error)) from error
    try:
        actual_toolchain = C.validate_toolchain_snapshot(snapshot["toolchain"], "snapshot toolchain")
    except C.CompositionError as error:
        raise VerificationError(str(error)) from error
    require(actual_toolchain == expected_toolchain,
            "snapshot toolchain differs from its archived manifest")

    operation = publication["operation"]
    evidence = root / "audit/source-attestations"
    evidence_arg = evidence if operation == "add_release" else None
    plan_view = {"operation": operation, "target_version": publication["target_version"]}
    try:
        expected_source, _ = C.validate_source_attestations(evidence_arg, plan_view, control)
        actual_source = C.validate_source_attestation_snapshot(
            snapshot["source_attestations"], root, "snapshot source attestations"
        )
    except C.CompositionError as error:
        raise VerificationError(str(error)) from error
    require(actual_source == expected_source,
            "snapshot source-attestation inventory differs from archived evidence")

    status = exact(load_json(args.site_root / "status.json", "site status", canonical=True),
                   STATUS_FIELDS, "site status")
    require(status == {
        "schema": C.STATUS_SCHEMA,
        "apt": True,
        "rpm": True,
        "reason": "ready",
        "audit_release_id": snapshot["audit_release_id"],
        "control_sha": snapshot["control_sha"],
        "snapshot_sha256": digest_bytes(snapshot_raw),
        "operation": operation,
        "target_version": publication["target_version"],
    }, "site status differs from snapshot and reviewed publication")

    target = publication["target_version"]
    if operation == "add_release":
        require(target in control["releases"] and control["releases"][target]["state"] == "active",
                "add_release target must be an active reviewed release")
    elif operation == "remove_indexes":
        require(target in control["releases"] and control["releases"][target]["state"] == "index_removed",
                "remove_indexes target must be the retained reviewed release")
    else:
        require(target not in control["releases"],
                "remove_payloads target must be absent from the resulting snapshot")
    return {
        "control": control,
        "snapshot": snapshot,
        "payloads": payloads,
        "keys": reviewed_keys,
        "operation": operation,
        "target": target,
        "unusable_historical": unusable_historical,
    }


def parse_release_hashes(data: bytes) -> dict[str, dict[str, tuple[str, int]]]:
    try:
        lines = data.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise VerificationError("APT Release is not UTF-8") from error
    algorithms = {
        "MD5Sum": 32,
        "SHA1": 40,
        "SHA256": 64,
        "SHA512": 128,
    }
    result: dict[str, dict[str, tuple[str, int]]] = {name: {} for name in algorithms}
    current: str | None = None
    seen_sections: set[str] = set()
    for line in lines:
        if line in {f"{name}:" for name in algorithms}:
            current = line[:-1]
            require(current not in seen_sections, f"APT Release contains duplicate {current} sections")
            seen_sections.add(current)
            continue
        if current is not None and line.startswith(" "):
            fields = line.split()
            width = algorithms[current]
            require(len(fields) == 3 and re.fullmatch(f"[0-9a-f]{{{width}}}", fields[0]) is not None,
                    f"APT Release contains an invalid {current} entry")
            try:
                size = int(fields[1])
            except ValueError as error:
                raise VerificationError(f"APT Release contains an invalid {current} size") from error
            require(size > 0, f"APT Release {current} size must be positive")
            try:
                path = C.safe_relative(fields[2], f"APT Release {current} path").as_posix()
            except C.CompositionError as error:
                raise VerificationError(str(error)) from error
            require(path not in result[current], f"APT Release contains duplicate {current} path")
            result[current][path] = (fields[0], size)
        elif current is not None:
            current = None
    require(seen_sections == set(algorithms),
            "APT Release must contain exactly the four reviewed checksum sections")
    return result


def apt_package_version(version: str) -> str:
    return version.replace("-", "~", 1)


def rpm_package_version(version: str) -> str:
    return version.replace("-", "~", 1).replace("-", "_")


def query_deb_identity(package: Path) -> dict[str, str]:
    result = run_command(
        [
            _tool("dpkg-deb"), "--show",
            "--showformat=${Package}\t${Version}\t${Architecture}\n", str(package),
        ],
        "DEB package identity query",
    )
    require(result.returncode == 0, "dpkg-deb rejected a reviewed DEB payload")
    try:
        fields = result.stdout.decode("utf-8", "strict").removesuffix("\n").split("\t")
    except UnicodeDecodeError as error:
        raise VerificationError("dpkg-deb returned a non-UTF-8 package identity") from error
    require(len(fields) == 3 and all(fields), "dpkg-deb returned a malformed package identity")
    return {"name": fields[0], "version": fields[1], "architecture": fields[2]}


def query_rpm_identity(package: Path) -> dict[str, str]:
    result = run_command(
        [
            _tool("rpm"), "-qp", "--queryformat",
            "%{NAME}\t%{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\n", str(package),
        ],
        "RPM package identity query",
    )
    require(result.returncode == 0, "rpm rejected a reviewed RPM payload header")
    try:
        fields = result.stdout.decode("utf-8", "strict").removesuffix("\n").split("\t")
    except UnicodeDecodeError as error:
        raise VerificationError("rpm returned a non-UTF-8 package identity") from error
    require(len(fields) == 5 and all(fields), "rpm returned a malformed package identity")
    return {
        "name": fields[0], "epoch": fields[1], "version": fields[2],
        "release": fields[3], "architecture": fields[4],
    }


def parse_apt_package_stanzas(data: bytes) -> list[dict[str, str]]:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise VerificationError("APT Packages metadata is not UTF-8") from error
    paragraphs: list[dict[str, str]] = []
    fields: dict[str, str] = {}
    last: str | None = None
    for line in text.splitlines():
        if line == "":
            if fields:
                paragraphs.append(fields)
                fields = {}
                last = None
            continue
        if line[0] in " \t":
            require(last is not None, "APT Packages contains an orphan continuation")
            fields[last] += "\n" + line[1:]
            continue
        require(":" in line, "APT Packages contains a malformed field")
        name, value = line.split(":", 1)
        require(name and name not in fields, "APT Packages contains a duplicate field")
        fields[name] = value.lstrip()
        last = name
    if fields:
        paragraphs.append(fields)
    require(paragraphs, "APT Packages metadata contains no package stanzas")
    return paragraphs


def validate_release_policy_headers(data: bytes) -> None:
    try:
        lines = data.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise VerificationError("APT Release is not UTF-8") from error
    checksum_sections = {"MD5Sum", "SHA1", "SHA256", "SHA512"}
    headers: dict[str, str] = {}
    current_section: str | None = None
    for line in lines:
        if line.startswith((" ", "\t")):
            require(current_section in checksum_sections and len(line.split()) == 3,
                    "APT Release contains an orphan or malformed continuation")
            continue
        current_section = None
        require(":" in line, "APT Release contains a malformed header")
        name, raw_value = line.split(":", 1)
        require(re.fullmatch(r"[A-Za-z][A-Za-z0-9-]*", name) is not None,
                "APT Release contains an invalid header name")
        require(name not in headers, f"APT Release contains duplicate {name} headers")
        value = raw_value.lstrip()
        if name in checksum_sections:
            require(value == "", f"APT Release {name} section header must have no value")
            current_section = name
        else:
            require(value != "", f"APT Release {name} header must not be empty")
        headers[name] = value
    expected = {
        "Origin": "WuKongIM",
        "Label": "WuKongIM",
        "Suite": "preview",
        "Codename": "preview",
        "Architectures": "amd64",
        "Components": "main",
        "Acquire-By-Hash": "yes",
    }
    expected_fields = set(expected) | {"Date", *checksum_sections}
    require(set(headers) == expected_fields,
            "APT Release headers must be exactly the reviewed builder allowlist")
    for name, value in expected.items():
        require(headers.get(name) == value,
                f"APT Release {name} must be exactly {value}")
    try:
        release_date = parsedate_to_datetime(headers["Date"])
    except (TypeError, ValueError) as error:
        raise VerificationError("APT Release Date must be canonical RFC 2822 UTC") from error
    require(
        release_date is not None
        and release_date.utcoffset() is not None
        and release_date.utcoffset().total_seconds() == 0
        and format_datetime(release_date) == headers["Date"],
        "APT Release Date must be canonical RFC 2822 UTC",
    )
    require(release_date.timestamp() <= time.time() + 60,
            "APT Release Date exceeds the allowed future clock skew")


def validate_apt(
    args: argparse.Namespace,
    context: dict[str, Any],
    site_files: dict[str, dict[str, Any]],
) -> set[str]:
    root = args.site_root / "apt"
    release_relative = "apt/dists/preview/Release"
    inrelease_relative = "apt/dists/preview/InRelease"
    detached_relative = "apt/dists/preview/Release.gpg"
    packages_relative = "apt/dists/preview/main/binary-amd64/Packages"
    packages_gz_relative = f"{packages_relative}.gz"
    for relative in (release_relative, inrelease_relative, detached_relative,
                     packages_relative, packages_gz_relative):
        require(relative in site_files, f"site omits required APT file: {relative}")

    current = context["keys"]["apt"]["current_signing_subkey_fingerprint"]
    detached = verify_openpgp_signature(
        args.apt_public_cert,
        args.site_root / detached_relative,
        args.site_root / release_relative,
    )
    require(detached["fingerprint"] == current,
            "APT Release.gpg was not signed by the exact current signing subkey")
    require(detached["digest_algorithm"] == 8,
            "APT Release.gpg signature must use OpenPGP SHA-256 (8)")
    inline = verify_openpgp_signature(
        args.apt_public_cert,
        args.site_root / inrelease_relative,
        None,
    )
    require(inline["fingerprint"] == current,
            "APT InRelease was not signed by the exact current signing subkey")
    require(inline["digest_algorithm"] == 8,
            "APT InRelease signature must use OpenPGP SHA-256 (8)")
    release_bytes = read_checked(args.site_root / release_relative, "APT Release",
                                 maximum=C.MAX_METADATA_BYTES)
    validate_release_policy_headers(release_bytes)
    require(inline["cleartext"] == release_bytes,
            "APT InRelease cleartext differs byte-for-byte from Release")

    packages_bytes = read_checked(args.site_root / packages_relative, "APT Packages",
                                  maximum=C.MAX_METADATA_BYTES)
    compressed = read_checked(args.site_root / packages_gz_relative, "APT Packages.gz",
                              maximum=C.MAX_METADATA_BYTES)
    try:
        opened = C.decompress_buffer(compressed, ".gz", C.MAX_METADATA_BYTES, "APT Packages.gz")
    except C.CompositionError as error:
        raise VerificationError(str(error)) from error
    require(opened == packages_bytes, "APT Packages.gz differs from Packages")

    hashes = parse_release_hashes(release_bytes)
    release_names = {
        "main/binary-amd64/Packages": packages_relative,
        "main/binary-amd64/Packages.gz": packages_gz_relative,
    }
    for algorithm, constructor in {
        "MD5Sum": lambda value: hashlib.md5(value, usedforsecurity=False),
        "SHA1": lambda value: hashlib.sha1(value, usedforsecurity=False),
        "SHA256": hashlib.sha256,
        "SHA512": hashlib.sha512,
    }.items():
        require(set(hashes[algorithm]) == set(release_names),
                f"APT Release {algorithm} does not exactly close over package indexes")
        for release_name, site_name in release_names.items():
            contents = read_checked(args.site_root / site_name, f"APT index {site_name}",
                                    maximum=C.MAX_METADATA_BYTES)
            require(hashes[algorithm][release_name] == (constructor(contents).hexdigest(), len(contents)),
                    f"APT Release {algorithm} identity differs for {release_name}")

    try:
        indexed = C.parse_apt_packages(packages_bytes)
    except C.CompositionError as error:
        raise VerificationError(str(error)) from error
    expected_indexed: dict[str, dict[str, Any]] = {}
    indexed_versions: dict[str, str] = {}
    payload_paths: set[str] = set()
    for version, item in context["payloads"]["apt"].items():
        path = item["path"]
        require(path in site_files, f"site omits reviewed APT payload {version}")
        require(site_files[path]["sha256"] == item["published_sha256"],
                f"APT payload digest differs from snapshot for {version}")
        payload_paths.add(path)
        relative = PurePosixPath(path).relative_to("apt").as_posix()
        if item["indexed"]:
            expected_indexed[relative] = site_files[path]
            indexed_versions[relative] = version
        identity = query_deb_identity(args.site_root / path)
        require(identity == {
            "name": "wukongim",
            "version": apt_package_version(version),
            "architecture": "amd64",
        }, f"DEB payload header identity differs from reviewed release {version}")
    require(indexed == expected_indexed,
            "APT Packages does not exactly contain active reviewed payloads")
    stanzas = parse_apt_package_stanzas(packages_bytes)
    require(len(stanzas) == len(indexed_versions),
            "APT Packages stanza count differs from active reviewed releases")
    seen_versions: set[str] = set()
    for stanza in stanzas:
        required = {"Package", "Version", "Architecture", "Filename", "Size", "SHA256"}
        require(required.issubset(stanza), "APT Packages stanza omits package identity fields")
        try:
            relative = C.safe_relative(stanza["Filename"], "APT Packages Filename").as_posix()
        except C.CompositionError as error:
            raise VerificationError(str(error)) from error
        require(relative in indexed_versions, "APT Packages names an unreviewed payload")
        version = indexed_versions[relative]
        require(stanza["Package"] == "wukongim"
                and stanza["Version"] == apt_package_version(version)
                and stanza["Architecture"] == "amd64",
                f"APT Packages semantic identity differs for {version}")
        require(version not in seen_versions, "APT Packages duplicates a reviewed version")
        seen_versions.add(version)
    require(seen_versions == set(indexed_versions.values()),
            "APT Packages does not semantically close over active reviewed versions")

    by_hash_paths: set[str] = set()
    for site_name in (packages_relative, packages_gz_relative):
        relative = f"apt/dists/preview/main/binary-amd64/by-hash/SHA256/{site_files[site_name]['sha256']}"
        require(relative in site_files and site_files[relative] == site_files[site_name],
                f"APT by-hash copy differs from {site_name}")
        require(read_checked(args.site_root / relative, f"APT by-hash {relative}",
                             maximum=C.MAX_METADATA_BYTES)
                == read_checked(args.site_root / site_name, f"APT source {site_name}",
                                maximum=C.MAX_METADATA_BYTES),
                f"APT by-hash bytes differ from {site_name}")
        by_hash_paths.add(relative)
    return payload_paths | by_hash_paths | {
        release_relative, inrelease_relative, detached_relative,
        packages_relative, packages_gz_relative,
    }


def _child(element: ET.Element, name: str, label: str) -> ET.Element:
    matches = [item for item in element if C.local_name(item.tag) == name]
    require(len(matches) == 1, f"{label} must contain exactly one {name}")
    return matches[0]


def _xml(data: bytes, root_name: str, label: str) -> ET.Element:
    require(b"<!DOCTYPE" not in data and b"<!ENTITY" not in data,
            f"{label} must not contain a DTD or entity declaration")
    try:
        root = ET.fromstring(data)
    except ET.ParseError as error:
        raise VerificationError(f"{label} is invalid XML") from error
    require(C.local_name(root.tag) == root_name, f"{label} root is invalid")
    return root


def _validate_secondary_metadata(
    data: bytes,
    root_name: str,
    expected_pkgids: dict[str, str],
    label: str,
) -> None:
    root = _xml(data, root_name, label)
    packages = [item for item in root if C.local_name(item.tag) == "package"]
    try:
        declared = int(root.get("packages", ""))
    except ValueError as error:
        raise VerificationError(f"{label} packages count is invalid") from error
    require(declared == len(packages), f"{label} packages count differs from its contents")
    pkgids: set[str] = set()
    for package in packages:
        pkgid = package.get("pkgid", "")
        require(C.SHA256_RE.fullmatch(pkgid) is not None and pkgid not in pkgids
                and pkgid in expected_pkgids,
                f"{label} contains an invalid or duplicate package identifier")
        require(package.get("name") == "wukongim" and package.get("arch") == "x86_64",
                f"{label} contains an unexpected package identity")
        _validate_rpm_version_node(package, expected_pkgids[pkgid], label)
        pkgids.add(pkgid)
    require(pkgids == set(expected_pkgids),
            f"{label} does not exactly close over active RPM package identifiers")


def _validate_rpm_version_node(package: ET.Element, version: str, label: str) -> None:
    node = _child(package, "version", label)
    require(node.get("epoch") in {None, "0"}
            and node.get("ver") == rpm_package_version(version)
            and node.get("rel") == "1",
            f"{label} package version identity differs for {version}")


def validate_rpm(
    args: argparse.Namespace,
    context: dict[str, Any],
    site_files: dict[str, dict[str, Any]],
) -> set[str]:
    repository = "rpm/preview/el/9/x86_64"
    repomd_relative = f"{repository}/repodata/repomd.xml"
    signature_relative = f"{repomd_relative}.asc"
    require(repomd_relative in site_files and signature_relative in site_files,
            "site omits RPM repomd.xml or its signature")
    current = context["keys"]["rpm"]["current_signing_subkey_fingerprint"]
    metadata_signature = verify_openpgp_signature(
        args.rpm_public_cert,
        args.site_root / signature_relative,
        args.site_root / repomd_relative,
    )
    require(metadata_signature["fingerprint"] == current,
            "RPM repomd.xml was not signed by the exact current signing subkey")
    require(metadata_signature["digest_algorithm"] == 8,
            "RPM repomd signature must use OpenPGP SHA-256 (8)")

    repomd_bytes = read_checked(args.site_root / repomd_relative, "RPM repomd.xml",
                                maximum=C.MAX_METADATA_BYTES)
    root = _xml(repomd_bytes, "repomd", "RPM repomd.xml")
    records: dict[str, tuple[str, bytes]] = {}
    referenced: set[str] = set()
    for element in [item for item in root if C.local_name(item.tag) == "data"]:
        data_type = element.get("type", "")
        require(data_type in {"primary", "filelists", "other"} and data_type not in records,
                "RPM repomd data types must be exactly primary, filelists, and other")
        location = _child(element, "location", f"RPM repomd {data_type}")
        checksum = _child(element, "checksum", f"RPM repomd {data_type}")
        open_checksum = _child(element, "open-checksum", f"RPM repomd {data_type}")
        size_node = _child(element, "size", f"RPM repomd {data_type}")
        open_size_node = _child(element, "open-size", f"RPM repomd {data_type}")
        try:
            href = C.safe_relative(location.get("href"), "RPM repomd location").as_posix()
        except C.CompositionError as error:
            raise VerificationError(str(error)) from error
        require(href.startswith("repodata/") and href not in referenced,
                "RPM repomd metadata location is unsafe or duplicated")
        require(checksum.get("type") == "sha256" and checksum.text is not None
                and C.SHA256_RE.fullmatch(checksum.text),
                "RPM repomd compressed checksum must be SHA-256")
        require(open_checksum.get("type") == "sha256" and open_checksum.text is not None
                and C.SHA256_RE.fullmatch(open_checksum.text),
                "RPM repomd open checksum must be SHA-256")
        try:
            size = int(size_node.text or "")
            open_size = int(open_size_node.text or "")
        except ValueError as error:
            raise VerificationError("RPM repomd metadata size is invalid") from error
        full = f"{repository}/{href}"
        require(full in site_files and size > 0 and open_size > 0,
                f"RPM repomd references missing or empty metadata: {href}")
        require((site_files[full]["sha256"], site_files[full]["size"])
                == (checksum.text, size),
                f"RPM repomd compressed identity differs for {href}")
        try:
            opened = C.decompress_metadata(args.site_root / full, site_files[full])
        except C.CompositionError as error:
            raise VerificationError(str(error)) from error
        require((digest_bytes(opened), len(opened)) == (open_checksum.text, open_size),
                f"RPM repomd open identity differs for {href}")
        records[data_type] = (full, opened)
        referenced.add(href)
    require(set(records) == {"primary", "filelists", "other"},
            "RPM repomd data types must be exactly primary, filelists, and other")

    active_facts: dict[str, dict[str, Any]] = {}
    active_versions: dict[str, str] = {}
    payload_paths: set[str] = set()
    for version, item in context["payloads"]["rpm"].items():
        path = item["path"]
        require(path in site_files, f"site omits reviewed RPM payload {version}")
        require(site_files[path]["sha256"] == item["published_sha256"],
                f"RPM payload digest differs from snapshot for {version}")
        relative = PurePosixPath(path).relative_to(repository).as_posix()
        payload_paths.add(path)
        if item["indexed"]:
            active_facts[relative] = site_files[path]
            active_versions[relative] = version
        identity = query_rpm_identity(args.site_root / path)
        require(identity == {
            "name": "wukongim", "epoch": "0",
            "version": rpm_package_version(version), "release": "1",
            "architecture": "x86_64",
        }, f"RPM payload header identity differs from reviewed release {version}")

    primary_root = _xml(records["primary"][1], "metadata", "RPM primary metadata")
    primary_packages = [item for item in primary_root if C.local_name(item.tag) == "package"]
    try:
        declared = int(primary_root.get("packages", ""))
    except ValueError as error:
        raise VerificationError("RPM primary metadata packages count is invalid") from error
    require(declared == len(primary_packages),
            "RPM primary metadata packages count differs from its contents")
    semantic_paths: set[str] = set()
    for package in primary_packages:
        require(package.get("type") == "rpm", "RPM primary contains a non-RPM package")
        name = _child(package, "name", "RPM primary package")
        architecture = _child(package, "arch", "RPM primary package")
        location = _child(package, "location", "RPM primary package")
        try:
            relative = C.safe_relative(location.get("href"), "RPM primary location").as_posix()
        except C.CompositionError as error:
            raise VerificationError(str(error)) from error
        require(relative in active_versions and relative not in semantic_paths,
                "RPM primary names an unreviewed or duplicate payload")
        version = active_versions[relative]
        require(name.text == "wukongim" and architecture.text == "x86_64",
                f"RPM primary semantic identity differs for {version}")
        _validate_rpm_version_node(package, version, "RPM primary package")
        semantic_paths.add(relative)
    require(semantic_paths == set(active_versions),
            "RPM primary does not semantically close over active reviewed versions")
    try:
        indexed_paths = C.parse_rpm_primary(records["primary"][1], active_facts)
    except C.CompositionError as error:
        raise VerificationError(str(error)) from error
    require(indexed_paths == set(active_facts),
            "RPM primary metadata does not exactly contain active reviewed payloads")
    pkgids = {
        active_facts[path]["sha256"]: version
        for path, version in active_versions.items()
    }
    require(len(pkgids) == len(active_facts),
            "active RPM payload SHA-256 package identifiers must be unique")
    _validate_secondary_metadata(records["filelists"][1], "filelists", pkgids,
                                 "RPM filelists metadata")
    _validate_secondary_metadata(records["other"][1], "otherdata", pkgids,
                                 "RPM other metadata")

    historical = set(context["keys"]["rpm"]["historical_signing_subkey_fingerprints"])
    next_fingerprint = context["keys"]["rpm"]["next_signing_subkey_fingerprint"]
    for version, item in context["payloads"]["rpm"].items():
        is_new = context["operation"] == "add_release" and version == context["target"]
        allowed = {current} if is_new else {current, *historical}
        issuer = verify_rpm_package_signature(
            args.site_root / item["path"], args.rpm_public_cert, allowed
        )
        require(issuer != next_fingerprint,
                f"RPM payload {version} was signed by the staged next subkey")
        require(issuer not in context["unusable_historical"]["rpm"],
                f"RPM payload {version} was signed by an unusable historical subkey")
        require(issuer in allowed,
                f"RPM payload {version} has an issuer outside its reviewed rotation allowlist")

    return payload_paths | {repomd_relative, signature_relative} | {
        full for full, _ in records.values()
    }


def verify(args: argparse.Namespace) -> dict[str, Any]:
    context = validate_snapshot_and_control(args)
    site_files, site_directories = collect_tree(args.site_root, "production package site")
    site_size = sum(item["size"] for item in site_files.values())
    limit = context["control"]["manifest"]["site_limit_bytes"]
    require(site_size <= limit, "production package site exceeds the reviewed Pages size limit")

    apt_expected = validate_apt(args, context, site_files)
    rpm_expected = validate_rpm(args, context, site_files)
    apt_key = context["keys"]["apt"]
    rpm_key = context["keys"]["rpm"]
    manifest = (
        "TEST_ONLY=false\n"
        f"APT_PRIMARY_FINGERPRINT={apt_key['primary_fingerprint']}\n"
        f"APT_SIGNING_FINGERPRINT={apt_key['current_signing_subkey_fingerprint']}\n"
        f"APT_NEXT_SIGNING_FINGERPRINT={apt_key['next_signing_subkey_fingerprint']}\n"
        f"RPM_PRIMARY_FINGERPRINT={rpm_key['primary_fingerprint']}\n"
        f"RPM_SIGNING_FINGERPRINT={rpm_key['current_signing_subkey_fingerprint']}\n"
        f"RPM_NEXT_SIGNING_FINGERPRINT={rpm_key['next_signing_subkey_fingerprint']}\n"
        "APT_RELEASE=apt/dists/preview/Release\n"
        "RPM_REPOSITORY=rpm/preview/el/9/x86_64\n"
    ).encode("ascii")
    require(read_checked(args.site_root / "signing-manifest.txt", "site signing manifest",
                         maximum=16 * 1024) == manifest,
            "site signing manifest differs from reviewed signing control")
    index = (
        "<!doctype html>\n<meta charset=\"utf-8\">\n"
        "<title>WuKongIM Linux packages</title>\n"
        "<h1>WuKongIM Linux packages</h1>\n"
        "<p>The signed preview APT and RPM repositories are ready.</p>\n"
    ).encode("utf-8")
    require(read_checked(args.site_root / "index.html", "site index", maximum=64 * 1024) == index,
            "site index differs from the fixed production page")
    expected_files = apt_expected | rpm_expected | {
        "index.html", "status.json", "signing-manifest.txt",
        "keys/apt-preview.asc", "keys/rpm-preview.asc",
    }
    require_tree_closure(site_files, site_directories, expected_files,
                         "production package site")
    return {
        "schema": VERIFICATION_SCHEMA,
        "audit_release_id": context["snapshot"]["audit_release_id"],
        "control_sha": context["snapshot"]["control_sha"],
        "operation": context["operation"],
        "target_version": context["target"],
        "site_file_count": len(site_files),
        "site_size_bytes": site_size,
        "apt_release_signing_fingerprint": apt_key["current_signing_subkey_fingerprint"],
        "rpm_repository_signing_fingerprint": rpm_key["current_signing_subkey_fingerprint"],
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--site-root", required=True, type=Path)
    parser.add_argument("--snapshot", required=True, type=Path)
    parser.add_argument("--channels", required=True, type=Path)
    parser.add_argument("--signing", required=True, type=Path)
    parser.add_argument("--apt-public-cert", required=True, type=Path)
    parser.add_argument("--rpm-public-cert", required=True, type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        receipt = verify(args)
    except (VerificationError, OSError) as error:
        print(f"production package-site verification failed: {error}", file=sys.stderr)
        return 1
    print(canonical_json(receipt).decode("utf-8"), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
