#!/usr/bin/env python3
"""Verify GitHub attestations for one resolved WuKongIM source Release."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any


SOURCE_REPOSITORY = "WuKongIM/WuKongIM"
SIGNER_WORKFLOW = "WuKongIM/WuKongIM/.github/workflows/binary-release-publish.yml"
SOURCE_RECEIPT_SCHEMA = "wukongim/source-release-resolution/v1"
EVIDENCE_RECEIPT_SCHEMA = "wukongim/source-attestation-verification/v1"
SHA1_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
SEMVER_RE = re.compile(
    r"^v(0|[1-9][0-9]*)\."
    r"(0|[1-9][0-9]*)\."
    r"(0|[1-9][0-9]*)"
    r"-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)$"
)
MAX_JSON_BYTES = 8 * 1024 * 1024
TOP_LEVEL_KEYS = {
    "schema",
    "repository",
    "release_id",
    "tag",
    "version",
    "prerelease",
    "published_at",
    "source_sha",
    "initial_main_sha",
    "final_main_sha",
    "main_sha",
    "asset_count",
    "total_size",
    "assets",
    "checksum_asset",
    "checksum_entries",
    "release_revalidated",
    "tag_revalidated",
    "main_ancestry_revalidated",
}
ASSET_KEYS = {"id", "name", "size", "sha256", "downloaded_file"}
CHECKSUM_ENTRY_KEYS = {"name", "sha256"}


class VerificationError(RuntimeError):
    """The source receipt, assets, or attestations failed closed."""


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise VerificationError(f"JSON contains duplicate key: {key}")
        result[key] = value
    return result


def _parse_json_bytes(data: bytes, label: str) -> Any:
    if not data:
        raise VerificationError(f"{label} is empty")
    if len(data) > MAX_JSON_BYTES:
        raise VerificationError(f"{label} exceeds the JSON size limit")
    try:
        return json.loads(data, object_pairs_hook=_reject_duplicate_keys)
    except VerificationError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise VerificationError(f"{label} is not valid JSON") from error


def _read_safe_json(path: Path, label: str) -> dict[str, Any]:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise VerificationError(f"cannot stat {label}: {error}") from error
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise VerificationError(f"{label} must be a regular single-link file")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as source:
            opened = os.fstat(source.fileno())
            if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1:
                raise VerificationError(f"{label} must be a regular single-link file")
            if (metadata.st_dev, metadata.st_ino) != (opened.st_dev, opened.st_ino):
                raise VerificationError(f"{label} changed before it was opened")
            data = source.read(MAX_JSON_BYTES + 1)
            finished = os.fstat(source.fileno())
    except VerificationError:
        raise
    except OSError as error:
        raise VerificationError(f"cannot read {label}: {error}") from error
    if (opened.st_dev, opened.st_ino, opened.st_size) != (
        finished.st_dev,
        finished.st_ino,
        finished.st_size,
    ):
        raise VerificationError(f"{label} changed while it was read")
    value = _parse_json_bytes(data, label)
    if not isinstance(value, dict):
        raise VerificationError(f"{label} must contain a JSON object")
    return value


def _require_exact_keys(value: dict[str, Any], expected: set[str], label: str) -> None:
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        unexpected = sorted(actual - expected)
        raise VerificationError(
            f"{label} keys are not exact; missing={missing}, unexpected={unexpected}"
        )


def _require_sha(value: Any, pattern: re.Pattern[str], label: str) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise VerificationError(f"{label} has an invalid digest")
    return value


def _parse_preview_tag(tag: Any, version: Any, prerelease: Any) -> tuple[str, str]:
    if not isinstance(tag, str):
        raise VerificationError("source receipt tag must be a string")
    if "+" in tag:
        raise VerificationError("preview source tag must not contain build metadata")
    match = SEMVER_RE.fullmatch(tag)
    if match is None:
        raise VerificationError("preview source tag must be strict pre-release SemVer")
    for identifier in match.group(4).split("."):
        if identifier.isdigit() and len(identifier) > 1 and identifier.startswith("0"):
            raise VerificationError(
                "numeric SemVer pre-release identifiers must not have leading zeroes"
            )
    expected_version = tag[1:]
    if version != expected_version:
        raise VerificationError("source receipt version does not match its tag")
    if prerelease is not True:
        raise VerificationError("source receipt must describe a pre-release")
    return tag, expected_version


def _expected_names(version: str) -> tuple[tuple[str, ...], str]:
    prefix = f"wukongim_{version}"
    payloads = (
        f"{prefix}_darwin_amd64.tar.gz",
        f"{prefix}_darwin_arm64.tar.gz",
        f"{prefix}_linux_amd64.deb",
        f"{prefix}_linux_amd64.rpm",
        f"{prefix}_linux_amd64.tar.gz",
        f"{prefix}_linux_arm64.tar.gz",
    )
    return payloads, f"{prefix}_checksums.txt"


def _validate_receipt(receipt: dict[str, Any]) -> dict[str, Any]:
    _require_exact_keys(receipt, TOP_LEVEL_KEYS, "source receipt")
    if receipt["schema"] != SOURCE_RECEIPT_SCHEMA:
        raise VerificationError("source receipt schema is not supported")
    if receipt["repository"] != SOURCE_REPOSITORY:
        raise VerificationError("source receipt repository is not trusted")
    release_id = receipt["release_id"]
    if not isinstance(release_id, int) or isinstance(release_id, bool) or release_id <= 0:
        raise VerificationError("source receipt release_id must be a positive integer")
    tag, version = _parse_preview_tag(
        receipt["tag"], receipt["version"], receipt["prerelease"]
    )
    source_sha = _require_sha(receipt["source_sha"], SHA1_RE, "source_sha")
    initial_main_sha = _require_sha(
        receipt["initial_main_sha"], SHA1_RE, "initial_main_sha"
    )
    final_main_sha = _require_sha(receipt["final_main_sha"], SHA1_RE, "final_main_sha")
    if receipt["main_sha"] != final_main_sha:
        raise VerificationError("source receipt main_sha must equal final_main_sha")
    if not isinstance(receipt["published_at"], str) or not receipt["published_at"]:
        raise VerificationError("source receipt published_at must be non-empty")
    for field in (
        "release_revalidated",
        "tag_revalidated",
        "main_ancestry_revalidated",
    ):
        if receipt[field] is not True:
            raise VerificationError(f"source receipt {field} must be true")

    payload_names, checksum_name = _expected_names(version)
    expected_names = set(payload_names) | {checksum_name}
    assets_value = receipt["assets"]
    if not isinstance(assets_value, list) or len(assets_value) != 7:
        raise VerificationError("source receipt must contain exactly seven asset facts")
    assets: dict[str, dict[str, Any]] = {}
    asset_ids: set[int] = set()
    for value in assets_value:
        if not isinstance(value, dict):
            raise VerificationError("source receipt asset fact must be an object")
        _require_exact_keys(value, ASSET_KEYS, "source receipt asset fact")
        name = value["name"]
        if not isinstance(name, str) or name not in expected_names:
            raise VerificationError(f"source receipt contains unexpected asset fact: {name}")
        if value["downloaded_file"] != name:
            raise VerificationError(f"source receipt downloaded_file conflicts for {name}")
        asset_id = value["id"]
        if not isinstance(asset_id, int) or isinstance(asset_id, bool) or asset_id <= 0:
            raise VerificationError(f"source receipt asset {name} has invalid id")
        size = value["size"]
        if not isinstance(size, int) or isinstance(size, bool) or size <= 0:
            raise VerificationError(f"source receipt asset {name} has invalid size")
        sha256 = _require_sha(value["sha256"], SHA256_RE, f"asset {name} sha256")
        if name in assets:
            raise VerificationError(f"source receipt contains duplicate asset name: {name}")
        if asset_id in asset_ids:
            raise VerificationError(f"source receipt contains duplicate asset id: {asset_id}")
        assets[name] = {
            "id": asset_id,
            "name": name,
            "size": size,
            "sha256": sha256,
            "downloaded_file": name,
        }
        asset_ids.add(asset_id)
    if set(assets) != expected_names:
        raise VerificationError("source receipt asset facts do not match the exact seven names")
    if receipt["asset_count"] != 7:
        raise VerificationError("source receipt asset_count must equal seven")
    if receipt["total_size"] != sum(asset["size"] for asset in assets.values()):
        raise VerificationError("source receipt total_size conflicts with asset facts")
    if receipt["checksum_asset"] != checksum_name:
        raise VerificationError("source receipt checksum_asset is not exact")

    checksum_entries = receipt["checksum_entries"]
    if not isinstance(checksum_entries, list) or len(checksum_entries) != 6:
        raise VerificationError("source receipt must contain six checksum entries")
    checksums: dict[str, str] = {}
    for entry in checksum_entries:
        if not isinstance(entry, dict):
            raise VerificationError("source receipt checksum entry must be an object")
        _require_exact_keys(entry, CHECKSUM_ENTRY_KEYS, "source receipt checksum entry")
        name = entry["name"]
        if not isinstance(name, str) or name not in payload_names:
            raise VerificationError(f"source receipt contains unexpected checksum entry: {name}")
        if name in checksums:
            raise VerificationError(f"source receipt contains duplicate checksum entry: {name}")
        checksums[name] = _require_sha(entry["sha256"], SHA256_RE, f"checksum {name}")
    if set(checksums) != set(payload_names):
        raise VerificationError("source receipt checksum entries are not an exact payload closure")
    for name, sha256 in checksums.items():
        if sha256 != assets[name]["sha256"]:
            raise VerificationError(f"source receipt checksum digest conflicts for {name}")

    return {
        "release_id": release_id,
        "tag": tag,
        "version": version,
        "source_sha": source_sha,
        "initial_main_sha": initial_main_sha,
        "final_main_sha": final_main_sha,
        "assets": assets,
    }


def _safe_directory(path: Path, label: str) -> os.stat_result:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise VerificationError(f"cannot stat {label}: {error}") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise VerificationError(f"{label} must be a real directory")
    return metadata


def _hash_asset_file(asset_dir: Path, name: str, expected: dict[str, Any]) -> None:
    path = asset_dir / name
    try:
        metadata = path.lstat()
    except OSError as error:
        raise VerificationError(f"cannot stat source asset {name}: {error}") from error
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise VerificationError(f"source asset {name} must be a regular single-link file")
    if metadata.st_size != expected["size"]:
        raise VerificationError(f"source asset {name} size conflicts with receipt")
    digest = hashlib.sha256()
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as stream:
            opened = os.fstat(stream.fileno())
            if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1:
                raise VerificationError(
                    f"source asset {name} changed before digest verification"
                )
            while True:
                chunk = stream.read(1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
            finished = os.fstat(stream.fileno())
    except VerificationError:
        raise
    except OSError as error:
        raise VerificationError(f"cannot read source asset {name}: {error}") from error
    if (opened.st_dev, opened.st_ino, opened.st_size) != (
        finished.st_dev,
        finished.st_ino,
        finished.st_size,
    ):
        raise VerificationError(f"source asset {name} changed during digest verification")
    if digest.hexdigest() != expected["sha256"]:
        raise VerificationError(f"source asset {name} digest conflicts with receipt")


def _validate_asset_directory(asset_dir: Path, assets: dict[str, dict[str, Any]]) -> None:
    _safe_directory(asset_dir, "asset directory")
    try:
        entries = set(os.listdir(asset_dir))
    except OSError as error:
        raise VerificationError(f"cannot list asset directory: {error}") from error
    if entries != set(assets):
        raise VerificationError("asset directory does not contain the exact seven receipt assets")
    for name in sorted(assets):
        _hash_asset_file(asset_dir, name, assets[name])


def _prepare_evidence_directory(
    evidence_dir: Path, asset_dir: Path
) -> tuple[bool, os.stat_result]:
    evidence_resolved = evidence_dir.resolve(strict=False)
    asset_resolved = asset_dir.resolve(strict=True)
    if evidence_resolved == asset_resolved or asset_resolved in evidence_resolved.parents:
        raise VerificationError("evidence directory must not be inside the asset directory")
    if os.path.lexists(evidence_dir):
        _safe_directory(evidence_dir, "evidence directory")
        try:
            if any(evidence_dir.iterdir()):
                raise VerificationError("evidence directory must be empty")
        except OSError as error:
            raise VerificationError(f"cannot inspect evidence directory: {error}") from error
        return False, _safe_directory(evidence_dir, "evidence directory")
    try:
        evidence_dir.mkdir(mode=0o700, parents=False)
    except OSError as error:
        raise VerificationError(f"cannot create evidence directory: {error}") from error
    return True, _safe_directory(evidence_dir, "evidence directory")


def _write_json_file(directory_fd: int, name: str, value: Any) -> str:
    data = json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    created = False
    try:
        descriptor = os.open(name, flags, 0o600, dir_fd=directory_fd)
        created = True
        with os.fdopen(descriptor, "wb") as output:
            output.write(data)
    except OSError as error:
        if created:
            try:
                os.unlink(name, dir_fd=directory_fd)
            except OSError:
                pass
        raise VerificationError(f"cannot write attestation evidence {name}: {error}") from error
    return hashlib.sha256(data).hexdigest()


def _verify_one_attestation(
    asset_path: Path, tag: str, source_sha: str
) -> Any:
    command = [
        "gh",
        "attestation",
        "verify",
        str(asset_path),
        "--repo",
        SOURCE_REPOSITORY,
        "--signer-workflow",
        SIGNER_WORKFLOW,
        "--source-ref",
        f"refs/tags/{tag}",
        "--source-digest",
        source_sha,
        "--deny-self-hosted-runners",
        "--format=json",
    ]
    try:
        completed = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=90,
        )
    except FileNotFoundError as error:
        raise VerificationError("gh CLI is not available") from error
    except subprocess.TimeoutExpired as error:
        raise VerificationError(f"gh attestation verification timed out: {asset_path.name}") from error
    if completed.returncode != 0:
        raise VerificationError(
            f"gh attestation verification failed for {asset_path.name} "
            f"with exit code {completed.returncode}"
        )
    value = _parse_json_bytes(completed.stdout, f"gh attestation output for {asset_path.name}")
    if value in (None, False, "", [], {}):
        raise VerificationError(f"gh attestation output is empty JSON for {asset_path.name}")
    return value


def verify_source_attestations(
    *, receipt_path: Path, asset_dir: Path, evidence_dir: Path
) -> dict[str, Any]:
    receipt = _validate_receipt(_read_safe_json(receipt_path, "source receipt"))
    _validate_asset_directory(asset_dir, receipt["assets"])
    created_evidence, evidence_metadata = _prepare_evidence_directory(
        evidence_dir, asset_dir
    )
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        directory_fd = os.open(evidence_dir, flags)
    except OSError as error:
        if created_evidence:
            evidence_dir.rmdir()
        raise VerificationError(f"cannot open evidence directory safely: {error}") from error
    opened_evidence = os.fstat(directory_fd)
    if (
        not stat.S_ISDIR(opened_evidence.st_mode)
        or (evidence_metadata.st_dev, evidence_metadata.st_ino)
        != (opened_evidence.st_dev, opened_evidence.st_ino)
    ):
        os.close(directory_fd)
        if created_evidence:
            try:
                evidence_dir.rmdir()
            except OSError:
                pass
        raise VerificationError("evidence directory changed before it was opened")

    written_names: list[str] = []
    evidence_entries: list[dict[str, Any]] = []
    try:
        resolved_asset_dir = asset_dir.resolve(strict=True)
        for name in sorted(receipt["assets"]):
            asset_path = resolved_asset_dir / name
            verification = _verify_one_attestation(
                asset_path, receipt["tag"], receipt["source_sha"]
            )
            evidence_name = f"{name}.attestation.json"
            evidence_sha256 = _write_json_file(directory_fd, evidence_name, verification)
            written_names.append(evidence_name)
            evidence_entries.append(
                {
                    "asset": name,
                    "asset_sha256": receipt["assets"][name]["sha256"],
                    "evidence_file": evidence_name,
                    "evidence_sha256": evidence_sha256,
                }
            )

        # Bind the evidence to the same bytes after all external verification calls.
        _validate_asset_directory(asset_dir, receipt["assets"])
        summary = {
            "schema": EVIDENCE_RECEIPT_SCHEMA,
            "repository": SOURCE_REPOSITORY,
            "release_id": receipt["release_id"],
            "tag": receipt["tag"],
            "version": receipt["version"],
            "source_sha": receipt["source_sha"],
            "source_ref": f"refs/tags/{receipt['tag']}",
            "signer_workflow": SIGNER_WORKFLOW,
            "deny_self_hosted_runners": True,
            "asset_count": len(evidence_entries),
            "assets": evidence_entries,
            "assets_revalidated_after_attestations": True,
        }
        summary_name = "source-attestations.json"
        _write_json_file(directory_fd, summary_name, summary)
        written_names.append(summary_name)
        return summary
    except Exception:
        for name in written_names:
            try:
                os.unlink(name, dir_fd=directory_fd)
            except OSError:
                pass
        raise
    finally:
        os.close(directory_fd)
        if created_evidence:
            try:
                if evidence_dir.exists() and not any(evidence_dir.iterdir()):
                    evidence_dir.rmdir()
            except OSError:
                pass


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Verify fixed GitHub attestations for seven opaque source Release assets."
    )
    parser.add_argument("--receipt", required=True, type=Path)
    parser.add_argument("--asset-dir", required=True, type=Path)
    parser.add_argument("--evidence-dir", required=True, type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        summary = verify_source_attestations(
            receipt_path=args.receipt,
            asset_dir=args.asset_dir,
            evidence_dir=args.evidence_dir,
        )
    except VerificationError as error:
        print(f"source attestation verification failed: {error}", file=sys.stderr)
        return 1
    json.dump(summary, sys.stdout, sort_keys=True, separators=(",", ":"))
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
