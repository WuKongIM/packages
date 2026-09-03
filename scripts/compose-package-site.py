#!/usr/bin/env python3
"""Compose one complete Pages site from independently signed family trees."""

from __future__ import annotations

import argparse
import bz2
import gzip
import hashlib
import io
import json
import lzma
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path, PurePosixPath
from typing import Any


CHANNELS_SCHEMA = "wukongim.native_package_channels/v3"
SIGNING_SCHEMA = "wukongim.native_package_signing/v3"
PLAN_SCHEMA = "wukongim.native_package_publication_plan/v1"
INVENTORY_SCHEMA = "wukongim.native_package_payload_inventory/v1"
BOOTSTRAP_INVENTORY_SCHEMA = "wukongim.native_package_bootstrap_inventory/v1"
SIGNING_RECEIPT_SCHEMA = "wukongim/package-family-signing-receipt/v1"
SNAPSHOT_SCHEMA = "wukongim.native_package_snapshot/v3"
COMPOSITION_SCHEMA = "wukongim.native_package_site_composition/v1"
STATUS_SCHEMA = "wukongim.native_package_repository_status/v2"
SIGNING_TOOLCHAIN_SCHEMA = "wukongim.native_package_signing_toolchain/v1"
SIGNING_TOOLCHAIN_IMAGE = "ghcr.io/wukongim/native-package-signing-toolchain"
SOURCE_ATTESTATION_SCHEMA = "wukongim/source-attestation-verification/v1"
SOURCE_REPOSITORY = "WuKongIM/WuKongIM"
SOURCE_SIGNER_WORKFLOW = "WuKongIM/WuKongIM/.github/workflows/binary-release-publish.yml"
SITE_WARNING_BYTES = 600 * 1024 * 1024
SITE_LIMIT_BYTES = 750 * 1024 * 1024
MAX_ONLINE_VERSIONS = 4
MAX_METADATA_BYTES = 64 * 1024 * 1024
COPY_CHUNK_BYTES = 1024 * 1024

SHA_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
OCI_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
FINGERPRINT_RE = re.compile(r"^[0-9A-F]{40}$")
UTC_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
VERSION_RE = re.compile(
    r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)-"
    r"(?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)"
    r"(?:\.(?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*))*$"
)
RELEASE_VERSION_RE = re.compile(
    r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$"
)
SAFE_COMPONENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+~-]{0,254}$")

CHANNEL_FIELDS = {
    "schema", "source_repository", "site_limit_bytes", "site_warning_bytes",
    "max_online_versions", "architectures", "channels",
}
PREVIEW_FIELDS = {"enabled", "status", "releases", "retirement", "publication"}
RELEASE_FIELDS = {
    "version", "source_sha", "source_release_id", "package_release_id",
    "deb_sha256", "rpm_sha256", "state", "not_before",
}
PUBLICATION_FIELDS = {
    "audit_release_id", "base_audit_release_id", "operation", "target_version",
}
PLAN_FIELDS = {
    "schema", "control_sha", "operation", "audit_release_id",
    "base_audit_release_id", "target_version", "active_versions",
    "retained_versions", "new_versions", "removed_versions", "not_before",
}
INVENTORY_FIELDS = {
    "schema", "audit_release_id", "active_versions", "retained_versions", "payloads",
}
INVENTORY_ENTRY_FIELDS = {
    "version", "path", "source_sha256", "published_sha256", "indexed", "new",
}
BOOTSTRAP_INVENTORY_FIELDS = {"schema", "version", "packages"}
BOOTSTRAP_PACKAGE_FIELDS = {
    "name", "version", "architecture", "filename", "repository_path", "download_path",
    "source_sha256", "source_size", "published_sha256", "published_size", "new",
}
SNAPSHOT_ENTRY_FIELDS = {
    "version", "path", "source_sha256", "published_sha256", "indexed",
}
KEY_RECEIPT_FIELDS = {
    "family", "historical_signing_subkey_fingerprints", "maximum_lifetime_days",
    "minimum_valid_days", "next_signing_subkey_fingerprint", "primary_fingerprint",
    "public_certificate_sha256", "public_certificate_size",
    "signing_subkey_created", "signing_subkey_expires",
    "signing_subkey_fingerprint", "validated",
}
ARTIFACT_FIELDS = {"path", "sha256", "size"}
SIGNING_FIELDS = {
    "schema", "enabled", "minimum_valid_days", "rotation_begin_days",
    "maximum_subkey_lifetime_days", "apt", "rpm",
}
SIGNING_FAMILY_FIELDS = {
    "environment", "public_key", "primary_fingerprint", "signing_subkeys",
    "secret_subkey_env", "passphrase_env",
}
SIGNING_SUBKEY_FIELDS = {"current", "next", "historical"}
PUBLIC_KEY_SNAPSHOT_FIELDS = {
    "path", "sha256", "size", "primary_fingerprint",
    "current_signing_subkey_fingerprint", "next_signing_subkey_fingerprint",
    "historical_signing_subkey_fingerprints",
}
SIGNING_TOOLCHAIN_FIELDS = {"schema", "enabled", "image", "digest", "workflow_sha"}
TOOLCHAIN_SNAPSHOT_FIELDS = {
    "image", "digest", "workflow_sha", "manifest_sha256", "manifest_size",
}
SOURCE_ATTESTATION_FIELDS = {
    "schema", "repository", "release_id", "tag", "version", "source_sha",
    "source_ref", "signer_workflow", "deny_self_hosted_runners", "asset_count",
    "assets", "assets_revalidated_after_attestations",
}
SOURCE_ATTESTATION_ASSET_FIELDS = {
    "asset", "asset_sha256", "evidence_file", "evidence_sha256",
}
SOURCE_ATTESTATION_SNAPSHOT_FIELDS = {"summary_sha256", "files"}


class CompositionError(ValueError):
    """Raised when signed publication inputs do not form one exact site."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise CompositionError(message)


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"


def digest_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in result, f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_json(path: Path, label: str, *, canonical: bool = False) -> Any:
    try:
        raw = read_checked(path, label, maximum_bytes=8 * 1024 * 1024)
        value = json.loads(raw, object_pairs_hook=reject_duplicate_pairs)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise CompositionError(f"cannot read {label}: {error}") from error
    if canonical:
        require(raw == canonical_json(value), f"{label} must use canonical JSON encoding")
    return value


def exact(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    require(isinstance(value, dict), f"{label} must be an object")
    require(set(value) == fields, f"{label} fields must be exactly {sorted(fields)}")
    return value


def positive_integer(value: Any, label: str) -> int:
    require(type(value) is int and value > 0, f"{label} must be a positive integer")
    return value


def sorted_strings(value: Any, label: str, *, allow_empty: bool = True) -> list[str]:
    require(isinstance(value, list) and all(isinstance(item, str) for item in value),
            f"{label} must be an array of strings")
    require(allow_empty or bool(value), f"{label} must not be empty")
    require(value == sorted(set(value)), f"{label} must be unique and sorted")
    return value


def safe_relative(value: Any, label: str) -> PurePosixPath:
    require(isinstance(value, str) and value != "" and "\\" not in value and "\x00" not in value,
            f"{label} must be a canonical relative POSIX path")
    path = PurePosixPath(value)
    require(not path.is_absolute() and path.as_posix() == value,
            f"{label} must be a canonical relative POSIX path")
    require(all(part not in {"", ".", ".."} and SAFE_COMPONENT_RE.fullmatch(part)
                for part in path.parts), f"{label} contains an unsafe path component")
    return path


def hash_file(path: Path, label: str, *, maximum_bytes: int | None = None) -> dict[str, Any]:
    try:
        before = path.lstat()
    except OSError as error:
        raise CompositionError(f"cannot inspect {label}") from error
    require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1,
            f"{label} must be a single-link regular file")
    require(before.st_size > 0, f"{label} must not be empty")
    if maximum_bytes is not None:
        require(before.st_size <= maximum_bytes, f"{label} exceeds its size limit")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise CompositionError(f"cannot safely open {label}") from error
    digest = hashlib.sha256()
    total = 0
    try:
        opened = os.fstat(descriptor)
        require(
            stat.S_ISREG(opened.st_mode) and opened.st_nlink == 1
            and (opened.st_dev, opened.st_ino, opened.st_size)
            == (before.st_dev, before.st_ino, before.st_size),
            f"{label} changed while it was opened",
        )
        while True:
            block = os.read(descriptor, COPY_CHUNK_BYTES)
            if not block:
                break
            digest.update(block)
            total += len(block)
        after = os.fstat(descriptor)
        require(
            (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            == (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
            and total == opened.st_size,
            f"{label} changed while it was read",
        )
    finally:
        os.close(descriptor)
    return {"sha256": digest.hexdigest(), "size": total}


def read_checked(
    path: Path,
    label: str,
    *,
    expected: dict[str, Any] | None = None,
    maximum_bytes: int | None = None,
) -> bytes:
    try:
        before = path.lstat()
    except OSError as error:
        raise CompositionError(f"cannot inspect {label}") from error
    require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1,
            f"{label} must be a single-link regular file")
    require(before.st_size > 0, f"{label} must not be empty")
    if maximum_bytes is not None:
        require(before.st_size <= maximum_bytes, f"{label} exceeds its size limit")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    chunks: list[bytes] = []
    digest = hashlib.sha256()
    total = 0
    try:
        opened = os.fstat(descriptor)
        require(
            stat.S_ISREG(opened.st_mode) and opened.st_nlink == 1
            and (opened.st_dev, opened.st_ino, opened.st_size)
            == (before.st_dev, before.st_ino, before.st_size),
            f"{label} changed while it was opened",
        )
        while True:
            block = os.read(descriptor, COPY_CHUNK_BYTES)
            if not block:
                break
            total += len(block)
            if maximum_bytes is not None:
                require(total <= maximum_bytes, f"{label} exceeds its size limit")
            chunks.append(block)
            digest.update(block)
        after = os.fstat(descriptor)
        require(
            (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            == (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
            and total == opened.st_size,
            f"{label} changed while it was read",
        )
    finally:
        os.close(descriptor)
    facts = {"sha256": digest.hexdigest(), "size": total}
    if expected is not None:
        expected_facts = {"sha256": expected.get("sha256"), "size": expected.get("size")}
        require(facts == expected_facts,
                f"{label} identity differs from its reviewed receipt")
    return b"".join(chunks)


def collect_tree(root: Path, label: str) -> tuple[dict[str, dict[str, Any]], set[str]]:
    try:
        metadata = root.lstat()
    except OSError as error:
        raise CompositionError(f"cannot inspect {label}") from error
    require(stat.S_ISDIR(metadata.st_mode), f"{label} must be a real directory")
    files: dict[str, dict[str, Any]] = {}
    directories: set[str] = set()
    for directory, names, filenames in os.walk(root, topdown=True, followlinks=False):
        current = Path(directory)
        relative_root = current.relative_to(root)
        for name in sorted(names):
            relative = (relative_root / name).as_posix()
            safe_relative(relative, f"{label} directory")
            child = current / name
            child_metadata = child.lstat()
            require(stat.S_ISDIR(child_metadata.st_mode),
                    f"{label} contains a linked or special directory: {relative}")
            directories.add(relative)
        for name in sorted(filenames):
            relative = (relative_root / name).as_posix()
            safe_relative(relative, f"{label} file")
            require(relative not in files, f"{label} contains duplicate path: {relative}")
            files[relative] = hash_file(current / name, f"{label} {relative}")
    require(files, f"{label} must not be empty")
    return files, directories


def expected_directories(paths: set[str]) -> set[str]:
    result: set[str] = set()
    for value in paths:
        parts = PurePosixPath(value).parts
        for index in range(1, len(parts)):
            result.add(PurePosixPath(*parts[:index]).as_posix())
    return result


def require_tree_closure(
    files: dict[str, dict[str, Any]], directories: set[str], expected_files: set[str], label: str
) -> None:
    require(set(files) == expected_files,
            f"{label} file closure differs from the reviewed receipt and inventory")
    require(directories == expected_directories(expected_files),
            f"{label} directory closure contains an extra or missing directory")


def validate_channels(value: Any) -> dict[str, Any]:
    channels = exact(value, CHANNEL_FIELDS, "channels manifest")
    require(channels["schema"] == CHANNELS_SCHEMA,
            f"channels schema must be {CHANNELS_SCHEMA}")
    require(channels["source_repository"] == "WuKongIM/WuKongIM",
            "channels source repository is unsupported")
    require(channels["site_limit_bytes"] == SITE_LIMIT_BYTES,
            f"site_limit_bytes must remain {SITE_LIMIT_BYTES}")
    require(channels["site_warning_bytes"] == SITE_WARNING_BYTES,
            f"site_warning_bytes must remain {SITE_WARNING_BYTES}")
    require(channels["max_online_versions"] == MAX_ONLINE_VERSIONS,
            f"max_online_versions must remain {MAX_ONLINE_VERSIONS}")
    require(channels["architectures"] == ["amd64"], "only amd64 is supported")
    channel_map = exact(channels["channels"], {"preview", "stable"}, "channels")
    preview = exact(channel_map["preview"], PREVIEW_FIELDS, "preview channel")
    stable = exact(channel_map["stable"], {"enabled", "status", "releases"}, "stable channel")
    require(stable == {"enabled": False, "status": "object_storage_required", "releases": []},
            "stable publishing is forbidden on Pages")
    require(preview["enabled"] is True and preview["status"] == "ready",
            "composer requires an enabled ready preview channel")
    releases_value = preview["releases"]
    require(isinstance(releases_value, list) and 0 < len(releases_value) <= MAX_ONLINE_VERSIONS,
            "preview releases must contain one through four versions")
    releases: dict[str, dict[str, Any]] = {}
    for index, raw in enumerate(releases_value):
        release = exact(raw, RELEASE_FIELDS, f"preview release {index}")
        version = release["version"]
        require(isinstance(version, str) and VERSION_RE.fullmatch(version),
                f"preview release {index}.version is invalid")
        require(version not in releases, "preview release versions must be unique")
        require(isinstance(release["source_sha"], str) and SHA_RE.fullmatch(release["source_sha"]),
                f"preview release {version} source_sha is invalid")
        positive_integer(release["source_release_id"], f"preview release {version} source_release_id")
        positive_integer(release["package_release_id"], f"preview release {version} package_release_id")
        for field in ("deb_sha256", "rpm_sha256"):
            require(isinstance(release[field], str) and SHA256_RE.fullmatch(release[field]),
                    f"preview release {version} {field} is invalid")
        require(release["state"] in {"active", "index_removed"},
                f"preview release {version} state is invalid")
        if release["state"] == "active":
            require(release["not_before"] is None,
                    f"active preview release {version} must have null not_before")
        else:
            require(isinstance(release["not_before"], str) and UTC_RE.fullmatch(release["not_before"]),
                    f"retained preview release {version} has invalid not_before")
        releases[version] = release
    retirement = exact(preview["retirement"], {"phase", "version", "not_before"},
                       "preview retirement")
    require(retirement["phase"] in {"none", "indexes_removed"},
            "preview retirement phase is invalid")
    retained_releases = [item for item in releases.values() if item["state"] == "index_removed"]
    require(len(retained_releases) <= 1, "preview may contain at most one retained release")
    if retirement["phase"] == "none":
        require(retirement["version"] is None and retirement["not_before"] is None
                and not retained_releases,
                "retirement none requires null fields and no retained release")
    else:
        require(len(retained_releases) == 1
                and retirement["version"] == retained_releases[0]["version"]
                and retirement["not_before"] == retained_releases[0]["not_before"],
                "indexes_removed retirement differs from the retained release")
    publication = exact(preview["publication"], PUBLICATION_FIELDS, "preview publication")
    require(publication["operation"] in {
        "add_release", "update_bootstrap", "remove_indexes", "remove_payloads",
    },
            "composer requires a concrete publication operation")
    if publication["operation"] == "remove_indexes":
        require(retirement["phase"] == "indexes_removed",
                "reviewed retirement phase differs from the publication operation")
    elif publication["operation"] != "update_bootstrap":
        require(retirement["phase"] == "none",
                "reviewed retirement phase differs from the publication operation")
    return {"manifest": channels, "preview": preview, "releases": releases,
            "retirement": retirement, "publication": publication}


def validate_signing_manifest(
    value: Any, apt_public_cert: Path, rpm_public_cert: Path
) -> dict[str, dict[str, Any]]:
    signing = exact(value, SIGNING_FIELDS, "preview signing manifest")
    require(signing["schema"] == SIGNING_SCHEMA,
            f"signing schema must be {SIGNING_SCHEMA}")
    require(signing["enabled"] is True, "composer requires enabled preview signing")
    require(signing["minimum_valid_days"] == 30
            and signing["rotation_begin_days"] == 45
            and signing["maximum_subkey_lifetime_days"] == 180,
            "preview signing policy differs from reviewed limits")
    expected = {
        "apt": (
            "native-package-preview-apt-signing", "keys/apt-preview.asc",
            "WK_APT_PREVIEW_SECRET_SUBKEY_B64", "WK_APT_PREVIEW_PASSPHRASE",
            apt_public_cert,
        ),
        "rpm": (
            "native-package-preview-rpm-signing", "keys/rpm-preview.asc",
            "WK_RPM_PREVIEW_SECRET_SUBKEY_B64", "WK_RPM_PREVIEW_PASSPHRASE",
            rpm_public_cert,
        ),
    }
    fingerprints: list[str] = []
    result: dict[str, dict[str, Any]] = {}
    for family, fixed in expected.items():
        environment, public_key, secret_env, passphrase_env, certificate = fixed
        values = exact(signing[family], SIGNING_FAMILY_FIELDS, f"signing.{family}")
        require(
            values["environment"] == environment
            and values["public_key"] == public_key
            and values["secret_subkey_env"] == secret_env
            and values["passphrase_env"] == passphrase_env,
            f"signing.{family} fixed custody fields changed",
        )
        require(certificate.name == PurePosixPath(public_key).name,
                f"{family} public certificate filename differs from reviewed control")
        primary = values["primary_fingerprint"]
        require(isinstance(primary, str) and FINGERPRINT_RE.fullmatch(primary),
                f"signing.{family}.primary_fingerprint is invalid")
        subkeys = exact(values["signing_subkeys"], SIGNING_SUBKEY_FIELDS,
                        f"signing.{family}.signing_subkeys")
        for field in ("current", "next"):
            require(isinstance(subkeys[field], str) and FINGERPRINT_RE.fullmatch(subkeys[field]),
                    f"signing.{family}.signing_subkeys.{field} is invalid")
        historical = sorted_strings(
            subkeys["historical"], f"signing.{family}.signing_subkeys.historical"
        )
        family_fingerprints = [primary, subkeys["current"], subkeys["next"], *historical]
        require(len(family_fingerprints) == len(set(family_fingerprints)),
                f"signing.{family} fingerprints must be distinct")
        fingerprints.extend(family_fingerprints)
        contents = read_checked(certificate, f"{family} reviewed public certificate",
                                maximum_bytes=1024 * 1024)
        require(contents.startswith(b"-----BEGIN PGP PUBLIC KEY BLOCK-----\n")
                and contents.rstrip().endswith(b"-----END PGP PUBLIC KEY BLOCK-----"),
                f"{family} reviewed public certificate must be ASCII armored")
        facts = hash_file(certificate, f"{family} reviewed public certificate",
                          maximum_bytes=1024 * 1024)
        result[family] = {
            "path": public_key,
            **facts,
            "primary_fingerprint": primary,
            "current_signing_subkey_fingerprint": subkeys["current"],
            "next_signing_subkey_fingerprint": subkeys["next"],
            "historical_signing_subkey_fingerprints": historical,
        }
    require(len(fingerprints) == len(set(fingerprints)),
            "APT and RPM reviewed signing fingerprints must all be distinct")
    require(len({value[-16:] for value in fingerprints}) == len(fingerprints),
            "APT and RPM reviewed signing fingerprints must have distinct 16-hex key IDs")
    require(len({value[-8:] for value in fingerprints}) == len(fingerprints),
            "APT and RPM reviewed signing fingerprints must have distinct 8-hex key IDs")
    return result


def validate_signing_toolchain(
    value: Any, manifest_facts: dict[str, Any]
) -> dict[str, Any]:
    toolchain = exact(value, SIGNING_TOOLCHAIN_FIELDS, "signing toolchain manifest")
    require(toolchain["schema"] == SIGNING_TOOLCHAIN_SCHEMA,
            f"signing toolchain schema must be {SIGNING_TOOLCHAIN_SCHEMA}")
    require(toolchain["enabled"] is True,
            "composer requires an enabled signing toolchain")
    require(toolchain["image"] == SIGNING_TOOLCHAIN_IMAGE,
            f"signing toolchain image must be {SIGNING_TOOLCHAIN_IMAGE}")
    require(isinstance(toolchain["digest"], str)
            and OCI_DIGEST_RE.fullmatch(toolchain["digest"]),
            "signing toolchain digest must be an immutable SHA-256 OCI digest")
    require(isinstance(toolchain["workflow_sha"], str)
            and SHA_RE.fullmatch(toolchain["workflow_sha"]),
            "signing toolchain workflow_sha must be a lowercase 40-hex commit")
    return {
        "image": toolchain["image"],
        "digest": toolchain["digest"],
        "workflow_sha": toolchain["workflow_sha"],
        "manifest_sha256": manifest_facts["sha256"],
        "manifest_size": manifest_facts["size"],
    }


def validate_source_attestations(
    root: Path | None,
    plan: dict[str, Any],
    control: dict[str, Any],
) -> tuple[dict[str, Any] | None, dict[str, dict[str, Any]]]:
    if plan["operation"] != "add_release":
        require(root is None,
                "source attestation evidence is forbidden for a retirement publication")
        return None, {}
    require(root is not None,
            "add_release requires the complete source attestation evidence directory")
    files, directories = collect_tree(root, "source attestation evidence")
    summary_name = "source-attestations.json"
    require(summary_name in files,
            "source attestation evidence omits source-attestations.json")
    summary = exact(
        load_json(root / summary_name, "source attestation summary", canonical=True),
        SOURCE_ATTESTATION_FIELDS,
        "source attestation summary",
    )
    target = plan["target_version"]
    release = control["releases"][target]
    require(summary["schema"] == SOURCE_ATTESTATION_SCHEMA,
            f"source attestation schema must be {SOURCE_ATTESTATION_SCHEMA}")
    require(summary["repository"] == SOURCE_REPOSITORY
            and summary["release_id"] == release["source_release_id"]
            and summary["version"] == target
            and summary["tag"] == f"v{target}"
            and summary["source_sha"] == release["source_sha"]
            and summary["source_ref"] == f"refs/tags/v{target}",
            "source attestation identity differs from the reviewed release")
    require(summary["signer_workflow"] == SOURCE_SIGNER_WORKFLOW
            and summary["deny_self_hosted_runners"] is True
            and summary["assets_revalidated_after_attestations"] is True,
            "source attestation policy checks are incomplete")
    require(summary["asset_count"] == 7
            and isinstance(summary["assets"], list)
            and len(summary["assets"]) == 7,
            "source attestation must close over seven assets")
    expected_files = {summary_name}
    assets: dict[str, dict[str, Any]] = {}
    prior = ""
    for index, raw in enumerate(summary["assets"]):
        asset = exact(raw, SOURCE_ATTESTATION_ASSET_FIELDS,
                      f"source attestation asset {index}")
        name = asset["asset"]
        require(isinstance(name, str) and name > prior and PurePosixPath(name).name == name,
                "source attestation asset names must be safe, unique, and sorted")
        require(isinstance(asset["asset_sha256"], str)
                and SHA256_RE.fullmatch(asset["asset_sha256"]),
                f"source attestation asset SHA-256 is invalid for {name}")
        evidence = asset["evidence_file"]
        require(isinstance(evidence, str) and PurePosixPath(evidence).name == evidence
                and evidence.endswith(".attestation.json"),
                f"source attestation evidence filename is invalid for {name}")
        require(isinstance(asset["evidence_sha256"], str)
                and SHA256_RE.fullmatch(asset["evidence_sha256"]),
                f"source attestation evidence SHA-256 is invalid for {name}")
        require(evidence not in expected_files,
                "source attestation evidence filenames must be unique")
        expected_files.add(evidence)
        assets[name] = asset
        prior = name
    require_tree_closure(files, directories, expected_files, "source attestation evidence")
    for asset in assets.values():
        evidence = asset["evidence_file"]
        load_json(root / evidence, f"source attestation evidence {evidence}", canonical=True)
        require(files[evidence]["sha256"] == asset["evidence_sha256"],
                f"source attestation evidence digest differs for {asset['asset']}")
    deb_name = f"wukongim_{target}_linux_amd64.deb"
    rpm_name = f"wukongim_{target}_linux_amd64.rpm"
    require(deb_name in assets and rpm_name in assets
            and assets[deb_name]["asset_sha256"] == release["deb_sha256"]
            and assets[rpm_name]["asset_sha256"] == release["rpm_sha256"],
            "source attestation package digests differ from the reviewed release")
    inventory = [
        {"path": f"audit/source-attestations/{name}", **files[name]}
        for name in sorted(files)
    ]
    return {
        "summary_sha256": files[summary_name]["sha256"],
        "files": inventory,
    }, files


def validate_plan(value: Any, control: dict[str, Any]) -> dict[str, Any]:
    plan = exact(value, PLAN_FIELDS, "publication plan")
    require(plan["schema"] == PLAN_SCHEMA, f"publication plan schema must be {PLAN_SCHEMA}")
    require(isinstance(plan["control_sha"], str) and SHA_RE.fullmatch(plan["control_sha"]),
            "publication plan control_sha must be a lowercase 40-hex commit")
    publication = control["publication"]
    for field in ("operation", "audit_release_id", "base_audit_release_id", "target_version"):
        require(plan[field] == publication[field],
                f"publication plan {field} differs from reviewed channels")
    positive_integer(plan["audit_release_id"], "publication plan audit_release_id")
    if plan["base_audit_release_id"] is not None:
        positive_integer(plan["base_audit_release_id"], "publication plan base_audit_release_id")
        require(plan["base_audit_release_id"] != plan["audit_release_id"],
                "publication audit and base Release IDs must differ")
    active = sorted_strings(plan["active_versions"], "publication plan active_versions",
                            allow_empty=False)
    retained = sorted_strings(plan["retained_versions"], "publication plan retained_versions")
    new = sorted_strings(plan["new_versions"], "publication plan new_versions")
    removed = sorted_strings(plan["removed_versions"], "publication plan removed_versions")
    require(not (set(active) & set(retained)), "active and retained versions must be disjoint")
    require(len(active) + len(retained) <= MAX_ONLINE_VERSIONS,
            "publication plan exceeds the online-version limit")
    releases = control["releases"]
    require(set(active) == {version for version, item in releases.items() if item["state"] == "active"},
            "publication plan active_versions differ from reviewed releases")
    require(set(retained) == {
        version for version, item in releases.items() if item["state"] == "index_removed"
    }, "publication plan retained_versions differ from reviewed releases")
    operation = plan["operation"]
    target = plan["target_version"]
    require(isinstance(target, str) and VERSION_RE.fullmatch(target),
            "publication plan target_version is invalid")
    if operation == "add_release":
        require(new == [target] and removed == [] and plan["not_before"] is None,
                "add_release plan has an invalid version transition")
    elif operation == "update_bootstrap":
        require(new == [] and removed == [] and target in active
                and plan["not_before"] is None,
                "update_bootstrap plan has an invalid version transition")
    elif operation == "remove_indexes":
        require(new == [] and removed == [] and target in retained,
                "remove_indexes plan has an invalid version transition")
        require(plan["not_before"] == releases[target]["not_before"],
                "remove_indexes plan not_before differs from reviewed release")
    else:
        require(new == [] and removed == [target] and target not in releases,
                "remove_payloads plan has an invalid version transition")
        require(isinstance(plan["not_before"], str) and UTC_RE.fullmatch(plan["not_before"]),
                "remove_payloads plan not_before is invalid")
    return plan


def expected_payload_path(family: str, version: str) -> str:
    filename = f"wukongim_{version}_linux_amd64.{ 'deb' if family == 'apt' else 'rpm' }"
    if family == "apt":
        return f"apt/pool/main/w/wukongim/{filename}"
    return f"rpm/preview/el/9/x86_64/Packages/{filename}"


def validate_inventory(
    value: Any, plan: dict[str, Any], control: dict[str, Any]
) -> dict[str, dict[str, dict[str, Any]]]:
    inventory = exact(value, INVENTORY_FIELDS, "payload inventory")
    require(inventory["schema"] == INVENTORY_SCHEMA,
            f"payload inventory schema must be {INVENTORY_SCHEMA}")
    require(inventory["audit_release_id"] == plan["audit_release_id"],
            "payload inventory audit Release differs from the publication plan")
    require(inventory["active_versions"] == plan["active_versions"]
            and inventory["retained_versions"] == plan["retained_versions"],
            "payload inventory version sets differ from the publication plan")
    payloads = exact(inventory["payloads"], {"apt", "rpm"}, "payload inventory families")
    expected_versions = set(plan["active_versions"]) | set(plan["retained_versions"])
    result: dict[str, dict[str, dict[str, Any]]] = {}
    for family, digest_field in (("apt", "deb_sha256"), ("rpm", "rpm_sha256")):
        values = payloads[family]
        require(isinstance(values, list), f"payload inventory {family} must be an array")
        versions: dict[str, dict[str, Any]] = {}
        prior = ""
        for index, raw in enumerate(values):
            item = exact(raw, INVENTORY_ENTRY_FIELDS, f"payload inventory {family} {index}")
            version = item["version"]
            require(isinstance(version, str) and version in expected_versions and version > prior,
                    f"payload inventory {family} versions must be exact, unique, and sorted")
            require(item["path"] == expected_payload_path(family, version),
                    f"payload inventory {family} path is not canonical for {version}")
            safe_relative(item["path"], f"payload inventory {family} path")
            for field in ("source_sha256", "published_sha256"):
                require(isinstance(item[field], str) and SHA256_RE.fullmatch(item[field]),
                        f"payload inventory {family} {version} {field} is invalid")
            require(item["source_sha256"] == control["releases"][version][digest_field],
                    f"payload inventory {family} source digest differs from reviewed release {version}")
            require(type(item["indexed"]) is bool
                    and item["indexed"] == (version in plan["active_versions"]),
                    f"payload inventory {family} indexed state differs for {version}")
            require(type(item["new"]) is bool
                    and item["new"] == (version in plan["new_versions"]),
                    f"payload inventory {family} new state differs for {version}")
            if family == "apt":
                require(item["published_sha256"] == item["source_sha256"],
                        f"APT payload bytes must remain unchanged for {version}")
            elif item["new"]:
                require(item["published_sha256"] == item["source_sha256"],
                        f"new RPM inventory must describe unsigned source bytes for {version}")
            versions[version] = item
            prior = version
        require(set(versions) == expected_versions,
                f"payload inventory {family} does not close over reviewed versions")
        result[family] = versions
    return result


def expected_bootstrap_package(family: str, version: str) -> dict[str, str]:
    if family == "apt":
        filename = f"wukongim-archive-keyring_{version}_all.deb"
        return {
            "name": "wukongim-archive-keyring",
            "architecture": "all",
            "filename": filename,
            "repository_path": f"apt/pool/main/w/wukongim/{filename}",
            "download_path": f"bootstrap/{filename}",
        }
    require(family == "rpm", "bootstrap package family is unsupported")
    filename = f"wukongim-release-{version}-1.noarch.rpm"
    return {
        "name": "wukongim-release",
        "architecture": "noarch",
        "filename": filename,
        "repository_path": f"rpm/preview/el/9/x86_64/Packages/{filename}",
        "download_path": f"bootstrap/{filename}",
    }


def release_version_order(version: str) -> tuple[int, int, int]:
    require(RELEASE_VERSION_RE.fullmatch(version) is not None,
            "bootstrap package version must be strict release SemVer")
    major, minor, patch = version.split(".")
    return int(major), int(minor), int(patch)


def validate_bootstrap_inventory(
    value: Any, *, prepared: bool, label: str = "bootstrap inventory"
) -> dict[str, Any]:
    inventory = exact(value, BOOTSTRAP_INVENTORY_FIELDS, label)
    require(inventory["schema"] == BOOTSTRAP_INVENTORY_SCHEMA,
            f"{label} schema must be {BOOTSTRAP_INVENTORY_SCHEMA}")
    version = inventory["version"]
    require(isinstance(version, str) and RELEASE_VERSION_RE.fullmatch(version),
            f"{label} version must be strict release SemVer")
    packages = exact(inventory["packages"], {"apt", "rpm"}, f"{label} packages")
    validated: dict[str, dict[str, Any]] = {}
    for family in ("apt", "rpm"):
        item = exact(packages[family], BOOTSTRAP_PACKAGE_FIELDS,
                     f"{label} {family} package")
        expected = expected_bootstrap_package(family, version)
        require(item["version"] == version,
                f"{label} {family} package version differs from the inventory version")
        for field, expected_value in expected.items():
            require(item[field] == expected_value,
                    f"{label} {family} package {field} must be {expected_value}")
        safe_relative(item["repository_path"], f"{label} {family} repository path")
        safe_relative(item["download_path"], f"{label} {family} download path")
        for field in ("source_sha256", "published_sha256"):
            require(isinstance(item[field], str) and SHA256_RE.fullmatch(item[field]),
                    f"{label} {family} {field} is invalid")
        for field in ("source_size", "published_size"):
            positive_integer(item[field], f"{label} {family} {field}")
        require(type(item["new"]) is bool, f"{label} {family} new must be boolean")
        if family == "apt":
            require((item["published_sha256"], item["published_size"])
                    == (item["source_sha256"], item["source_size"]),
                    "APT bootstrap package bytes must remain unchanged")
        elif prepared and item["new"]:
            require((item["published_sha256"], item["published_size"])
                    == (item["source_sha256"], item["source_size"]),
                    "new RPM bootstrap inventory must describe unsigned source bytes")
        validated[family] = dict(item)
    return {"schema": inventory["schema"], "version": version, "packages": validated}


def validate_bootstrap_transition(
    base_site: Path | None, plan: dict[str, Any], current: dict[str, Any]
) -> dict[str, Any] | None:
    if base_site is None:
        require(all(item["new"] for item in current["packages"].values()),
                "first publication bootstrap packages must both be new")
        return None
    manifest_path = base_site / "bootstrap/manifest.json"
    if not os.path.lexists(manifest_path):
        require(plan["operation"] == "update_bootstrap",
                "a base without bootstrap packages requires update_bootstrap")
        require(all(item["new"] for item in current["packages"].values()),
                "initial bootstrap packages must both be new")
        return None
    base = validate_bootstrap_inventory(
        load_json(manifest_path, "base bootstrap manifest", canonical=True),
        prepared=False,
        label="base bootstrap manifest",
    )
    for family, item in base["packages"].items():
        facts = {"sha256": item["published_sha256"], "size": item["published_size"]}
        for field in ("repository_path", "download_path"):
            require(hash_file(base_site / item[field], f"base bootstrap {family} {field}") == facts,
                    f"base bootstrap {family} {field} differs from its manifest")
    changed = current["version"] != base["version"]
    if changed:
        require(
            release_version_order(current["version"])
            > release_version_order(base["version"]),
            "bootstrap package version must increase",
        )
        require(all(item["new"] for item in current["packages"].values()),
                "changed bootstrap packages must both be new")
    else:
        for family in ("apt", "rpm"):
            item = current["packages"][family]
            previous = base["packages"][family]
            require((item["source_sha256"], item["source_size"])
                    == (previous["source_sha256"], previous["source_size"]),
                    f"bootstrap {family} source changed without a version bump")
            require(item["new"] is False,
                    f"unchanged bootstrap {family} package must be preserved")
            require((item["published_sha256"], item["published_size"])
                    == (previous["published_sha256"], previous["published_size"]),
                    f"preserved bootstrap {family} package differs from the base")
    if plan["operation"] == "update_bootstrap":
        require(changed, "update_bootstrap must change the bootstrap package version")
    else:
        require(not changed,
                "bootstrap package version changes require update_bootstrap")
    return base


def validate_snapshot_entry(raw: Any, family: str, index: int) -> dict[str, Any]:
    item = exact(raw, SNAPSHOT_ENTRY_FIELDS, f"base {family} payload {index}")
    require(isinstance(item["version"], str) and VERSION_RE.fullmatch(item["version"]),
            f"base {family} payload version is invalid")
    require(item["path"] == expected_payload_path(family, item["version"]),
            f"base {family} payload path is not canonical")
    for field in ("source_sha256", "published_sha256"):
        require(isinstance(item[field], str) and SHA256_RE.fullmatch(item[field]),
                f"base {family} payload {field} is invalid")
    require(type(item["indexed"]) is bool, f"base {family} payload indexed must be boolean")
    return item


def validate_public_key_snapshot(raw: Any, family: str, site: Path) -> dict[str, Any]:
    item = exact(raw, PUBLIC_KEY_SNAPSHOT_FIELDS, f"base {family} public key")
    expected_path = f"keys/{family}-preview.asc"
    require(item["path"] == expected_path,
            f"base {family} public-key path must be {expected_path}")
    for field in (
        "primary_fingerprint", "current_signing_subkey_fingerprint",
        "next_signing_subkey_fingerprint",
    ):
        require(isinstance(item[field], str) and FINGERPRINT_RE.fullmatch(item[field]),
                f"base {family} public key {field} is invalid")
    sorted_strings(item["historical_signing_subkey_fingerprints"],
                   f"base {family} historical signing-subkey fingerprints")
    require(isinstance(item["sha256"], str) and SHA256_RE.fullmatch(item["sha256"]),
            f"base {family} public-key SHA-256 is invalid")
    positive_integer(item["size"], f"base {family} public-key size")
    facts = hash_file(site / expected_path, f"base {family} public certificate",
                      maximum_bytes=1024 * 1024)
    require(facts == {"sha256": item["sha256"], "size": item["size"]},
            f"base {family} public certificate differs from its snapshot inventory")
    return item


def validate_toolchain_snapshot(raw: Any, label: str) -> dict[str, Any]:
    item = exact(raw, TOOLCHAIN_SNAPSHOT_FIELDS, label)
    require(item["image"] == SIGNING_TOOLCHAIN_IMAGE,
            f"{label} image is invalid")
    require(isinstance(item["digest"], str) and OCI_DIGEST_RE.fullmatch(item["digest"]),
            f"{label} digest is invalid")
    require(isinstance(item["workflow_sha"], str) and SHA_RE.fullmatch(item["workflow_sha"]),
            f"{label} workflow_sha is invalid")
    require(isinstance(item["manifest_sha256"], str)
            and SHA256_RE.fullmatch(item["manifest_sha256"]),
            f"{label} manifest_sha256 is invalid")
    positive_integer(item["manifest_size"], f"{label} manifest_size")
    return item


def validate_source_attestation_snapshot(
    raw: Any,
    root: Path,
    label: str,
) -> dict[str, Any] | None:
    evidence_root = root / "audit/source-attestations"
    if raw is None:
        require(not os.path.lexists(evidence_root),
                f"{label} evidence directory is forbidden when inventory is null")
        return None
    item = exact(raw, SOURCE_ATTESTATION_SNAPSHOT_FIELDS, label)
    require(isinstance(item["summary_sha256"], str)
            and SHA256_RE.fullmatch(item["summary_sha256"]),
            f"{label} summary_sha256 is invalid")
    values = item["files"]
    require(isinstance(values, list) and len(values) == 8,
            f"{label} files must contain eight entries")
    expected: dict[str, dict[str, Any]] = {}
    prior = ""
    for index, raw_file in enumerate(values):
        artifact = exact(raw_file, ARTIFACT_FIELDS, f"{label} file {index}")
        path = safe_relative(artifact["path"], f"{label} file path")
        require(path.as_posix() > prior
                and path.parts[:2] == ("audit", "source-attestations")
                and len(path.parts) == 3,
                f"{label} file paths must be exact, unique, and sorted")
        require(isinstance(artifact["sha256"], str)
                and SHA256_RE.fullmatch(artifact["sha256"]),
                f"{label} file SHA-256 is invalid")
        positive_integer(artifact["size"], f"{label} file size")
        expected[path.name] = {"sha256": artifact["sha256"], "size": artifact["size"]}
        prior = path.as_posix()
    require("source-attestations.json" in expected
            and expected["source-attestations.json"]["sha256"] == item["summary_sha256"],
            f"{label} summary identity differs from its file inventory")
    files, directories = collect_tree(evidence_root, f"{label} archived evidence")
    require_tree_closure(files, directories, set(expected), f"{label} archived evidence")
    require(files == expected, f"{label} archived evidence differs from its inventory")
    return item


def load_base(
    base_root: Path | None,
    plan: dict[str, Any],
    inventory: dict[str, dict[str, dict[str, Any]]],
    control: dict[str, Any],
) -> tuple[dict[str, Any] | None, Path | None, dict[str, dict[str, dict[str, Any]]]]:
    expected_id = plan["base_audit_release_id"]
    if expected_id is None:
        require(base_root is None, "base root is forbidden without a reviewed base snapshot")
        require(plan["operation"] == "add_release" and plan["new_versions"] == plan["active_versions"],
                "only a first add_release may omit the base snapshot")
        return None, None, {"apt": {}, "rpm": {}}
    require(base_root is not None, "base root is required by the publication plan")
    try:
        root_metadata = base_root.lstat()
    except OSError as error:
        raise CompositionError("cannot inspect base snapshot root") from error
    require(stat.S_ISDIR(root_metadata.st_mode), "base snapshot root must be a real directory")
    snapshot = exact(load_json(base_root / "audit/snapshot.json", "base snapshot"),
                     {"schema", "audit_release_id", "control_sha", "releases", "retirement",
                      "payloads", "public_keys", "source_attestations", "toolchain"},
                     "base snapshot")
    require(snapshot["schema"] == SNAPSHOT_SCHEMA,
            f"base snapshot schema must be {SNAPSHOT_SCHEMA}")
    require(snapshot["audit_release_id"] == expected_id,
            "base snapshot audit Release differs from the publication plan")
    require(isinstance(snapshot["control_sha"], str) and SHA_RE.fullmatch(snapshot["control_sha"]),
            "base snapshot control_sha is invalid")
    base_toolchain = validate_toolchain_snapshot(
        snapshot["toolchain"], "base signing toolchain"
    )
    require(
        hash_file(base_root / "audit/signing-toolchain.json",
                  "base signing toolchain manifest")
        == {"sha256": base_toolchain["manifest_sha256"],
            "size": base_toolchain["manifest_size"]},
        "base signing toolchain manifest differs from its snapshot inventory",
    )
    validate_source_attestation_snapshot(
        snapshot["source_attestations"], base_root, "base source attestation inventory"
    )
    require(isinstance(snapshot["releases"], list), "base snapshot releases must be an array")
    base_releases: dict[str, dict[str, Any]] = {}
    for index, raw in enumerate(snapshot["releases"]):
        item = exact(raw, RELEASE_FIELDS, f"base release {index}")
        version = item["version"]
        require(isinstance(version, str) and VERSION_RE.fullmatch(version)
                and version not in base_releases,
                "base release version is invalid or duplicated")
        require(isinstance(item["source_sha"], str) and SHA_RE.fullmatch(item["source_sha"]),
                f"base release {version} source_sha is invalid")
        positive_integer(item["source_release_id"], f"base release {version} source_release_id")
        positive_integer(item["package_release_id"], f"base release {version} package_release_id")
        for field in ("deb_sha256", "rpm_sha256"):
            require(isinstance(item[field], str) and SHA256_RE.fullmatch(item[field]),
                    f"base release {version} {field} is invalid")
        require(item["state"] in {"active", "index_removed"},
                f"base release {version} state is invalid")
        if item["state"] == "active":
            require(item["not_before"] is None,
                    f"base active release {version} must have null not_before")
        else:
            require(isinstance(item["not_before"], str) and UTC_RE.fullmatch(item["not_before"]),
                    f"base retained release {version} not_before is invalid")
        base_releases[version] = item
    base_retirement = exact(
        snapshot["retirement"], {"phase", "version", "not_before"}, "base retirement"
    )
    families = exact(snapshot["payloads"], {"apt", "rpm"}, "base payload families")
    base_entries: dict[str, dict[str, dict[str, Any]]] = {}
    base_site = base_root / "site"
    require(base_site.is_dir() and not base_site.is_symlink(), "base site must be a real directory")
    public_keys = exact(snapshot["public_keys"], {"apt", "rpm"}, "base public keys")
    base_key_fingerprints: list[str] = []
    for family in ("apt", "rpm"):
        key = validate_public_key_snapshot(public_keys[family], family, base_site)
        base_key_fingerprints.extend([
            key["primary_fingerprint"], key["current_signing_subkey_fingerprint"],
            key["next_signing_subkey_fingerprint"],
            *key["historical_signing_subkey_fingerprints"],
        ])
    require(len(base_key_fingerprints) == len(set(base_key_fingerprints)),
            "base APT and RPM public-key fingerprints must all be distinct")
    require(len({value[-16:] for value in base_key_fingerprints})
            == len(base_key_fingerprints),
            "base APT and RPM public-key fingerprints must have distinct 16-hex key IDs")
    require(len({value[-8:] for value in base_key_fingerprints})
            == len(base_key_fingerprints),
            "base APT and RPM public-key fingerprints must have distinct 8-hex key IDs")
    for family in ("apt", "rpm"):
        values = families[family]
        require(isinstance(values, list), f"base {family} payloads must be an array")
        entries: dict[str, dict[str, Any]] = {}
        prior = ""
        for index, raw in enumerate(values):
            item = validate_snapshot_entry(raw, family, index)
            version = item["version"]
            require(version > prior and version not in entries,
                    f"base {family} payload versions must be unique and sorted")
            path = base_site.joinpath(*PurePosixPath(item["path"]).parts)
            facts = hash_file(path, f"base {family} payload {version}")
            require(facts["sha256"] == item["published_sha256"],
                    f"base {family} payload digest differs from its snapshot inventory")
            entries[version] = item
            prior = version
        base_entries[family] = entries
    require(set(base_entries["apt"]) == set(base_entries["rpm"]),
            "base APT and RPM payload versions differ")
    require(set(base_releases) == set(base_entries["apt"]),
            "base release list and payload inventory versions differ")
    for family, digest_field in (("apt", "deb_sha256"), ("rpm", "rpm_sha256")):
        for version, item in base_entries[family].items():
            require(item["source_sha256"] == base_releases[version][digest_field],
                    f"base {family} source digest differs from release {version}")
            require(item["indexed"] == (base_releases[version]["state"] == "active"),
                    f"base {family} indexed state differs from release {version}")

    current_versions = set(inventory["apt"])
    base_versions = set(base_entries["apt"])
    target = plan["target_version"]
    if plan["operation"] == "add_release":
        require(base_versions == current_versions - {target} and target not in base_versions,
                "base inventory does not match the add_release transition")
        require(base_retirement == {"phase": "none", "version": None, "not_before": None},
                "add_release base must not have a retirement in progress")
    elif plan["operation"] == "update_bootstrap":
        require(base_versions == current_versions,
                "base inventory does not match the update_bootstrap transition")
        require(base_retirement == control["retirement"],
                "update_bootstrap must not change retirement state")
    elif plan["operation"] == "remove_indexes":
        require(base_versions == current_versions and target in base_versions,
                "base inventory does not match the remove_indexes transition")
        require(base_retirement == {"phase": "none", "version": None, "not_before": None},
                "remove_indexes base must not have a retirement in progress")
    else:
        require(base_versions == current_versions | {target} and target in base_versions,
                "base inventory does not match the remove_payloads transition")
        require(base_retirement == {
            "phase": "indexes_removed", "version": target, "not_before": plan["not_before"],
        }, "remove_payloads base retirement differs from the publication plan")
    current_releases = control["releases"]
    if plan["operation"] == "add_release":
        require(set(base_releases) == set(current_releases) - {target},
                "base releases do not match the add_release transition")
        for version in base_releases:
            require(base_releases[version] == current_releases[version],
                    f"add_release changed existing release {version}")
    elif plan["operation"] == "update_bootstrap":
        require(base_releases == current_releases,
                "update_bootstrap must not change product releases")
    elif plan["operation"] == "remove_indexes":
        require(set(base_releases) == set(current_releases),
                "base releases do not match the remove_indexes transition")
        for version in base_releases:
            if version == target:
                expected = dict(base_releases[version], state="index_removed",
                                not_before=plan["not_before"])
                require(current_releases[version] == expected,
                        "remove_indexes changed target identity beyond retirement fields")
            else:
                require(base_releases[version] == current_releases[version],
                        f"remove_indexes changed unrelated release {version}")
    else:
        require(set(base_releases) == set(current_releases) | {target}
                and base_releases[target]["state"] == "index_removed"
                and base_releases[target]["not_before"] == plan["not_before"],
                "base releases do not match the remove_payloads transition")
        for version in current_releases:
            require(base_releases[version] == current_releases[version],
                    f"remove_payloads changed retained release {version}")
    for family in ("apt", "rpm"):
        for version in current_versions & base_versions:
            current = inventory[family][version]
            previous = base_entries[family][version]
            for field in ("version", "path", "source_sha256", "published_sha256"):
                require(current[field] == previous[field],
                        f"{family} payload identity changed from base for {version}")
            expected_indexed = current["indexed"]
            if plan["operation"] == "remove_indexes" and version == target:
                require(previous["indexed"] is True and expected_indexed is False,
                        f"{family} remove_indexes target did not transition out of indexes")
            else:
                require(previous["indexed"] == expected_indexed,
                        f"{family} indexed state changed unexpectedly for {version}")
        if plan["operation"] == "remove_payloads":
            require(base_entries[family][target]["indexed"] is False,
                    f"{family} remove_payloads target was still indexed in the base")
    return snapshot, base_site, base_entries


def validate_key_receipt(raw: Any, family: str) -> dict[str, Any]:
    key = exact(raw, KEY_RECEIPT_FIELDS, f"{family} signing key receipt")
    require(key["family"] == family and key["validated"] is True,
            f"{family} signing key receipt is not validated for its family")
    require(key["minimum_valid_days"] == 30 and key["maximum_lifetime_days"] == 180,
            f"{family} signing key receipt policy differs from reviewed limits")
    for field in ("primary_fingerprint", "signing_subkey_fingerprint"):
        require(isinstance(key[field], str) and FINGERPRINT_RE.fullmatch(key[field]),
                f"{family} signing key {field} is invalid")
    next_fingerprint = key["next_signing_subkey_fingerprint"]
    require(next_fingerprint is None
            or (isinstance(next_fingerprint, str) and FINGERPRINT_RE.fullmatch(next_fingerprint)),
            f"{family} signing key next_signing_subkey_fingerprint is invalid")
    historical = sorted_strings(
        key["historical_signing_subkey_fingerprints"],
        f"{family} signing key historical fingerprints",
    )
    fingerprints = [
        key["primary_fingerprint"], key["signing_subkey_fingerprint"],
        *([next_fingerprint] if next_fingerprint is not None else []), *historical,
    ]
    require(len(fingerprints) == len(set(fingerprints)),
            f"{family} signing key fingerprints must be distinct")
    require(isinstance(key["public_certificate_sha256"], str)
            and SHA256_RE.fullmatch(key["public_certificate_sha256"]),
            f"{family} signing key public_certificate_sha256 is invalid")
    positive_integer(key["public_certificate_size"],
                     f"{family} signing key public_certificate_size")
    for field in ("signing_subkey_created", "signing_subkey_expires"):
        require(isinstance(key[field], str) and UTC_RE.fullmatch(key[field]),
                f"{family} signing key {field} is invalid")
    return key


def require_reviewed_key_receipt(
    key: dict[str, Any], reviewed: dict[str, Any], family: str
) -> None:
    require(
        key["primary_fingerprint"] == reviewed["primary_fingerprint"]
        and key["signing_subkey_fingerprint"]
        == reviewed["current_signing_subkey_fingerprint"]
        and key["next_signing_subkey_fingerprint"]
        == reviewed["next_signing_subkey_fingerprint"]
        and key["historical_signing_subkey_fingerprints"]
        == reviewed["historical_signing_subkey_fingerprints"]
        and key["public_certificate_sha256"] == reviewed["sha256"]
        and key["public_certificate_size"] == reviewed["size"],
        f"{family} signing receipt differs from the reviewed public certificate",
    )


def parse_artifact(raw: Any, label: str) -> dict[str, Any]:
    artifact = exact(raw, ARTIFACT_FIELDS, label)
    safe_relative(artifact["path"], f"{label} path")
    require(isinstance(artifact["sha256"], str) and SHA256_RE.fullmatch(artifact["sha256"]),
            f"{label} SHA-256 is invalid")
    positive_integer(artifact["size"], f"{label} size")
    require(artifact["size"] <= SITE_LIMIT_BYTES, f"{label} exceeds the site hard limit")
    return artifact


def artifact_list(raw: Any, label: str) -> dict[str, dict[str, Any]]:
    require(isinstance(raw, list), f"{label} must be an array")
    result: dict[str, dict[str, Any]] = {}
    prior = ""
    for index, value in enumerate(raw):
        item = parse_artifact(value, f"{label} {index}")
        require(item["path"] > prior and item["path"] not in result,
                f"{label} paths must be unique and sorted")
        result[item["path"]] = item
        prior = item["path"]
    return result


def require_artifact_identity(
    artifact: dict[str, Any], actual: dict[str, dict[str, Any]], path: str, label: str
) -> None:
    require(path in actual, f"{label} is missing from its signed tree: {path}")
    require({"sha256": artifact["sha256"], "size": artifact["size"]} == actual[path],
            f"{label} identity differs from its signing receipt: {path}")


def load_signing_receipt(path: Path, family: str) -> dict[str, Any]:
    receipt = exact(load_json(path, f"{family} signing receipt", canonical=True),
                    {"schema", "family", "key", "result"}, f"{family} signing receipt")
    require(receipt["schema"] == SIGNING_RECEIPT_SCHEMA,
            f"{family} signing receipt schema must be {SIGNING_RECEIPT_SCHEMA}")
    require(receipt["family"] == family, f"{family} signing receipt has the wrong family")
    validate_key_receipt(receipt["key"], family)
    return receipt


def parse_apt_packages(data: bytes) -> dict[str, dict[str, Any]]:
    require(len(data) <= MAX_METADATA_BYTES, "APT Packages metadata exceeds its size limit")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise CompositionError("APT Packages metadata is not UTF-8") from error
    paragraphs: list[dict[str, str]] = []
    fields: dict[str, str] = {}
    last_key: str | None = None
    for line in text.splitlines():
        if not line:
            if fields:
                paragraphs.append(fields)
                fields = {}
                last_key = None
            continue
        if line[0] in " \t":
            require(last_key is not None, "APT Packages stanza has an orphan continuation")
            fields[last_key] += "\n" + line[1:]
            continue
        require(":" in line, "APT Packages stanza contains a malformed field")
        name, value = line.split(":", 1)
        require(name and name not in fields, "APT Packages stanza contains a duplicate field")
        fields[name] = value.lstrip()
        last_key = name
    if fields:
        paragraphs.append(fields)
    paths: dict[str, dict[str, Any]] = {}
    for fields in paragraphs:
        require({"Filename", "Size", "SHA256"}.issubset(fields),
                "APT Packages stanza lacks Filename, Size, or SHA256")
        path = safe_relative(fields["Filename"], "APT Packages Filename").as_posix()
        require(path not in paths, "APT Packages metadata contains a duplicate payload")
        try:
            size = int(fields["Size"])
        except ValueError as error:
            raise CompositionError("APT Packages payload Size is invalid") from error
        positive_integer(size, "APT Packages payload Size")
        require(SHA256_RE.fullmatch(fields["SHA256"]) is not None,
                "APT Packages payload SHA256 is invalid")
        paths[path] = {"sha256": fields["SHA256"], "size": size}
    require(paths, "APT Packages metadata contains no payloads")
    return paths


def parse_apt_release(data: bytes) -> dict[str, tuple[str, int]]:
    try:
        lines = data.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise CompositionError("APT Release is not UTF-8") from error
    entries: dict[str, tuple[str, int]] = {}
    in_sha256 = False
    for line in lines:
        if line == "SHA256:":
            require(not in_sha256 and not entries, "APT Release contains duplicate SHA256 sections")
            in_sha256 = True
            continue
        if in_sha256 and line.startswith(" "):
            fields = line.split()
            require(len(fields) == 3 and SHA256_RE.fullmatch(fields[0]),
                    "APT Release contains an invalid SHA256 entry")
            try:
                size = int(fields[1])
            except ValueError as error:
                raise CompositionError("APT Release contains an invalid SHA256 size") from error
            positive_integer(size, "APT Release SHA256 size")
            path = safe_relative(fields[2], "APT Release SHA256 path").as_posix()
            require(path not in entries, "APT Release contains a duplicate SHA256 path")
            entries[path] = (fields[0], size)
        elif in_sha256:
            in_sha256 = False
    require(entries, "APT Release contains no SHA256 entries")
    return entries


def validate_apt_tree(
    root: Path,
    receipt_path: Path,
    inventory: dict[str, dict[str, Any]],
    bootstrap: dict[str, Any],
    active_versions: list[str],
    retained_versions: list[str],
) -> tuple[dict[str, dict[str, Any]], dict[str, Path], dict[str, Any]]:
    files, directories = collect_tree(root, "APT signer tree")
    receipt = load_signing_receipt(receipt_path, "apt")
    result = exact(receipt["result"], {"inrelease", "release", "release_gpg"},
                   "APT signing result")
    receipt_artifacts = {
        name: parse_artifact(result[name], f"APT signing result {name}")
        for name in ("inrelease", "release", "release_gpg")
    }
    expected_receipt_paths = {
        "release": "dists/preview/Release",
        "inrelease": "dists/preview/InRelease",
        "release_gpg": "dists/preview/Release.gpg",
    }
    for name, expected in expected_receipt_paths.items():
        require(receipt_artifacts[name]["path"] == expected,
                f"APT {name} receipt path must be {expected}")
        require_artifact_identity(receipt_artifacts[name], files, expected, f"APT {name}")

    packages_path = "dists/preview/main/binary-amd64/Packages"
    compressed_path = f"{packages_path}.gz"
    require(packages_path in files and compressed_path in files,
            "APT signer tree is missing Packages metadata")
    packages_bytes = read_checked(
        root / packages_path, "APT Packages", expected=files[packages_path],
        maximum_bytes=MAX_METADATA_BYTES,
    )
    compressed_packages = decompress_buffer(
        read_checked(
            root / compressed_path, "APT Packages.gz", expected=files[compressed_path],
            maximum_bytes=MAX_METADATA_BYTES,
        ),
        ".gz",
        MAX_METADATA_BYTES,
        "APT Packages.gz",
    )
    require(compressed_packages == packages_bytes, "APT Packages.gz differs from Packages")
    active_payloads = {
        PurePosixPath(inventory[version]["path"]).relative_to("apt").as_posix()
        : files[PurePosixPath(inventory[version]["path"]).relative_to("apt").as_posix()]
        for version in active_versions
    }
    bootstrap_relative = PurePosixPath(bootstrap["repository_path"]).relative_to("apt").as_posix()
    require(bootstrap_relative in files, "APT signer tree is missing the bootstrap package")
    active_payloads[bootstrap_relative] = files[bootstrap_relative]
    retained_paths = {
        PurePosixPath(inventory[version]["path"]).relative_to("apt").as_posix()
        for version in retained_versions
    }
    indexed_payloads = parse_apt_packages(packages_bytes)
    require(indexed_payloads == active_payloads,
            "APT Packages index does not exactly contain active payloads")
    require(not (set(indexed_payloads) & retained_paths),
            "retained APT payload appears in Packages metadata")

    release_entries = parse_apt_release(read_checked(
        root / expected_receipt_paths["release"], "APT Release",
        expected=files[expected_receipt_paths["release"]], maximum_bytes=MAX_METADATA_BYTES,
    ))
    release_expected = {
        "main/binary-amd64/Packages": files[packages_path],
        "main/binary-amd64/Packages.gz": files[compressed_path],
    }
    require(set(release_entries) == set(release_expected),
            "APT Release SHA256 section does not exactly cover Packages metadata")
    for relative, facts in release_expected.items():
        require(release_entries[relative] == (facts["sha256"], facts["size"]),
                f"APT Release identity differs for {relative}")
    by_hash_paths = {
        f"dists/preview/main/binary-amd64/by-hash/SHA256/{files[path]['sha256']}"
        for path in (packages_path, compressed_path)
    }
    for source in (packages_path, compressed_path):
        by_hash = f"dists/preview/main/binary-amd64/by-hash/SHA256/{files[source]['sha256']}"
        require(by_hash in files and files[by_hash] == files[source],
                f"APT by-hash object differs from {source}")
    payload_paths = {
        PurePosixPath(item["path"]).relative_to("apt").as_posix()
        for item in inventory.values()
    }
    payload_paths.add(bootstrap_relative)
    expected_files = payload_paths | set(expected_receipt_paths.values()) | {
        packages_path, compressed_path,
    } | by_hash_paths
    require_tree_closure(files, directories, expected_files, "APT signer tree")
    for version, item in inventory.items():
        relative = PurePosixPath(item["path"]).relative_to("apt").as_posix()
        require(files[relative]["sha256"] == item["published_sha256"],
                f"APT signer payload digest differs from inventory for {version}")
    require(files[bootstrap_relative] == {
        "sha256": bootstrap["published_sha256"], "size": bootstrap["published_size"],
    }, "APT signer bootstrap package differs from inventory")
    sources = {relative: root / relative for relative in expected_files}
    return files, sources, receipt["key"]


def local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def decompress_buffer(raw: bytes, suffix: str, maximum: int, label: str) -> bytes:
    try:
        if suffix == ".gz":
            stream = gzip.GzipFile(fileobj=io.BytesIO(raw))
        elif suffix == ".bz2":
            stream = bz2.BZ2File(io.BytesIO(raw))
        elif suffix in {".xz", ".lzma"}:
            stream = lzma.LZMAFile(io.BytesIO(raw))
        else:
            require(0 < len(raw) <= maximum, f"{label} size is invalid")
            return raw
        with stream:
            data = stream.read(maximum + 1)
    except (OSError, EOFError, lzma.LZMAError) as error:
        raise CompositionError(f"{label} compression is invalid") from error
    require(0 < len(data) <= maximum, f"{label} exceeds its decompressed size limit")
    return data


def decompress_metadata(
    path: Path, expected: dict[str, Any], maximum: int = MAX_METADATA_BYTES
) -> bytes:
    suffix = path.suffix
    raw = read_checked(path, f"RPM metadata {path.name}", expected=expected,
                       maximum_bytes=SITE_LIMIT_BYTES)
    try:
        if suffix in {".zst", ".zstd"}:
            tool = shutil.which("zstd")
            require(tool is not None, "zstd is required to inspect RPM primary metadata")
            with tempfile.TemporaryDirectory(prefix="wk-rpm-metadata-") as temporary:
                immutable_input = Path(temporary) / "metadata.zst"
                write_exclusive(immutable_input, raw, "isolated RPM metadata")
                process = subprocess.Popen(
                    [tool, "--quiet", "--decompress", "--stdout", "--", str(immutable_input)],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                )
                chunks: list[bytes] = []
                total = 0
                require(process.stdout is not None, "cannot read zstd metadata output")
                while True:
                    chunk = process.stdout.read(COPY_CHUNK_BYTES)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > maximum:
                        process.kill()
                        process.wait()
                        raise CompositionError(
                            "RPM primary metadata exceeds its decompressed size limit"
                        )
                    chunks.append(chunk)
                require(process.wait() == 0, "zstd rejected RPM primary metadata")
                data = b"".join(chunks)
        else:
            data = decompress_buffer(raw, suffix, maximum, "RPM metadata")
    except OSError as error:
        raise CompositionError("RPM primary metadata compression is invalid") from error
    require(0 < len(data) <= maximum, "RPM primary metadata size is invalid")
    return data


def direct_child(element: ET.Element, name: str, label: str) -> ET.Element:
    matches = [child for child in element if local_name(child.tag) == name]
    require(len(matches) == 1, f"{label} must contain exactly one {name}")
    return matches[0]


def parse_rpm_primary(
    data: bytes, active_payloads: dict[str, dict[str, Any]]
) -> set[str]:
    require(b"<!DOCTYPE" not in data and b"<!ENTITY" not in data,
            "RPM primary metadata must not contain a DTD or entity declaration")
    try:
        root = ET.fromstring(data)
    except ET.ParseError as error:
        raise CompositionError("RPM primary metadata is invalid XML") from error
    require(local_name(root.tag) == "metadata", "RPM primary metadata root is invalid")
    paths: set[str] = set()
    packages = [element for element in root if local_name(element.tag) == "package"]
    for package in packages:
        require(package.get("type") == "rpm", "RPM primary metadata contains a non-RPM package")
        location = direct_child(package, "location", "RPM primary package")
        checksum = direct_child(package, "checksum", "RPM primary package")
        size_element = direct_child(package, "size", "RPM primary package")
        value = safe_relative(location.get("href"), "RPM primary package location").as_posix()
        require(value.startswith("Packages/") and value.endswith(".rpm"),
                "RPM primary package location must be below Packages/")
        require(value not in paths, "RPM primary metadata contains a duplicate payload")
        require(checksum.get("type") == "sha256" and checksum.get("pkgid", "").upper() == "YES"
                and checksum.text is not None and SHA256_RE.fullmatch(checksum.text),
                "RPM primary payload checksum must be a SHA-256 package identifier")
        try:
            size = int(size_element.get("package", ""))
        except ValueError as error:
            raise CompositionError("RPM primary payload size is invalid") from error
        positive_integer(size, "RPM primary payload size")
        require(value in active_payloads
                and (checksum.text, size)
                == (active_payloads[value]["sha256"], active_payloads[value]["size"]),
                f"RPM primary payload identity differs for {value}")
        paths.add(value)
    require(paths, "RPM primary metadata contains no packages")
    return paths


def validate_repomd(
    rpm_root: Path,
    repository: str,
    repodata: dict[str, dict[str, Any]],
    active_payloads: dict[str, dict[str, Any]],
) -> None:
    repomd_relative = f"{repository}/repodata/repomd.xml"
    repomd_path = rpm_root / repomd_relative
    raw = read_checked(
        repomd_path, "RPM repomd.xml", expected=repodata["repodata/repomd.xml"],
        maximum_bytes=MAX_METADATA_BYTES,
    )
    require(b"<!DOCTYPE" not in raw and b"<!ENTITY" not in raw,
            "RPM repomd.xml must not contain a DTD or entity declaration")
    try:
        root = ET.fromstring(raw)
    except ET.ParseError as error:
        raise CompositionError("RPM repomd.xml is invalid XML") from error
    require(local_name(root.tag) == "repomd", "RPM repomd.xml root is invalid")
    referenced: set[str] = set()
    data_types: set[str] = set()
    opened_by_type: dict[str, bytes] = {}
    primary_path: str | None = None
    for data in [child for child in root if local_name(child.tag) == "data"]:
        data_type = data.get("type")
        require(isinstance(data_type, str) and data_type != "" and data_type not in data_types,
                "RPM repomd data type must be non-empty and unique")
        data_types.add(data_type)
        location = direct_child(data, "location", f"RPM repomd {data_type}")
        checksum = direct_child(data, "checksum", f"RPM repomd {data_type}")
        open_checksum = direct_child(data, "open-checksum", f"RPM repomd {data_type}")
        size_element = direct_child(data, "size", f"RPM repomd {data_type}")
        open_size_element = direct_child(data, "open-size", f"RPM repomd {data_type}")
        href = safe_relative(location.get("href"), "RPM repomd location").as_posix()
        require(href.startswith("repodata/"), "RPM repomd location must be below repodata/")
        require(href not in referenced, "RPM repomd contains a duplicate location")
        require(checksum.get("type") == "sha256" and checksum.text is not None
                and SHA256_RE.fullmatch(checksum.text),
                "RPM repomd checksum must be SHA-256")
        require(open_checksum.get("type") == "sha256" and open_checksum.text is not None
                and SHA256_RE.fullmatch(open_checksum.text),
                "RPM repomd open checksum must be SHA-256")
        try:
            size = int(size_element.text or "")
            open_size = int(open_size_element.text or "")
        except ValueError as error:
            raise CompositionError("RPM repomd size or open size is invalid") from error
        positive_integer(size, "RPM repomd size")
        positive_integer(open_size, "RPM repomd open size")
        require(open_size <= MAX_METADATA_BYTES,
                "RPM repomd open size exceeds the metadata limit")
        require(href in repodata, f"RPM repomd references an unreceipted file: {href}")
        require((checksum.text, size) ==
                (repodata[href]["sha256"], repodata[href]["size"]),
                f"RPM repomd identity differs for {href}")
        opened = decompress_metadata(rpm_root / repository / href, repodata[href])
        require((digest_bytes(opened), len(opened)) == (open_checksum.text, open_size),
                f"RPM repomd open identity differs for {href}")
        opened_by_type[data_type] = opened
        referenced.add(href)
        if data_type == "primary":
            require(primary_path is None, "RPM repomd contains duplicate primary metadata")
            primary_path = href
    expected_references = set(repodata) - {"repodata/repomd.xml", "repodata/repomd.xml.asc"}
    require(referenced == expected_references,
            "RPM repomd does not exactly cover received metadata files")
    require({"primary", "filelists", "other"}.issubset(data_types),
            "RPM repomd must contain primary, filelists, and other metadata")
    require(primary_path is not None, "RPM repomd is missing primary metadata")
    require(parse_rpm_primary(opened_by_type["primary"], active_payloads)
            == set(active_payloads),
            "RPM primary metadata does not exactly contain active payloads")


def validate_rpm_tree(
    root: Path,
    receipt_path: Path,
    inventory: dict[str, dict[str, Any]],
    bootstrap: dict[str, Any],
    active_versions: list[str],
    retained_versions: list[str],
) -> tuple[dict[str, dict[str, Any]], dict[str, Path], dict[str, Any]]:
    files, directories = collect_tree(root, "RPM signer tree")
    receipt = load_signing_receipt(receipt_path, "rpm")
    result = exact(receipt["result"], {
        "active", "new_unsigned_inputs", "newly_signed", "preserved_signed",
        "repodata", "repository", "retired",
    }, "RPM signing result")
    repository = result["repository"]
    require(repository == "preview/el/9/x86_64", "RPM signing repository path is unsupported")
    categories = {
        name: artifact_list(result[name], f"RPM signing result {name}")
        for name in (
            "active", "new_unsigned_inputs", "newly_signed",
            "preserved_signed", "repodata", "retired",
        )
    }
    expected_relative = {
        f"product:{version}": PurePosixPath(item["path"]).relative_to(
            PurePosixPath("rpm") / repository
        ).as_posix()
        for version, item in inventory.items()
    }
    expected_relative["bootstrap"] = PurePosixPath(bootstrap["repository_path"]).relative_to(
        PurePosixPath("rpm") / repository
    ).as_posix()
    expected_new = {
        expected_relative[f"product:{version}"]
        for version, item in inventory.items() if item["new"]
    }
    if bootstrap["new"]:
        expected_new.add(expected_relative["bootstrap"])
    expected_preserved = set(expected_relative.values()) - expected_new
    expected_active = {
        expected_relative[f"product:{version}"] for version in active_versions
    } | {expected_relative["bootstrap"]}
    expected_retired = {
        expected_relative[f"product:{version}"] for version in retained_versions
    }
    require(set(categories["newly_signed"]) == expected_new,
            "RPM newly-signed receipt differs from new inventory payloads")
    require(set(categories["new_unsigned_inputs"]) == expected_new,
            "RPM unsigned-input receipt differs from new inventory payloads")
    require(set(categories["preserved_signed"]) == expected_preserved,
            "RPM preserved-signed receipt differs from existing inventory payloads")
    require(set(categories["active"]) == expected_active,
            "RPM active receipt differs from active inventory payloads")
    require(set(categories["retired"]) == expected_retired,
            "RPM retired receipt differs from retained inventory payloads")
    all_payloads = {**categories["newly_signed"], **categories["preserved_signed"]}
    require(set(all_payloads) == expected_active | expected_retired,
            "RPM signing receipt does not close over exact payloads")
    for version, item in inventory.items():
        relative = expected_relative[f"product:{version}"]
        if item["new"]:
            require(categories["new_unsigned_inputs"][relative]["sha256"]
                    == item["source_sha256"],
                    f"new RPM unsigned receipt differs from source inventory for {version}")
            require(all_payloads[relative]["sha256"] != item["source_sha256"],
                    f"new RPM bytes were not changed by signing for {version}")
        else:
            require(all_payloads[relative]["sha256"] == item["published_sha256"],
                    f"preserved RPM digest differs from inventory for {version}")
    bootstrap_relative = expected_relative["bootstrap"]
    if bootstrap["new"]:
        require(categories["new_unsigned_inputs"][bootstrap_relative] == {
            "path": bootstrap_relative,
            "sha256": bootstrap["source_sha256"],
            "size": bootstrap["source_size"],
        }, "new RPM bootstrap unsigned receipt differs from inventory")
        require(all_payloads[bootstrap_relative]["sha256"] != bootstrap["source_sha256"],
                "new RPM bootstrap package bytes were not changed by signing")
    else:
        require(all_payloads[bootstrap_relative] == {
            "path": bootstrap_relative,
            "sha256": bootstrap["published_sha256"],
            "size": bootstrap["published_size"],
        }, "preserved RPM bootstrap package differs from inventory")
    for name in ("active", "retired"):
        for relative, artifact in categories[name].items():
            require(relative in all_payloads and artifact == all_payloads[relative],
                    f"RPM {name} receipt identity differs for {relative}")

    expected_files: set[str] = set()
    for relative, artifact in all_payloads.items():
        full = f"{repository}/{relative}"
        require_artifact_identity(artifact, files, full, "RPM payload")
        expected_files.add(full)
    repodata_relative: dict[str, dict[str, Any]] = {}
    for relative, artifact in categories["repodata"].items():
        require(relative.startswith("repodata/"), "RPM repodata receipt path is invalid")
        full = f"{repository}/{relative}"
        require_artifact_identity(artifact, files, full, "RPM repodata")
        expected_files.add(full)
        repodata_relative[relative] = artifact
    require("repodata/repomd.xml" in repodata_relative
            and "repodata/repomd.xml.asc" in repodata_relative,
            "RPM repodata receipt lacks repomd.xml or its signature")
    require_tree_closure(files, directories, expected_files, "RPM signer tree")
    validate_repomd(
        root,
        repository,
        repodata_relative,
        {path: all_payloads[path] for path in expected_active},
    )
    sources = {relative: root / relative for relative in expected_files}
    return files, sources, receipt["key"]


def copy_checked(source: Path, destination: Path, expected: dict[str, Any], label: str) -> None:
    require(hash_file(source, label) == expected, f"{label} changed before copy")
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    require(not os.path.lexists(destination), f"duplicate output path: {destination}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    output_descriptor = os.open(destination, flags, 0o600)
    input_descriptor = os.open(source, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        while True:
            block = os.read(input_descriptor, COPY_CHUNK_BYTES)
            if not block:
                break
            view = memoryview(block)
            while view:
                written = os.write(output_descriptor, view)
                view = view[written:]
        os.fsync(output_descriptor)
        os.fchmod(output_descriptor, 0o644)
    finally:
        os.close(input_descriptor)
        os.close(output_descriptor)
    require(hash_file(destination, f"copied {label}") == expected,
            f"{label} changed during copy")


def capacity_status(total: int, warning: int, hard: int) -> bool:
    positive_integer(warning, "site warning threshold")
    positive_integer(hard, "site hard limit")
    require(warning < hard, "site warning threshold must be below the hard limit")
    require(type(total) is int and total >= 0, "site size must be a non-negative integer")
    require(total <= hard, "composed site exceeds the hard Pages limit")
    return total >= warning


def write_exclusive(path: Path, data: bytes, label: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    require(not os.path.lexists(path), f"{label} already exists")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o644)
    try:
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def compose(args: argparse.Namespace) -> dict[str, Any]:
    control = validate_channels(load_json(args.channels, "channels manifest"))
    reviewed_keys = validate_signing_manifest(
        load_json(args.signing, "preview signing manifest"),
        args.apt_public_cert,
        args.rpm_public_cert,
    )
    plan = validate_plan(load_json(args.plan, "publication plan", canonical=True), control)
    toolchain_value = load_json(args.signing_toolchain, "signing toolchain manifest")
    toolchain_manifest_facts = hash_file(
        args.signing_toolchain, "signing toolchain manifest", maximum_bytes=1024 * 1024
    )
    require(load_json(args.signing_toolchain, "signing toolchain manifest") == toolchain_value,
            "signing toolchain manifest changed during validation")
    toolchain = validate_signing_toolchain(toolchain_value, toolchain_manifest_facts)
    source_attestations, source_attestation_files = validate_source_attestations(
        args.source_attestations, plan, control
    )
    inventory = validate_inventory(
        load_json(args.inventory, "payload inventory", canonical=True), plan, control
    )
    bootstrap_inventory = validate_bootstrap_inventory(
        load_json(args.bootstrap_inventory, "bootstrap inventory", canonical=True),
        prepared=True,
    )
    _, base_site, base_entries = load_base(args.base_root, plan, inventory, control)
    validate_bootstrap_transition(base_site, plan, bootstrap_inventory)
    apt_files, apt_sources, apt_key = validate_apt_tree(
        args.apt_tree, args.apt_receipt, inventory["apt"],
        bootstrap_inventory["packages"]["apt"],
        plan["active_versions"], plan["retained_versions"],
    )
    rpm_files, rpm_sources, rpm_key = validate_rpm_tree(
        args.rpm_tree, args.rpm_receipt, inventory["rpm"],
        bootstrap_inventory["packages"]["rpm"],
        plan["active_versions"], plan["retained_versions"],
    )
    require_reviewed_key_receipt(apt_key, reviewed_keys["apt"], "apt")
    require_reviewed_key_receipt(rpm_key, reviewed_keys["rpm"], "rpm")

    output = args.output_root
    require(not os.path.lexists(output), "output root must not already exist")
    output.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    require(stat.S_ISDIR(output.parent.lstat().st_mode),
            "output root parent must be a real directory")
    parent = output.parent.resolve(strict=True)
    require(output.name not in {"", ".", ".."} and SAFE_COMPONENT_RE.fullmatch(output.name),
            "output root name is unsafe")
    stage = Path(tempfile.mkdtemp(prefix=f".{output.name}.tmp.", dir=parent))
    try:
        site = stage / "site"
        site.mkdir(mode=0o755)
        copy_checked(
            args.signing_toolchain,
            stage / "audit/signing-toolchain.json",
            toolchain_manifest_facts,
            "signing toolchain manifest",
        )
        if source_attestations is not None:
            assert args.source_attestations is not None
            for name in sorted(source_attestation_files):
                copy_checked(
                    args.source_attestations / name,
                    stage / "audit/source-attestations" / name,
                    source_attestation_files[name],
                    f"source attestation evidence {name}",
                )
        for family, source in (
            ("apt", args.apt_public_cert),
            ("rpm", args.rpm_public_cert),
        ):
            key = reviewed_keys[family]
            copy_checked(
                source,
                site / key["path"],
                {"sha256": key["sha256"], "size": key["size"]},
                f"{family} reviewed public certificate",
            )
        snapshot_payloads: dict[str, list[dict[str, Any]]] = {"apt": [], "rpm": []}
        for family, files, sources in (
            ("apt", apt_files, apt_sources),
            ("rpm", rpm_files, rpm_sources),
        ):
            payload_family_relative = {
                version: PurePosixPath(item["path"]).relative_to(family).as_posix()
                for version, item in inventory[family].items()
            }
            version_by_payload_path = {
                path: version for version, path in payload_family_relative.items()
            }
            payload_paths = set(version_by_payload_path)
            for relative in sorted(files):
                destination_relative = f"{family}/{relative}"
                if relative in payload_paths:
                    version = version_by_payload_path[relative]
                    if version in plan["retained_versions"]:
                        require(base_site is not None,
                                "retained payload requires a base site")
                        source = base_site.joinpath(*PurePosixPath(destination_relative).parts)
                        expected_digest = base_entries[family][version]["published_sha256"]
                        expected = hash_file(source, f"base retained {family} payload {version}")
                        require(expected["sha256"] == expected_digest,
                                f"base retained {family} payload changed for {version}")
                        require(files[relative] == expected,
                                f"signed {family} retained payload differs from base for {version}")
                    else:
                        source = sources[relative]
                        expected = files[relative]
                else:
                    source = sources[relative]
                    expected = files[relative]
                copy_checked(source, site / destination_relative, expected,
                             f"{family} site input {relative}")
            for version in sorted(inventory[family]):
                item = inventory[family][version]
                relative = payload_family_relative[version]
                snapshot_payloads[family].append({
                    "version": version,
                    "path": item["path"],
                    "source_sha256": item["source_sha256"],
                    "published_sha256": files[relative]["sha256"],
                    "indexed": item["indexed"],
                })

        published_bootstrap = {
            "schema": BOOTSTRAP_INVENTORY_SCHEMA,
            "version": bootstrap_inventory["version"],
            "packages": {},
        }
        for family, files in (("apt", apt_files), ("rpm", rpm_files)):
            item = dict(bootstrap_inventory["packages"][family])
            relative = PurePosixPath(item["repository_path"]).relative_to(family).as_posix()
            facts = files[relative]
            if family == "apt":
                require(facts == {
                    "sha256": item["source_sha256"], "size": item["source_size"],
                }, "published APT bootstrap package differs from its source bytes")
            elif not item["new"]:
                require(facts == {
                    "sha256": item["published_sha256"], "size": item["published_size"],
                }, "preserved RPM bootstrap package differs from its inventory")
            item["published_sha256"] = facts["sha256"]
            item["published_size"] = facts["size"]
            published_bootstrap["packages"][family] = item
            repository_file = site.joinpath(*PurePosixPath(item["repository_path"]).parts)
            copy_checked(
                repository_file,
                site.joinpath(*PurePosixPath(item["download_path"]).parts),
                facts,
                f"{family} bootstrap download",
            )
        write_exclusive(
            site / "bootstrap/manifest.json",
            canonical_json(published_bootstrap),
            "bootstrap manifest",
        )

        snapshot = {
            "schema": SNAPSHOT_SCHEMA,
            "audit_release_id": plan["audit_release_id"],
            "control_sha": plan["control_sha"],
            "releases": control["preview"]["releases"],
            "retirement": control["retirement"],
            "payloads": snapshot_payloads,
            "public_keys": reviewed_keys,
            "source_attestations": source_attestations,
            "toolchain": toolchain,
        }
        snapshot_path = stage / "audit/snapshot.json"
        write_exclusive(snapshot_path, canonical_json(snapshot), "snapshot inventory")
        snapshot_facts = hash_file(snapshot_path, "snapshot inventory")
        status = {
            "schema": STATUS_SCHEMA,
            "apt": True,
            "rpm": True,
            "reason": "ready",
            "audit_release_id": plan["audit_release_id"],
            "control_sha": plan["control_sha"],
            "snapshot_sha256": snapshot_facts["sha256"],
            "operation": plan["operation"],
            "target_version": plan["target_version"],
        }
        write_exclusive(site / "status.json", canonical_json(status), "site status")
        signing_manifest = (
            "TEST_ONLY=false\n"
            f"APT_PRIMARY_FINGERPRINT={apt_key['primary_fingerprint']}\n"
            f"APT_SIGNING_FINGERPRINT={apt_key['signing_subkey_fingerprint']}\n"
            f"APT_NEXT_SIGNING_FINGERPRINT={apt_key['next_signing_subkey_fingerprint']}\n"
            f"RPM_PRIMARY_FINGERPRINT={rpm_key['primary_fingerprint']}\n"
            f"RPM_SIGNING_FINGERPRINT={rpm_key['signing_subkey_fingerprint']}\n"
            f"RPM_NEXT_SIGNING_FINGERPRINT={rpm_key['next_signing_subkey_fingerprint']}\n"
            "APT_RELEASE=apt/dists/preview/Release\n"
            "RPM_REPOSITORY=rpm/preview/el/9/x86_64\n"
        ).encode("ascii")
        write_exclusive(site / "signing-manifest.txt", signing_manifest,
                        "site signing manifest")
        index = (
            "<!doctype html>\n<meta charset=\"utf-8\">\n"
            "<title>WuKongIM Linux packages</title>\n"
            "<h1>WuKongIM Linux packages</h1>\n"
            "<p>The signed preview APT and RPM repositories and bootstrap packages are ready.</p>\n"
        ).encode("utf-8")
        write_exclusive(site / "index.html", index, "site index")

        site_files, _ = collect_tree(site, "composed site")
        site_size = sum(item["size"] for item in site_files.values())
        warning = capacity_status(
            site_size, control["manifest"]["site_warning_bytes"],
            control["manifest"]["site_limit_bytes"],
        )
        require(not os.path.lexists(output), "output root appeared during composition")
        try:
            os.chmod(stage, 0o755)
        except OSError as error:
            raise CompositionError(
                f"cannot export composed snapshot: {error}"
            ) from error
        os.replace(stage, output)
    except BaseException:
        if os.path.lexists(stage):
            shutil.rmtree(stage)
        raise
    return {
        "schema": COMPOSITION_SCHEMA,
        "audit_release_id": plan["audit_release_id"],
        "control_sha": plan["control_sha"],
        "active_versions": plan["active_versions"],
        "retained_versions": plan["retained_versions"],
        "site_file_count": len(site_files),
        "site_size_bytes": site_size,
        "site_warning_bytes": control["manifest"]["site_warning_bytes"],
        "site_limit_bytes": control["manifest"]["site_limit_bytes"],
        "capacity_warning": warning,
        "snapshot_sha256": snapshot_facts["sha256"],
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--channels", required=True, type=Path)
    parser.add_argument("--signing", required=True, type=Path)
    parser.add_argument("--signing-toolchain", required=True, type=Path)
    parser.add_argument("--plan", required=True, type=Path)
    parser.add_argument("--inventory", required=True, type=Path)
    parser.add_argument("--bootstrap-inventory", required=True, type=Path)
    parser.add_argument("--apt-tree", required=True, type=Path)
    parser.add_argument("--apt-receipt", required=True, type=Path)
    parser.add_argument("--apt-public-cert", required=True, type=Path)
    parser.add_argument("--rpm-tree", required=True, type=Path)
    parser.add_argument("--rpm-receipt", required=True, type=Path)
    parser.add_argument("--rpm-public-cert", required=True, type=Path)
    parser.add_argument("--source-attestations", type=Path)
    parser.add_argument("--base-root", type=Path)
    parser.add_argument("--output-root", required=True, type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        receipt = compose(args)
    except (CompositionError, OSError) as error:
        print(f"package-site composition failed: {error}", file=sys.stderr)
        return 1
    print(canonical_json(receipt).decode("utf-8"), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
