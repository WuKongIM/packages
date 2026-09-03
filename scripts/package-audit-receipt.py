#!/usr/bin/env python3
"""Create or verify the external receipt for one package publication snapshot."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import stat
import sys
import tempfile
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
ARCHIVE_SCRIPT = ROOT / "scripts" / "archive-package-snapshot.py"
ARCHIVE_SPEC = importlib.util.spec_from_file_location(
    "wukongim_archive_package_snapshot", ARCHIVE_SCRIPT
)
if ARCHIVE_SPEC is None or ARCHIVE_SPEC.loader is None:
    raise RuntimeError("cannot load package snapshot archiver")
snapshot_archive = importlib.util.module_from_spec(ARCHIVE_SPEC)
ARCHIVE_SPEC.loader.exec_module(snapshot_archive)


RECEIPT_SCHEMA = "wukongim/package-audit-receipt/v2"
CHANNELS_SCHEMA = "wukongim.native_package_channels/v3"
SIGNING_SCHEMA = "wukongim.native_package_signing/v3"
PLAN_SCHEMA = "wukongim.native_package_publication_plan/v1"
SNAPSHOT_SCHEMA = "wukongim.native_package_snapshot/v3"
FAMILY_RECEIPT_SCHEMA = "wukongim/package-family-signing-receipt/v1"
SOURCE_REPOSITORY = "WuKongIM/WuKongIM"
SIGNING_TOOLCHAIN_SCHEMA = "wukongim.native_package_signing_toolchain/v1"
SIGNING_TOOLCHAIN_IMAGE = "ghcr.io/wukongim/native-package-signing-toolchain"
SOURCE_ATTESTATION_SCHEMA = "wukongim/source-attestation-verification/v1"
SOURCE_SIGNER_WORKFLOW = "WuKongIM/WuKongIM/.github/workflows/binary-release-publish.yml"
SITE_WARNING_BYTES = 600 * 1024 * 1024
SITE_LIMIT_BYTES = 750 * 1024 * 1024
ARCHIVE_MAX_TOTAL_BYTES = 800 * 1024 * 1024
MAX_JSON_BYTES = 8 * 1024 * 1024
COPY_CHUNK_SIZE = 1024 * 1024

LOWER_SHA = re.compile(r"^[0-9a-f]{40}$")
LOWER_SHA256 = re.compile(r"^[0-9a-f]{64}$")
OCI_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
UPPER_FINGERPRINT = re.compile(r"^[0-9A-F]{40}$")
UTC_TIMESTAMP = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")

CHANNEL_FIELDS = {
    "schema",
    "source_repository",
    "site_limit_bytes",
    "site_warning_bytes",
    "max_online_versions",
    "architectures",
    "channels",
}
PREVIEW_FIELDS = {"enabled", "status", "releases", "retirement", "publication"}
STABLE_FIELDS = {"enabled", "status", "releases"}
RETIREMENT_FIELDS = {"phase", "version", "not_before"}
PUBLICATION_FIELDS = {
    "audit_release_id",
    "base_audit_release_id",
    "operation",
    "target_version",
}
RELEASE_FIELDS = {
    "version",
    "source_sha",
    "source_release_id",
    "package_release_id",
    "deb_sha256",
    "rpm_sha256",
    "state",
    "not_before",
}
SIGNING_FIELDS = {
    "schema",
    "enabled",
    "minimum_valid_days",
    "rotation_begin_days",
    "maximum_subkey_lifetime_days",
    "apt",
    "rpm",
}
SIGNING_FAMILY_FIELDS = {
    "environment",
    "public_key",
    "primary_fingerprint",
    "signing_subkeys",
    "secret_subkey_env",
    "passphrase_env",
}
SIGNING_SUBKEY_FIELDS = {"current", "next", "historical"}
SIGNING_TOOLCHAIN_FIELDS = {"schema", "enabled", "image", "digest", "workflow_sha"}
SOURCE_ATTESTATION_FIELDS = {
    "schema", "repository", "release_id", "tag", "version", "source_sha",
    "source_ref", "signer_workflow", "deny_self_hosted_runners", "asset_count",
    "assets", "assets_revalidated_after_attestations",
}
SOURCE_ATTESTATION_ASSET_FIELDS = {
    "asset", "asset_sha256", "evidence_file", "evidence_sha256",
}
PLAN_FIELDS = {
    "schema",
    "control_sha",
    "operation",
    "audit_release_id",
    "base_audit_release_id",
    "target_version",
    "active_versions",
    "retained_versions",
    "new_versions",
    "removed_versions",
    "not_before",
}
SNAPSHOT_FIELDS = {
    "schema",
    "audit_release_id",
    "control_sha",
    "releases",
    "retirement",
    "payloads",
    "public_keys",
    "source_attestations",
    "toolchain",
}
PAYLOAD_FIELDS = {"version", "path", "source_sha256", "published_sha256", "indexed"}
PUBLIC_KEY_SNAPSHOT_FIELDS = {
    "path",
    "sha256",
    "size",
    "primary_fingerprint",
    "current_signing_subkey_fingerprint",
    "next_signing_subkey_fingerprint",
    "historical_signing_subkey_fingerprints",
}
SOURCE_ATTESTATION_SNAPSHOT_FIELDS = {"summary_sha256", "files"}
TOOLCHAIN_SNAPSHOT_FIELDS = {
    "image", "digest", "workflow_sha", "manifest_sha256", "manifest_size",
}
FAMILY_RECEIPT_FIELDS = {"schema", "family", "key", "result"}
KEY_RECEIPT_FIELDS = {
    "family",
    "historical_signing_subkey_fingerprints",
    "maximum_lifetime_days",
    "minimum_valid_days",
    "next_signing_subkey_fingerprint",
    "primary_fingerprint",
    "public_certificate_sha256",
    "public_certificate_size",
    "signing_subkey_created",
    "signing_subkey_expires",
    "signing_subkey_fingerprint",
    "validated",
}
ARTIFACT_FIELDS = {"path", "sha256", "size"}
RECEIPT_FIELDS = {
    "schema",
    "audit_release_id",
    "control_sha",
    "plan",
    "archive",
    "site",
    "signers",
    "source",
    "toolchain",
}
RECEIPT_PLAN_FIELDS = {
    "operation",
    "base_audit_release_id",
    "target_version",
    "sha256",
}
RECEIPT_ARCHIVE_FIELDS = {"name", "size", "sha256", "snapshot_sha256"}
RECEIPT_SITE_FIELDS = {
    "total_bytes",
    "warning_bytes",
    "hard_limit_bytes",
    "warning_exceeded",
}
RECEIPT_SIGNER_FIELDS = {
    "historical_signing_subkey_fingerprints",
    "next_signing_subkey_fingerprint",
    "public_certificate_sha256",
    "public_certificate_size",
    "receipt_sha256",
    "primary_fingerprint",
    "signing_subkey_fingerprint",
}
RECEIPT_SOURCE_FIELDS = {
    "release_id", "source_sha", "deb_sha256", "rpm_sha256",
    "attestation_summary_sha256", "attestations",
}
RECEIPT_TOOLCHAIN_FIELDS = TOOLCHAIN_SNAPSHOT_FIELDS


class AuditReceiptError(ValueError):
    """An input cannot produce the exact reviewed package audit receipt."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AuditReceiptError(message)


def exact_object(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    require(isinstance(value, dict), f"{label} must be an object")
    require(set(value) == fields, f"{label} fields must be exactly {sorted(fields)}")
    return value


def reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in result, f"duplicate JSON key: {key}")
        result[key] = value
    return result


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"


def _read_regular(path: Path, label: str, maximum: int = MAX_JSON_BYTES) -> bytes:
    try:
        before = path.lstat()
    except OSError as error:
        raise AuditReceiptError(f"cannot inspect {label}: {error}") from error
    require(
        stat.S_ISREG(before.st_mode) and before.st_nlink == 1,
        f"{label} must be a single-link regular file",
    )
    require(0 < before.st_size <= maximum, f"{label} has an invalid size")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise AuditReceiptError(f"cannot safely open {label}: {error}") from error
    chunks: list[bytes] = []
    total = 0
    try:
        opened = os.fstat(descriptor)
        require(
            stat.S_ISREG(opened.st_mode)
            and opened.st_nlink == 1
            and (opened.st_dev, opened.st_ino, opened.st_size)
            == (before.st_dev, before.st_ino, before.st_size),
            f"{label} changed while it was opened",
        )
        while True:
            chunk = os.read(descriptor, min(COPY_CHUNK_SIZE, maximum + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            require(total <= maximum, f"{label} exceeds its size limit")
        after = os.fstat(descriptor)
        require(
            (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            == (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
            and total == opened.st_size,
            f"{label} changed while it was read",
        )
    finally:
        os.close(descriptor)
    return b"".join(chunks)


def load_json(path: Path, label: str, *, canonical: bool = False) -> tuple[Any, bytes]:
    raw = _read_regular(path, label)
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=reject_duplicate_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AuditReceiptError(f"{label} is not valid JSON") from error
    if canonical:
        require(raw == canonical_json(value), f"{label} must use canonical JSON encoding")
    return value, raw


def positive_id(value: Any, label: str) -> int:
    require(type(value) is int and value > 0, f"{label} must be a positive integer")
    return value


def sha256_string(value: Any, label: str) -> str:
    require(isinstance(value, str) and LOWER_SHA256.fullmatch(value) is not None,
            f"{label} must be a lowercase SHA-256")
    return value


def fingerprint(value: Any, label: str) -> str:
    require(isinstance(value, str) and UPPER_FINGERPRINT.fullmatch(value) is not None,
            f"{label} must be an uppercase 40-hex fingerprint")
    return value


def safe_path(value: Any, label: str) -> PurePosixPath:
    require(isinstance(value, str) and value and "\\" not in value and "\0" not in value,
            f"{label} must be a canonical relative POSIX path")
    path = PurePosixPath(value)
    require(not path.is_absolute() and str(path) == value,
            f"{label} must be a canonical relative POSIX path")
    require(all(part not in {"", ".", ".."} for part in path.parts),
            f"{label} contains path traversal")
    return path


def _validate_release(raw: Any, index: int) -> dict[str, Any]:
    release = exact_object(raw, RELEASE_FIELDS, f"preview release {index}")
    require(isinstance(release["version"], str) and release["version"],
            f"preview release {index}.version must be a string")
    require(isinstance(release["source_sha"], str)
            and LOWER_SHA.fullmatch(release["source_sha"]) is not None,
            f"preview release {index}.source_sha is invalid")
    positive_id(release["source_release_id"], f"preview release {index}.source_release_id")
    positive_id(release["package_release_id"], f"preview release {index}.package_release_id")
    sha256_string(release["deb_sha256"], f"preview release {index}.deb_sha256")
    sha256_string(release["rpm_sha256"], f"preview release {index}.rpm_sha256")
    require(release["state"] in {"active", "index_removed"},
            f"preview release {index}.state is invalid")
    if release["state"] == "active":
        require(release["not_before"] is None,
                f"preview release {index}.not_before must be null while active")
    else:
        require(isinstance(release["not_before"], str)
                and UTC_TIMESTAMP.fullmatch(release["not_before"]) is not None,
                f"preview release {index}.not_before is invalid")
    return release


def validate_channels(value: Any) -> dict[str, Any]:
    channels = exact_object(value, CHANNEL_FIELDS, "channels manifest")
    require(channels["schema"] == CHANNELS_SCHEMA, f"channels schema must be {CHANNELS_SCHEMA}")
    require(channels["source_repository"] == SOURCE_REPOSITORY,
            f"source_repository must be {SOURCE_REPOSITORY}")
    require(channels["site_warning_bytes"] == SITE_WARNING_BYTES,
            f"site_warning_bytes must remain {SITE_WARNING_BYTES}")
    require(channels["site_limit_bytes"] == SITE_LIMIT_BYTES,
            f"site_limit_bytes must remain {SITE_LIMIT_BYTES}")
    require(channels["max_online_versions"] == 4, "max_online_versions must remain 4")
    require(channels["architectures"] == ["amd64"], "only amd64 may be published")
    channel_map = exact_object(channels["channels"], {"preview", "stable"}, "channels")
    preview = exact_object(channel_map["preview"], PREVIEW_FIELDS, "preview channel")
    exact_object(channel_map["stable"], STABLE_FIELDS, "stable channel")
    require(preview["enabled"] is True and preview["status"] == "ready",
            "an audit receipt requires an enabled ready preview channel")
    releases_value = preview["releases"]
    require(isinstance(releases_value, list) and releases_value,
            "preview releases must be a non-empty array")
    releases = [_validate_release(item, index) for index, item in enumerate(releases_value)]
    versions = [release["version"] for release in releases]
    require(len(versions) == len(set(versions)), "preview release versions must be unique")
    retirement = exact_object(preview["retirement"], RETIREMENT_FIELDS, "retirement")
    publication = exact_object(preview["publication"], PUBLICATION_FIELDS, "publication")
    positive_id(publication["audit_release_id"], "publication.audit_release_id")
    return {
        "releases": releases,
        "retirement": retirement,
        "publication": publication,
    }


def _string_list(value: Any, label: str) -> list[str]:
    require(isinstance(value, list) and all(isinstance(item, str) and item for item in value),
            f"{label} must be an array of non-empty strings")
    require(value == sorted(set(value)), f"{label} must be unique and sorted")
    return value


def validate_plan(value: Any, channel_facts: dict[str, Any]) -> dict[str, Any]:
    plan = exact_object(value, PLAN_FIELDS, "publication plan")
    require(plan["schema"] == PLAN_SCHEMA, f"publication plan schema must be {PLAN_SCHEMA}")
    require(isinstance(plan["control_sha"], str) and LOWER_SHA.fullmatch(plan["control_sha"]),
            "publication plan control_sha must be a lowercase 40-hex commit")
    publication = channel_facts["publication"]
    for field in ("audit_release_id", "base_audit_release_id", "operation", "target_version"):
        require(plan[field] == publication[field],
                f"publication plan {field} differs from reviewed channels")
    audit_id = positive_id(plan["audit_release_id"], "publication plan audit_release_id")
    require(plan["base_audit_release_id"] is None
            or (type(plan["base_audit_release_id"]) is int and plan["base_audit_release_id"] > 0),
            "publication plan base_audit_release_id is invalid")
    require(plan["base_audit_release_id"] != audit_id,
            "publication audit and base ids must differ")
    operation = plan["operation"]
    require(operation in {
        "add_release", "update_bootstrap", "remove_indexes", "remove_payloads",
    },
            "publication plan operation cannot produce an audit snapshot")
    target = plan["target_version"]
    require(isinstance(target, str) and target, "publication plan target_version is required")
    active = _string_list(plan["active_versions"], "publication plan active_versions")
    retained = _string_list(plan["retained_versions"], "publication plan retained_versions")
    new = _string_list(plan["new_versions"], "publication plan new_versions")
    removed = _string_list(plan["removed_versions"], "publication plan removed_versions")
    releases = {release["version"]: release for release in channel_facts["releases"]}
    require(active == sorted(version for version, release in releases.items()
                             if release["state"] == "active"),
            "publication plan active_versions differs from current channels")
    require(retained == sorted(version for version, release in releases.items()
                               if release["state"] == "index_removed"),
            "publication plan retained_versions differs from current channels")
    if operation == "add_release":
        require(target in releases and releases[target]["state"] == "active"
                and releases[target]["package_release_id"] == audit_id,
                "add_release target does not match current channels")
        require(new == [target] and not removed and plan["not_before"] is None,
                "add_release transition lists are inconsistent")
    elif operation == "update_bootstrap":
        positive_id(plan["base_audit_release_id"],
                    "update_bootstrap base_audit_release_id")
        require(target in releases and releases[target]["state"] == "active",
                "update_bootstrap target does not match current channels")
        require(not new and not removed and plan["not_before"] is None,
                "update_bootstrap transition facts are inconsistent")
    elif operation == "remove_indexes":
        positive_id(plan["base_audit_release_id"],
                    "remove_indexes base_audit_release_id")
        require(target in releases and releases[target]["state"] == "index_removed",
                "remove_indexes target does not match current channels")
        require(not new and not removed and plan["not_before"] == releases[target]["not_before"],
                "remove_indexes transition facts are inconsistent")
    else:
        positive_id(plan["base_audit_release_id"],
                    "remove_payloads base_audit_release_id")
        require(target not in releases and not new and removed == [target],
                "remove_payloads transition facts are inconsistent")
        require(isinstance(plan["not_before"], str)
                and UTC_TIMESTAMP.fullmatch(plan["not_before"]) is not None,
                "remove_payloads not_before is invalid")
    return plan


def validate_signing(
    value: Any,
    apt_public_cert: Path,
    rpm_public_cert: Path,
) -> dict[str, dict[str, Any]]:
    signing = exact_object(value, SIGNING_FIELDS, "preview signing manifest")
    require(signing["schema"] == SIGNING_SCHEMA, f"signing schema must be {SIGNING_SCHEMA}")
    require(signing["enabled"] is True, "audit receipt requires enabled signing")
    require(signing["minimum_valid_days"] == 30, "minimum_valid_days must remain 30")
    require(signing["rotation_begin_days"] == 45, "rotation_begin_days must remain 45")
    require(signing["maximum_subkey_lifetime_days"] == 180,
            "maximum_subkey_lifetime_days must remain 180")
    expected = {
        "apt": (
            "native-package-preview-apt-signing",
            "keys/apt-preview.asc",
            "WK_APT_PREVIEW_SECRET_SUBKEY_B64",
            "WK_APT_PREVIEW_PASSPHRASE",
            Path(apt_public_cert),
        ),
        "rpm": (
            "native-package-preview-rpm-signing",
            "keys/rpm-preview.asc",
            "WK_RPM_PREVIEW_SECRET_SUBKEY_B64",
            "WK_RPM_PREVIEW_PASSPHRASE",
            Path(rpm_public_cert),
        ),
    }
    result: dict[str, dict[str, Any]] = {}
    all_fingerprints: list[str] = []
    for family, expected_fields in expected.items():
        values = exact_object(signing[family], SIGNING_FAMILY_FIELDS, f"signing.{family}")
        environment, public_key, secret_env, passphrase_env, certificate = expected_fields
        require(values["environment"] == environment and values["public_key"] == public_key
                and values["secret_subkey_env"] == secret_env
                and values["passphrase_env"] == passphrase_env,
                f"signing.{family} fixed custody fields changed")
        require(certificate.name == PurePosixPath(public_key).name,
                f"{family} public certificate filename differs from reviewed control")
        certificate_raw = _read_regular(
            certificate, f"{family.upper()} reviewed public certificate", 1024 * 1024
        )
        require(
            certificate_raw.startswith(b"-----BEGIN PGP PUBLIC KEY BLOCK-----\n")
            and certificate_raw.rstrip().endswith(b"-----END PGP PUBLIC KEY BLOCK-----"),
            f"{family.upper()} reviewed public certificate must be ASCII armored",
        )
        primary = fingerprint(values["primary_fingerprint"], f"signing.{family}.primary_fingerprint")
        subkeys = exact_object(
            values["signing_subkeys"], SIGNING_SUBKEY_FIELDS,
            f"signing.{family}.signing_subkeys",
        )
        current = fingerprint(
            subkeys["current"], f"signing.{family}.signing_subkeys.current"
        )
        successor = fingerprint(
            subkeys["next"], f"signing.{family}.signing_subkeys.next"
        )
        historical = _string_list(
            subkeys["historical"], f"signing.{family}.signing_subkeys.historical"
        )
        historical = [
            fingerprint(item, f"signing.{family}.signing_subkeys.historical")
            for item in historical
        ]
        family_fingerprints = [primary, current, successor, *historical]
        require(len(family_fingerprints) == len(set(family_fingerprints)),
                f"signing.{family} fingerprints must be distinct")
        all_fingerprints.extend(family_fingerprints)
        result[family] = {
            "path": public_key,
            "primary_fingerprint": primary,
            "signing_subkey_fingerprint": current,
            "next_signing_subkey_fingerprint": successor,
            "historical_signing_subkey_fingerprints": historical,
            "public_certificate_sha256": hashlib.sha256(certificate_raw).hexdigest(),
            "public_certificate_size": len(certificate_raw),
            "minimum_valid_days": signing["minimum_valid_days"],
            "maximum_lifetime_days": signing["maximum_subkey_lifetime_days"],
        }
    require(len(set(all_fingerprints)) == len(all_fingerprints),
            "APT and RPM reviewed signing fingerprints must all be distinct")
    require(len({value[-16:] for value in all_fingerprints}) == len(all_fingerprints),
            "APT and RPM reviewed signing fingerprints must have distinct 16-hex key IDs")
    require(len({value[-8:] for value in all_fingerprints}) == len(all_fingerprints),
            "APT and RPM reviewed signing fingerprints must have distinct 8-hex key IDs")
    return result


def validate_signing_toolchain(value: Any, raw: bytes) -> dict[str, Any]:
    toolchain = exact_object(value, SIGNING_TOOLCHAIN_FIELDS, "signing toolchain manifest")
    require(toolchain["schema"] == SIGNING_TOOLCHAIN_SCHEMA,
            f"signing toolchain schema must be {SIGNING_TOOLCHAIN_SCHEMA}")
    require(toolchain["enabled"] is True,
            "audit receipt requires an enabled signing toolchain")
    require(toolchain["image"] == SIGNING_TOOLCHAIN_IMAGE,
            f"signing toolchain image must be {SIGNING_TOOLCHAIN_IMAGE}")
    require(isinstance(toolchain["digest"], str)
            and OCI_DIGEST.fullmatch(toolchain["digest"]) is not None,
            "signing toolchain digest must be an immutable SHA-256 OCI digest")
    require(isinstance(toolchain["workflow_sha"], str)
            and LOWER_SHA.fullmatch(toolchain["workflow_sha"]) is not None,
            "signing toolchain workflow_sha must be a lowercase 40-hex commit")
    return {
        "image": toolchain["image"],
        "digest": toolchain["digest"],
        "workflow_sha": toolchain["workflow_sha"],
        "manifest_sha256": hashlib.sha256(raw).hexdigest(),
        "manifest_size": len(raw),
    }


def validate_source_attestation(
    root: Path | None,
    plan: dict[str, Any],
    channel_facts: dict[str, Any],
) -> tuple[dict[str, Any] | None, dict[str, bytes]]:
    if plan["operation"] != "add_release":
        require(root is None,
                "source attestation evidence is forbidden for a non-add-release publication")
        return None, {}
    require(root is not None,
            "add_release requires the complete source attestation evidence directory")
    root = Path(root)
    try:
        root_metadata = root.lstat()
    except OSError as error:
        raise AuditReceiptError(f"cannot inspect source attestation evidence: {error}") from error
    require(stat.S_ISDIR(root_metadata.st_mode),
            "source attestation evidence must be a real directory")
    summary_name = "source-attestations.json"
    value, summary_raw = load_json(
        root / summary_name, "source attestation summary", canonical=True
    )
    summary = exact_object(value, SOURCE_ATTESTATION_FIELDS,
                           "source attestation summary")
    target = plan["target_version"]
    release = next(
        item for item in channel_facts["releases"] if item["version"] == target
    )
    require(summary["schema"] == SOURCE_ATTESTATION_SCHEMA,
            f"source attestation schema must be {SOURCE_ATTESTATION_SCHEMA}")
    require(summary["repository"] == SOURCE_REPOSITORY,
            "source attestation repository differs from reviewed source")
    require(summary["release_id"] == release["source_release_id"],
            "source attestation Release id differs from reviewed release")
    require(summary["version"] == target and summary["tag"] == f"v{target}",
            "source attestation version or tag differs from reviewed release")
    require(summary["source_sha"] == release["source_sha"],
            "source attestation commit differs from reviewed release")
    require(summary["source_ref"] == f"refs/tags/v{target}",
            "source attestation ref differs from reviewed release")
    require(summary["signer_workflow"] == SOURCE_SIGNER_WORKFLOW,
            "source attestation signer workflow differs from reviewed policy")
    require(summary["deny_self_hosted_runners"] is True
            and summary["assets_revalidated_after_attestations"] is True,
            "source attestation safety checks are incomplete")
    require(summary["asset_count"] == 7,
            "source attestation must close over seven source assets")
    assets_value = summary["assets"]
    require(isinstance(assets_value, list) and len(assets_value) == 7,
            "source attestation assets must contain seven entries")
    assets: dict[str, dict[str, Any]] = {}
    expected_files = {summary_name}
    prior = ""
    for index, raw_asset in enumerate(assets_value):
        asset = exact_object(raw_asset, SOURCE_ATTESTATION_ASSET_FIELDS,
                             f"source attestation asset {index}")
        name = asset["asset"]
        require(isinstance(name, str) and name > prior
                and PurePosixPath(name).name == name,
                "source attestation asset names must be safe, unique, and sorted")
        sha256_string(asset["asset_sha256"],
                      f"source attestation asset {name} SHA-256")
        evidence = safe_path(asset["evidence_file"],
                             f"source attestation evidence for {name}")
        require(len(evidence.parts) == 1 and evidence.name.endswith(".attestation.json"),
                f"source attestation evidence filename is invalid for {name}")
        require(evidence.name not in expected_files,
                "source attestation evidence filenames must be unique")
        expected_files.add(evidence.name)
        sha256_string(asset["evidence_sha256"],
                      f"source attestation evidence SHA-256 for {name}")
        assets[name] = asset
        prior = name
    deb_name = f"wukongim_{target}_linux_amd64.deb"
    rpm_name = f"wukongim_{target}_linux_amd64.rpm"
    require(deb_name in assets and rpm_name in assets,
            "source attestation omits the reviewed Linux package assets")
    require(assets[deb_name]["asset_sha256"] == release["deb_sha256"]
            and assets[rpm_name]["asset_sha256"] == release["rpm_sha256"],
            "source attestation package digests differ from reviewed release")
    try:
        actual_files = {entry.name for entry in root.iterdir()}
    except OSError as error:
        raise AuditReceiptError(f"cannot enumerate source attestation evidence: {error}") from error
    require(actual_files == expected_files,
            "source attestation evidence does not have the exact eight-file closure")
    evidence_raw: dict[str, bytes] = {summary_name: summary_raw}
    for asset in assets.values():
        name = PurePosixPath(asset["evidence_file"]).name
        _, raw = load_json(
            root / name, f"source attestation evidence {name}", canonical=True
        )
        require(hashlib.sha256(raw).hexdigest() == asset["evidence_sha256"],
                f"source attestation evidence digest differs for {asset['asset']}")
        evidence_raw[name] = raw
    artifacts = [
        {
            "path": f"audit/source-attestations/{name}",
            "sha256": hashlib.sha256(evidence_raw[name]).hexdigest(),
            "size": len(evidence_raw[name]),
        }
        for name in sorted(evidence_raw)
    ]
    return {
        "release_id": release["source_release_id"],
        "source_sha": release["source_sha"],
        "deb_sha256": release["deb_sha256"],
        "rpm_sha256": release["rpm_sha256"],
        "attestation_summary_sha256": hashlib.sha256(summary_raw).hexdigest(),
        "attestations": artifacts,
    }, evidence_raw


def _digest_file(path: Path, label: str) -> dict[str, Any]:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise AuditReceiptError(f"cannot inspect {label}: {error}") from error
    require(stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1,
            f"{label} must be a single-link regular file")
    digest = hashlib.sha256()
    total = 0
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        require((opened.st_dev, opened.st_ino, opened.st_size)
                == (metadata.st_dev, metadata.st_ino, metadata.st_size),
                f"{label} changed while it was opened")
        while True:
            chunk = os.read(descriptor, COPY_CHUNK_SIZE)
            if not chunk:
                break
            total += len(chunk)
            digest.update(chunk)
        after = os.fstat(descriptor)
        require((after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
                == (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
                and total == opened.st_size,
                f"{label} changed while it was read")
    finally:
        os.close(descriptor)
    return {"sha256": digest.hexdigest(), "size": total}


def _artifact(value: Any, label: str) -> dict[str, Any]:
    artifact = exact_object(value, ARTIFACT_FIELDS, label)
    safe_path(artifact["path"], f"{label}.path")
    sha256_string(artifact["sha256"], f"{label}.sha256")
    require(type(artifact["size"]) is int and artifact["size"] > 0,
            f"{label}.size must be a positive integer")
    return artifact


def _archived_artifact(root: Path, relative: PurePosixPath, expected: dict[str, Any], label: str) -> None:
    actual = _digest_file(root.joinpath(*relative.parts), label)
    require(actual == {"sha256": expected["sha256"], "size": expected["size"]},
            f"{label} differs from the signing receipt")


def _artifact_list(value: Any, label: str) -> list[dict[str, Any]]:
    require(isinstance(value, list), f"{label} must be an array")
    result = [_artifact(item, f"{label}[{index}]") for index, item in enumerate(value)]
    paths = [item["path"] for item in result]
    require(paths == sorted(set(paths)), f"{label} paths must be unique and sorted")
    return result


def validate_family_receipt(
    path: Path,
    family: str,
    reviewed_key: dict[str, Any],
    extracted_root: Path,
) -> dict[str, Any]:
    value, raw = load_json(path, f"{family.upper()} signing receipt", canonical=True)
    receipt = exact_object(value, FAMILY_RECEIPT_FIELDS, f"{family.upper()} signing receipt")
    require(receipt["schema"] == FAMILY_RECEIPT_SCHEMA,
            f"{family.upper()} signing receipt schema is invalid")
    require(receipt["family"] == family, f"{family.upper()} signing receipt family conflicts")
    key = exact_object(receipt["key"], KEY_RECEIPT_FIELDS,
                       f"{family.upper()} signing receipt key")
    require(key["family"] == family and key["validated"] is True,
            f"{family.upper()} signing key receipt is not validated")
    for field in (
        "primary_fingerprint",
        "signing_subkey_fingerprint",
        "next_signing_subkey_fingerprint",
        "historical_signing_subkey_fingerprints",
        "public_certificate_sha256",
        "public_certificate_size",
    ):
        require(key[field] == reviewed_key[field],
                f"{family.upper()} signing receipt {field} differs from reviewed signing")
    fingerprint(key["primary_fingerprint"],
                f"{family.upper()} signing receipt primary_fingerprint")
    fingerprint(key["signing_subkey_fingerprint"],
                f"{family.upper()} signing receipt signing_subkey_fingerprint")
    fingerprint(key["next_signing_subkey_fingerprint"],
                f"{family.upper()} signing receipt next_signing_subkey_fingerprint")
    historical = _string_list(
        key["historical_signing_subkey_fingerprints"],
        f"{family.upper()} signing receipt historical_signing_subkey_fingerprints",
    )
    for item in historical:
        fingerprint(item, f"{family.upper()} signing receipt historical fingerprint")
    sha256_string(key["public_certificate_sha256"],
                  f"{family.upper()} signing receipt public_certificate_sha256")
    require(type(key["public_certificate_size"]) is int
            and key["public_certificate_size"] > 0,
            f"{family.upper()} signing receipt public_certificate_size must be positive")
    require(key["minimum_valid_days"] == reviewed_key["minimum_valid_days"]
            and key["maximum_lifetime_days"] == reviewed_key["maximum_lifetime_days"],
            f"{family.upper()} signing receipt policy differs from reviewed signing")
    timestamps = []
    for field in ("signing_subkey_created", "signing_subkey_expires"):
        value = key[field]
        require(isinstance(value, str) and UTC_TIMESTAMP.fullmatch(value) is not None,
                f"{family.upper()} signing receipt {field} is invalid")
        try:
            timestamps.append(datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ"))
        except ValueError as error:
            raise AuditReceiptError(
                f"{family.upper()} signing receipt {field} is invalid"
            ) from error
    require(timestamps[0] < timestamps[1],
            f"{family.upper()} signing subkey lifetime is invalid")

    if family == "apt":
        result = exact_object(receipt["result"], {"inrelease", "release", "release_gpg"},
                              "APT signing result")
        expected_paths = {
            "inrelease": "dists/preview/InRelease",
            "release": "dists/preview/Release",
            "release_gpg": "dists/preview/Release.gpg",
        }
        for field, expected_path in expected_paths.items():
            item = _artifact(result[field], f"APT signing result {field}")
            require(item["path"] == expected_path, f"APT {field} path is unexpected")
            _archived_artifact(
                extracted_root,
                PurePosixPath("site/apt") / expected_path,
                item,
                f"archived APT {field}",
            )
    else:
        result = exact_object(
            receipt["result"],
            {
                "active",
                "new_unsigned_inputs",
                "newly_signed",
                "preserved_signed",
                "repodata",
                "repository",
                "retired",
            },
            "RPM signing result",
        )
        require(result["repository"] == "preview/el/9/x86_64",
                "RPM signing repository path is unexpected")
        lists = {
            field: _artifact_list(result[field], f"RPM signing result {field}")
            for field in (
                "active",
                "new_unsigned_inputs",
                "newly_signed",
                "preserved_signed",
                "repodata",
                "retired",
            )
        }
        package_fields = ("active", "new_unsigned_inputs", "newly_signed", "preserved_signed", "retired")
        for field in package_fields:
            require(all(item["path"].startswith("Packages/") and item["path"].endswith(".rpm")
                        for item in lists[field]),
                    f"RPM signing result {field} contains a non-package path")
        require(all(item["path"].startswith("repodata/") for item in lists["repodata"]),
                "RPM repodata receipt contains an unexpected path")
        new_paths = {item["path"] for item in lists["new_unsigned_inputs"]}
        require(new_paths == {item["path"] for item in lists["newly_signed"]},
                "RPM newly-signed inputs and outputs differ")
        preserved_paths = {item["path"] for item in lists["preserved_signed"]}
        require(new_paths.isdisjoint(preserved_paths),
                "RPM new and preserved package sets overlap")
        require({item["path"] for item in lists["active"]}
                | {item["path"] for item in lists["retired"]}
                == new_paths | preserved_paths,
                "RPM active and retired sets do not close over signed packages")
        for field in ("active", "newly_signed", "preserved_signed", "repodata", "retired"):
            for item in lists[field]:
                _archived_artifact(
                    extracted_root,
                    PurePosixPath("site/rpm") / result["repository"] / item["path"],
                    item,
                    f"archived RPM {field} {item['path']}",
                )
    return {
        "receipt_sha256": hashlib.sha256(raw).hexdigest(),
        "primary_fingerprint": reviewed_key["primary_fingerprint"],
        "signing_subkey_fingerprint": reviewed_key["signing_subkey_fingerprint"],
        "next_signing_subkey_fingerprint": reviewed_key["next_signing_subkey_fingerprint"],
        "historical_signing_subkey_fingerprints": reviewed_key[
            "historical_signing_subkey_fingerprints"
        ],
        "public_certificate_sha256": reviewed_key["public_certificate_sha256"],
        "public_certificate_size": reviewed_key["public_certificate_size"],
    }


def validate_snapshot_public_key(
    value: Any,
    family: str,
    reviewed_key: dict[str, Any],
    extracted_root: Path,
) -> dict[str, Any]:
    item = exact_object(value, PUBLIC_KEY_SNAPSHOT_FIELDS,
                        f"snapshot {family} public key")
    expected = {
        "path": reviewed_key["path"],
        "sha256": reviewed_key["public_certificate_sha256"],
        "size": reviewed_key["public_certificate_size"],
        "primary_fingerprint": reviewed_key["primary_fingerprint"],
        "current_signing_subkey_fingerprint": reviewed_key[
            "signing_subkey_fingerprint"
        ],
        "next_signing_subkey_fingerprint": reviewed_key[
            "next_signing_subkey_fingerprint"
        ],
        "historical_signing_subkey_fingerprints": reviewed_key[
            "historical_signing_subkey_fingerprints"
        ],
    }
    require(item == expected,
            f"snapshot {family} public key differs from reviewed signing")
    path = safe_path(item["path"], f"snapshot {family} public-key path")
    require(path.as_posix() == f"keys/{family}-preview.asc",
            f"snapshot {family} public-key path is unexpected")
    sha256_string(item["sha256"], f"snapshot {family} public-key SHA-256")
    require(type(item["size"]) is int and item["size"] > 0,
            f"snapshot {family} public-key size must be positive")
    for field in (
        "primary_fingerprint",
        "current_signing_subkey_fingerprint",
        "next_signing_subkey_fingerprint",
    ):
        fingerprint(item[field], f"snapshot {family} public key {field}")
    historical = _string_list(
        item["historical_signing_subkey_fingerprints"],
        f"snapshot {family} historical signing-subkey fingerprints",
    )
    for value in historical:
        fingerprint(value, f"snapshot {family} historical signing-subkey fingerprint")
    actual = _digest_file(
        (extracted_root / "site").joinpath(*path.parts),
        f"archived {family.upper()} public certificate",
    )
    require(actual == {"sha256": item["sha256"], "size": item["size"]},
            f"archived {family.upper()} public certificate differs from snapshot inventory")
    return item


def validate_snapshot_source_attestations(
    value: Any,
    source: dict[str, Any] | None,
    extracted_root: Path,
) -> None:
    evidence_root = extracted_root / "audit/source-attestations"
    if source is None:
        require(value is None and not os.path.lexists(evidence_root),
                "non-add-release snapshot must not contain source attestation evidence")
        return
    item = exact_object(value, SOURCE_ATTESTATION_SNAPSHOT_FIELDS,
                        "snapshot source attestations")
    expected = {
        "summary_sha256": source["attestation_summary_sha256"],
        "files": source["attestations"],
    }
    require(item == expected,
            "snapshot source attestation inventory differs from reviewed evidence")
    for index, raw in enumerate(item["files"]):
        artifact = _artifact(raw, f"snapshot source attestation {index}")
        path = safe_path(artifact["path"], f"snapshot source attestation {index}.path")
        require(path.parts[:2] == ("audit", "source-attestations")
                and len(path.parts) == 3,
                "snapshot source attestation paths must be direct archive evidence paths")
        actual = _digest_file(
            extracted_root.joinpath(*path.parts),
            f"archived source attestation {path.name}",
        )
        require(actual == {"sha256": artifact["sha256"], "size": artifact["size"]},
                f"archived source attestation differs from snapshot: {path.name}")


def validate_snapshot(
    value: Any,
    audit_id: int,
    control_sha: str,
    channel_facts: dict[str, Any],
    reviewed_keys: dict[str, dict[str, Any]],
    source: dict[str, Any] | None,
    toolchain: dict[str, Any],
    extracted_root: Path,
) -> dict[str, Any]:
    snapshot = exact_object(value, SNAPSHOT_FIELDS, "archive snapshot")
    require(snapshot["schema"] == SNAPSHOT_SCHEMA,
            f"archive snapshot schema must be {SNAPSHOT_SCHEMA}")
    require(snapshot["audit_release_id"] == audit_id,
            "archive snapshot audit_release_id differs from current plan")
    require(snapshot["control_sha"] == control_sha,
            "archive snapshot control_sha differs from current plan")
    require(snapshot["releases"] == channel_facts["releases"],
            "archive snapshot releases differ from current channels")
    require(snapshot["retirement"] == channel_facts["retirement"],
            "archive snapshot retirement differs from current channels")
    snapshot_toolchain = exact_object(snapshot["toolchain"], TOOLCHAIN_SNAPSHOT_FIELDS,
                                      "snapshot signing toolchain")
    require(snapshot_toolchain == toolchain,
            "snapshot signing toolchain differs from reviewed control")
    actual_toolchain_manifest = _digest_file(
        extracted_root / "audit/signing-toolchain.json",
        "archived signing toolchain manifest",
    )
    require(
        actual_toolchain_manifest
        == {"sha256": toolchain["manifest_sha256"],
            "size": toolchain["manifest_size"]},
        "archived signing toolchain manifest differs from snapshot inventory",
    )
    validate_snapshot_source_attestations(
        snapshot["source_attestations"], source, extracted_root
    )
    public_keys = exact_object(snapshot["public_keys"], {"apt", "rpm"},
                               "snapshot public keys")
    for family in ("apt", "rpm"):
        validate_snapshot_public_key(
            public_keys[family], family, reviewed_keys[family], extracted_root
        )
    payloads = exact_object(snapshot["payloads"], {"apt", "rpm"}, "snapshot payloads")
    releases = {release["version"]: release for release in channel_facts["releases"]}
    for family, source_field, prefix in (
        ("apt", "deb_sha256", "apt/"),
        ("rpm", "rpm_sha256", "rpm/"),
    ):
        values = payloads[family]
        require(isinstance(values, list), f"snapshot {family} payloads must be an array")
        entries = [exact_object(item, PAYLOAD_FIELDS,
                                f"snapshot {family} payload {index}")
                   for index, item in enumerate(values)]
        versions = [entry["version"] for entry in entries]
        require(versions == sorted(releases),
                f"snapshot {family} payload versions must exactly cover current releases")
        for entry in entries:
            version = entry["version"]
            require(isinstance(version, str) and version in releases,
                    f"snapshot {family} payload version is invalid")
            path = safe_path(entry["path"], f"snapshot {family} payload path")
            require(path.as_posix().startswith(prefix),
                    f"snapshot {family} payload path has the wrong family prefix")
            require(path.suffix == (".deb" if family == "apt" else ".rpm"),
                    f"snapshot {family} payload has the wrong package suffix")
            require(sha256_string(entry["source_sha256"],
                                  f"snapshot {family} source_sha256")
                    == releases[version][source_field],
                    f"snapshot {family} source digest differs from current channels")
            published_sha = sha256_string(entry["published_sha256"],
                                          f"snapshot {family} published_sha256")
            if family == "apt":
                require(published_sha == entry["source_sha256"],
                        "snapshot APT published digest differs from its unsigned source")
            actual = _digest_file(
                (extracted_root / "site").joinpath(*path.parts),
                f"archived {family} payload {version}",
            )
            require(actual["sha256"] == published_sha,
                    f"archived {family} payload differs from snapshot inventory")
            require(type(entry["indexed"]) is bool
                    and entry["indexed"] == (releases[version]["state"] == "active"),
                    f"snapshot {family} indexed state differs from current channels")
    return snapshot


def _validate_archive_layout(
    summary: dict[str, Any], source: dict[str, Any] | None
) -> None:
    names = [member["name"] for member in summary["members"]]
    required_audit = {
        "audit/",
        "audit/snapshot.json",
        "audit/plan.json",
        "audit/apt-signing.json",
        "audit/rpm-signing.json",
        "audit/signing-toolchain.json",
    }
    if source is not None:
        required_audit.add("audit/source-attestations/")
        required_audit.update(item["path"] for item in source["attestations"])
    require(required_audit.issubset(names) and "site/" in names,
            "archive must contain the exact audit evidence closure and the site tree")
    for name in names:
        require(name in required_audit or name.startswith("site/"),
                f"archive contains an unexpected path outside audit and site: {name}")


def _require_archived_copy(
    *,
    external_raw: bytes,
    archived_path: Path,
    label: str,
) -> bytes:
    _, archived_raw = load_json(archived_path, f"archived {label}", canonical=True)
    external_sha256 = hashlib.sha256(external_raw).hexdigest()
    archived_sha256 = hashlib.sha256(archived_raw).hexdigest()
    require(
        archived_raw == external_raw and archived_sha256 == external_sha256,
        f"external {label} bytes or SHA-256 differ from the archived recovery copy",
    )
    return archived_raw


def build_audit_receipt(
    *,
    channels_path: Path,
    signing_path: Path,
    signing_toolchain_path: Path,
    apt_public_cert_path: Path,
    rpm_public_cert_path: Path,
    source_attestations_path: Path | None,
    plan_path: Path,
    apt_receipt_path: Path,
    rpm_receipt_path: Path,
    archive_path: Path,
) -> dict[str, Any]:
    channels_value, _ = load_json(Path(channels_path), "channels manifest")
    signing_value, _ = load_json(Path(signing_path), "preview signing manifest")
    toolchain_value, toolchain_raw = load_json(
        Path(signing_toolchain_path), "signing toolchain manifest"
    )
    plan_value, plan_raw = load_json(
        Path(plan_path), "publication plan", canonical=True
    )
    _, apt_receipt_raw = load_json(
        Path(apt_receipt_path), "APT signing receipt", canonical=True
    )
    _, rpm_receipt_raw = load_json(
        Path(rpm_receipt_path), "RPM signing receipt", canonical=True
    )
    channel_facts = validate_channels(channels_value)
    plan = validate_plan(plan_value, channel_facts)
    signing = validate_signing(
        signing_value,
        Path(apt_public_cert_path),
        Path(rpm_public_cert_path),
    )
    toolchain = validate_signing_toolchain(toolchain_value, toolchain_raw)
    source, source_evidence_raw = validate_source_attestation(
        source_attestations_path, plan, channel_facts
    )
    audit_id = plan["audit_release_id"]
    expected_archive = f"wukongim-preview-r{audit_id}-site.tar"
    require(Path(archive_path).name == expected_archive,
            f"archive name must be {expected_archive}")
    try:
        archive_metadata = Path(archive_path).lstat()
    except OSError as error:
        raise AuditReceiptError(f"cannot inspect package archive: {error}") from error
    require(stat.S_ISREG(archive_metadata.st_mode) and archive_metadata.st_nlink == 1,
            "package archive must be a single-link regular file")

    try:
        with tempfile.TemporaryDirectory(prefix="wk-package-audit-receipt-") as temporary:
            extracted = Path(temporary) / "snapshot"
            summary = snapshot_archive.extract_snapshot(
                archive_path=Path(archive_path),
                output_dir=extracted,
                max_members=snapshot_archive.DEFAULT_MAX_MEMBERS,
                max_total_size=ARCHIVE_MAX_TOTAL_BYTES,
            )
            _validate_archive_layout(summary, source)
            archived_plan_raw = _require_archived_copy(
                external_raw=plan_raw,
                archived_path=extracted / "audit" / "plan.json",
                label="publication plan",
            )
            _require_archived_copy(
                external_raw=apt_receipt_raw,
                archived_path=extracted / "audit" / "apt-signing.json",
                label="APT signing receipt",
            )
            _require_archived_copy(
                external_raw=rpm_receipt_raw,
                archived_path=extracted / "audit" / "rpm-signing.json",
                label="RPM signing receipt",
            )
            archived_toolchain_raw = _read_regular(
                extracted / "audit/signing-toolchain.json",
                "archived signing toolchain manifest",
            )
            require(
                archived_toolchain_raw == toolchain_raw,
                "external signing toolchain manifest bytes differ from archive",
            )
            for name, external_raw in source_evidence_raw.items():
                archived_raw = _read_regular(
                    extracted / "audit/source-attestations" / name,
                    f"archived source attestation evidence {name}",
                )
                require(
                    archived_raw == external_raw,
                    f"external source attestation evidence differs from archive: {name}",
                )
            snapshot_path = extracted / "audit" / "snapshot.json"
            snapshot_value, snapshot_raw = load_json(
                snapshot_path, "archive snapshot", canonical=True
            )
            validate_snapshot(
                snapshot_value,
                audit_id,
                plan["control_sha"],
                channel_facts,
                signing,
                source,
                toolchain,
                extracted,
            )
            site_bytes = sum(
                member["size"]
                for member in summary["members"]
                if member["type"] == "file" and member["name"].startswith("site/")
            )
            require(site_bytes <= SITE_LIMIT_BYTES,
                    "package site exceeds the 750 MiB hard limit")
            signer_facts = {
                "apt": validate_family_receipt(
                    Path(apt_receipt_path), "apt", signing["apt"], extracted
                ),
                "rpm": validate_family_receipt(
                    Path(rpm_receipt_path), "rpm", signing["rpm"], extracted
                ),
            }
    except snapshot_archive.ArchiveError as error:
        raise AuditReceiptError(f"package archive validation failed: {error}") from error

    return {
        "schema": RECEIPT_SCHEMA,
        "audit_release_id": audit_id,
        "control_sha": plan["control_sha"],
        "plan": {
            "operation": plan["operation"],
            "base_audit_release_id": plan["base_audit_release_id"],
            "target_version": plan["target_version"],
            "sha256": hashlib.sha256(archived_plan_raw).hexdigest(),
        },
        "archive": {
            "name": expected_archive,
            "size": summary["size"],
            "sha256": summary["sha256"],
            "snapshot_sha256": hashlib.sha256(snapshot_raw).hexdigest(),
        },
        "site": {
            "total_bytes": site_bytes,
            "warning_bytes": SITE_WARNING_BYTES,
            "hard_limit_bytes": SITE_LIMIT_BYTES,
            "warning_exceeded": site_bytes >= SITE_WARNING_BYTES,
        },
        "signers": signer_facts,
        "source": source,
        "toolchain": toolchain,
    }


def validate_external_receipt(value: Any) -> dict[str, Any]:
    receipt = exact_object(value, RECEIPT_FIELDS, "external audit receipt")
    require(receipt["schema"] == RECEIPT_SCHEMA,
            f"external receipt schema must be {RECEIPT_SCHEMA}")
    positive_id(receipt["audit_release_id"], "external receipt audit_release_id")
    require(isinstance(receipt["control_sha"], str) and LOWER_SHA.fullmatch(receipt["control_sha"]),
            "external receipt control_sha is invalid")
    plan = exact_object(receipt["plan"], RECEIPT_PLAN_FIELDS, "external receipt plan")
    require(plan["operation"] in {
        "add_release", "update_bootstrap", "remove_indexes", "remove_payloads",
    },
            "external receipt plan operation is invalid")
    sha256_string(plan["sha256"], "external receipt plan sha256")
    archive_value = exact_object(receipt["archive"], RECEIPT_ARCHIVE_FIELDS,
                                 "external receipt archive")
    require(isinstance(archive_value["name"], str), "external receipt archive name is invalid")
    require(type(archive_value["size"]) is int and archive_value["size"] > 0,
            "external receipt archive size is invalid")
    sha256_string(archive_value["sha256"], "external receipt archive sha256")
    sha256_string(archive_value["snapshot_sha256"],
                  "external receipt snapshot sha256")
    site = exact_object(receipt["site"], RECEIPT_SITE_FIELDS, "external receipt site")
    require(type(site["total_bytes"]) is int and site["total_bytes"] >= 0,
            "external receipt site total_bytes is invalid")
    require(site["warning_bytes"] == SITE_WARNING_BYTES
            and site["hard_limit_bytes"] == SITE_LIMIT_BYTES,
            "external receipt site limits changed")
    require(type(site["warning_exceeded"]) is bool,
            "external receipt warning_exceeded must be boolean")
    require(site["total_bytes"] <= site["hard_limit_bytes"],
            "external receipt site exceeds its hard limit")
    require(site["warning_exceeded"] == (site["total_bytes"] >= site["warning_bytes"]),
            "external receipt site warning classification is inconsistent")
    signers = exact_object(receipt["signers"], {"apt", "rpm"}, "external receipt signers")
    signer_fingerprints: list[str] = []
    for family in ("apt", "rpm"):
        signer = exact_object(signers[family], RECEIPT_SIGNER_FIELDS,
                              f"external receipt {family} signer")
        sha256_string(signer["receipt_sha256"],
                      f"external receipt {family} signer receipt_sha256")
        fingerprint(signer["primary_fingerprint"],
                    f"external receipt {family} primary_fingerprint")
        fingerprint(signer["signing_subkey_fingerprint"],
                    f"external receipt {family} signing_subkey_fingerprint")
        fingerprint(signer["next_signing_subkey_fingerprint"],
                    f"external receipt {family} next_signing_subkey_fingerprint")
        historical = _string_list(
            signer["historical_signing_subkey_fingerprints"],
            f"external receipt {family} historical_signing_subkey_fingerprints",
        )
        for item in historical:
            fingerprint(item, f"external receipt {family} historical fingerprint")
        sha256_string(signer["public_certificate_sha256"],
                      f"external receipt {family} public_certificate_sha256")
        require(type(signer["public_certificate_size"]) is int
                and signer["public_certificate_size"] > 0,
                f"external receipt {family} public_certificate_size must be positive")
        signer_fingerprints.extend([
            signer["primary_fingerprint"],
            signer["signing_subkey_fingerprint"],
            signer["next_signing_subkey_fingerprint"],
            *historical,
        ])
    require(len(signer_fingerprints) == len(set(signer_fingerprints)),
            "external receipt APT and RPM signing fingerprints must all be distinct")
    require(len({value[-16:] for value in signer_fingerprints})
            == len(signer_fingerprints),
            "external receipt signing fingerprints must have distinct 16-hex key IDs")
    require(len({value[-8:] for value in signer_fingerprints})
            == len(signer_fingerprints),
            "external receipt signing fingerprints must have distinct 8-hex key IDs")
    source = receipt["source"]
    require((plan["operation"] == "add_release") == (source is not None),
            "external receipt source identity conflicts with the publication operation")
    if source is not None:
        source = exact_object(source, RECEIPT_SOURCE_FIELDS, "external receipt source")
        positive_id(source["release_id"], "external receipt source release_id")
        require(isinstance(source["source_sha"], str)
                and LOWER_SHA.fullmatch(source["source_sha"]) is not None,
                "external receipt source source_sha is invalid")
        for field in ("deb_sha256", "rpm_sha256", "attestation_summary_sha256"):
            sha256_string(source[field], f"external receipt source {field}")
        attestations = source["attestations"]
        require(isinstance(attestations, list) and len(attestations) == 8,
                "external receipt source attestations must contain eight files")
        paths: list[str] = []
        for index, raw in enumerate(attestations):
            artifact = _artifact(raw, f"external receipt source attestation {index}")
            path = safe_path(
                artifact["path"], f"external receipt source attestation {index}.path"
            )
            require(path.parts[:2] == ("audit", "source-attestations")
                    and len(path.parts) == 3,
                    "external receipt source attestation path is invalid")
            paths.append(path.as_posix())
        require(paths == sorted(set(paths)),
                "external receipt source attestation paths must be unique and sorted")
        summary_path = "audit/source-attestations/source-attestations.json"
        summary_items = [item for item in attestations if item["path"] == summary_path]
        require(len(summary_items) == 1
                and summary_items[0]["sha256"] == source["attestation_summary_sha256"],
                "external receipt source attestation summary identity is inconsistent")
    toolchain = exact_object(receipt["toolchain"], RECEIPT_TOOLCHAIN_FIELDS,
                             "external receipt toolchain")
    require(toolchain["image"] == SIGNING_TOOLCHAIN_IMAGE,
            "external receipt toolchain image is invalid")
    require(isinstance(toolchain["digest"], str)
            and OCI_DIGEST.fullmatch(toolchain["digest"]) is not None,
            "external receipt toolchain digest is invalid")
    require(isinstance(toolchain["workflow_sha"], str)
            and LOWER_SHA.fullmatch(toolchain["workflow_sha"]) is not None,
            "external receipt toolchain workflow_sha is invalid")
    sha256_string(toolchain["manifest_sha256"],
                  "external receipt toolchain manifest_sha256")
    require(type(toolchain["manifest_size"]) is int and toolchain["manifest_size"] > 0,
            "external receipt toolchain manifest_size must be positive")
    return receipt


def _write_exclusive(path: Path, value: dict[str, Any]) -> None:
    require(not os.path.lexists(path), "external receipt output must not already exist")
    try:
        parent = path.parent.lstat()
    except OSError as error:
        raise AuditReceiptError(f"cannot inspect external receipt directory: {error}") from error
    require(stat.S_ISDIR(parent.st_mode) and not stat.S_ISLNK(parent.st_mode),
            "external receipt parent must be a real directory")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, 0o644)
    except OSError as error:
        raise AuditReceiptError(f"cannot create external receipt: {error}") from error
    try:
        raw = canonical_json(value)
        with os.fdopen(descriptor, "wb") as output:
            output.write(raw)
    except Exception as error:
        path.unlink(missing_ok=True)
        raise AuditReceiptError(f"cannot write external receipt: {error}") from error


def create_audit_receipt(*, output_path: Path, **inputs: Any) -> dict[str, Any]:
    receipt = build_audit_receipt(**inputs)
    expected_name = f"wukongim-preview-r{receipt['audit_release_id']}-receipt.json"
    require(Path(output_path).name == expected_name,
            f"external receipt name must be {expected_name}")
    _write_exclusive(Path(output_path), receipt)
    return receipt


def verify_audit_receipt(*, receipt_path: Path, **inputs: Any) -> dict[str, Any]:
    expected = build_audit_receipt(**inputs)
    expected_name = f"wukongim-preview-r{expected['audit_release_id']}-receipt.json"
    require(Path(receipt_path).name == expected_name,
            f"external receipt name must be {expected_name}")
    actual_value, _ = load_json(Path(receipt_path), "external audit receipt", canonical=True)
    actual = validate_external_receipt(actual_value)
    require(actual == expected,
            "external audit receipt differs from the current reviewed inputs or archive")
    return actual


def _common_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--channels", required=True, type=Path)
    parser.add_argument("--signing", required=True, type=Path)
    parser.add_argument("--signing-toolchain", required=True, type=Path)
    parser.add_argument("--apt-public-cert", required=True, type=Path)
    parser.add_argument("--rpm-public-cert", required=True, type=Path)
    parser.add_argument("--source-attestations", type=Path)
    parser.add_argument("--plan", required=True, type=Path)
    parser.add_argument("--apt-receipt", required=True, type=Path)
    parser.add_argument("--rpm-receipt", required=True, type=Path)
    parser.add_argument("--archive", required=True, type=Path)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    create = subparsers.add_parser("create")
    _common_arguments(create)
    create.add_argument("--output", required=True, type=Path)
    verify = subparsers.add_parser("verify")
    _common_arguments(verify)
    verify.add_argument("--receipt", required=True, type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    inputs = {
        "channels_path": args.channels,
        "signing_path": args.signing,
        "signing_toolchain_path": args.signing_toolchain,
        "apt_public_cert_path": args.apt_public_cert,
        "rpm_public_cert_path": args.rpm_public_cert,
        "source_attestations_path": args.source_attestations,
        "plan_path": args.plan,
        "apt_receipt_path": args.apt_receipt,
        "rpm_receipt_path": args.rpm_receipt,
        "archive_path": args.archive,
    }
    try:
        if args.command == "create":
            receipt = create_audit_receipt(output_path=args.output, **inputs)
        else:
            receipt = verify_audit_receipt(receipt_path=args.receipt, **inputs)
    except AuditReceiptError as error:
        print(f"package audit receipt operation failed: {error}", file=sys.stderr)
        return 1
    print(canonical_json(receipt).decode("utf-8"), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
