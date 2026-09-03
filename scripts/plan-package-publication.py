#!/usr/bin/env python3
"""Derive one canonical, reviewed native-package publication transition."""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath
from typing import Any


CHANNELS_SCHEMA = "wukongim.native_package_channels/v3"
SNAPSHOT_SCHEMA = "wukongim.native_package_snapshot/v3"
PLAN_SCHEMA = "wukongim.native_package_publication_plan/v1"
LOWER_SHA = re.compile(r"^[0-9a-f]{40}$")
LOWER_SHA256 = re.compile(r"^[0-9a-f]{64}$")
UPPER_FINGERPRINT = re.compile(r"^[0-9A-F]{40}$")
OCI_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
UTC_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
RETIREMENT_MINIMUM_DELAY = timedelta(minutes=30)
SIGNING_TOOLCHAIN_IMAGE = "ghcr.io/wukongim/native-package-signing-toolchain"
SEMVER_PRERELEASE = re.compile(
    r"^((?:0|[1-9][0-9]*))\."
    r"((?:0|[1-9][0-9]*))\."
    r"((?:0|[1-9][0-9]*))-"
    r"((?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)"
    r"(?:\.(?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*))*)$"
)
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
SNAPSHOT_FIELDS = {
    "schema", "audit_release_id", "control_sha", "releases", "retirement",
    "payloads", "public_keys", "source_attestations", "toolchain",
}
PUBLIC_KEY_FIELDS = {
    "path", "sha256", "size", "primary_fingerprint",
    "current_signing_subkey_fingerprint", "next_signing_subkey_fingerprint",
    "historical_signing_subkey_fingerprints",
}
SOURCE_ATTESTATION_FIELDS = {"summary_sha256", "files"}
ARTIFACT_FIELDS = {"path", "sha256", "size"}
TOOLCHAIN_FIELDS = {
    "image", "digest", "workflow_sha", "manifest_sha256", "manifest_size",
}


class PlanError(ValueError):
    """Raised when the desired snapshot is not one legal reviewed transition."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise PlanError(message)


def reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        require(key not in value, f"duplicate JSON key: {key}")
        value[key] = item
    return value


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicate_pairs)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise PlanError(f"cannot read JSON input {path.name}: {error}") from error


def exact_object(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    require(isinstance(value, dict), f"{label} must be an object")
    require(set(value) == fields, f"{label} fields must be exactly {sorted(fields)}")
    return value


def positive_id(value: Any, label: str) -> int:
    require(type(value) is int and value > 0, f"{label} must be a positive integer")
    return value


def release_map(values: Any, label: str) -> dict[str, dict[str, Any]]:
    require(isinstance(values, list), f"{label} must be an array")
    result: dict[str, dict[str, Any]] = {}
    for index, raw in enumerate(values):
        release = exact_object(raw, RELEASE_FIELDS, f"{label}[{index}]")
        version = release["version"]
        require(isinstance(version, str) and SEMVER_PRERELEASE.fullmatch(version) is not None,
                f"{label}[{index}].version must be strict prerelease SemVer")
        require(version not in result, f"{label} contains duplicate version {version}")
        result[version] = release
    return result


def semver_prerelease_key(version: str) -> tuple[tuple[int, int, int], tuple[tuple[int, Any], ...]]:
    """Return a comparison key implementing strict SemVer prerelease precedence."""
    match = SEMVER_PRERELEASE.fullmatch(version)
    require(match is not None, "version must be strict prerelease SemVer")
    core = tuple(int(match.group(index)) for index in (1, 2, 3))
    prerelease: list[tuple[int, Any]] = []
    for identifier in match.group(4).split("."):
        prerelease.append((0, int(identifier)) if identifier.isdigit() else (1, identifier))
    return core, tuple(prerelease)


def semver_is_greater(candidate: str, baseline: str) -> bool:
    """Compare two strict prerelease SemVer values without build metadata."""
    candidate_core, candidate_pre = semver_prerelease_key(candidate)
    baseline_core, baseline_pre = semver_prerelease_key(baseline)
    if candidate_core != baseline_core:
        return candidate_core > baseline_core
    for left, right in zip(candidate_pre, baseline_pre):
        if left == right:
            continue
        if left[0] != right[0]:
            return left[0] > right[0]
        return left[1] > right[1]
    return len(candidate_pre) > len(baseline_pre)


def package_versions(version: str) -> tuple[str, str]:
    """Map one reviewed source version to its exact DEB and RPM versions."""
    semver_prerelease_key(version)
    deb = version.replace("-", "~", 1)
    return deb, deb.replace("-", "_")


def native_version_is_greater(
    candidate: str,
    baseline: str,
    *,
    runner: Any = subprocess.run,
) -> bool:
    """Require both fixed package managers to rank candidate above baseline."""
    dpkg = shutil.which("dpkg")
    rpm = shutil.which("rpm")
    require(dpkg is not None and rpm is not None,
            "dpkg and rpm are required for native package version comparison")
    candidate_deb, candidate_rpm = package_versions(candidate)
    baseline_deb, baseline_rpm = package_versions(baseline)
    deb_result = runner(
        [dpkg, "--compare-versions", candidate_deb, "gt", baseline_deb],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    rpm_expression = (
        f'%{{lua: print(rpm.vercmp("{candidate_rpm}", "{baseline_rpm}"))}}'
    )
    rpm_result = runner(
        [rpm, "--eval", rpm_expression],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    require(deb_result.returncode in {0, 1}, "dpkg version comparison failed")
    require(rpm_result.returncode == 0, "RPM version comparison failed")
    try:
        rpm_order = rpm_result.stdout.decode("ascii", errors="strict").strip()
    except UnicodeDecodeError as error:
        raise PlanError("RPM version comparison returned non-ASCII output") from error
    require(rpm_order in {"-1", "0", "1"}, "RPM version comparison returned invalid output")
    return deb_result.returncode == 0 and rpm_order == "1"


def validate_native_version_transition(
    plan: dict[str, Any], base: dict[str, Any] | None
) -> None:
    """Cross-check reviewed monotonicity with the actual fixed package tools."""
    if base is None:
        return
    base_active = [
        item["version"] for item in base["releases"] if item["state"] == "active"
    ]
    target = plan["target_version"]
    if plan["operation"] == "add_release":
        for version in base_active:
            require(
                native_version_is_greater(target, version),
                f"add_release target {target} is not newer than active {version} in both package managers",
            )
    elif plan["operation"] == "remove_indexes":
        for version in base_active:
            if version == target:
                continue
            require(
                native_version_is_greater(version, target),
                f"remove_indexes target {target} is not the oldest active native package version",
            )


def parse_utc(value: Any, label: str) -> datetime:
    require(isinstance(value, str), f"{label} must be a UTC timestamp")
    try:
        parsed = datetime.strptime(value, UTC_FORMAT).replace(tzinfo=timezone.utc)
    except ValueError as error:
        raise PlanError(f"{label} must use RFC3339 UTC second precision") from error
    return parsed


def same_except(left: dict[str, Any], right: dict[str, Any], excluded: set[str]) -> bool:
    return all(left[field] == right[field] for field in RELEASE_FIELDS - excluded)


def sha256(value: Any, label: str) -> str:
    require(isinstance(value, str) and LOWER_SHA256.fullmatch(value) is not None,
            f"{label} must be a lowercase SHA-256")
    return value


def fingerprint(value: Any, label: str) -> str:
    require(isinstance(value, str) and UPPER_FINGERPRINT.fullmatch(value) is not None,
            f"{label} must be an uppercase 40-hex fingerprint")
    return value


def artifact(value: Any, label: str) -> dict[str, Any]:
    item = exact_object(value, ARTIFACT_FIELDS, label)
    path_value = item["path"]
    require(isinstance(path_value, str) and path_value,
            f"{label}.path must be a canonical relative POSIX path")
    path = PurePosixPath(path_value)
    require(not path.is_absolute() and path.as_posix() == path_value
            and all(part not in {"", ".", ".."} for part in path.parts),
            f"{label}.path must be a canonical relative POSIX path")
    sha256(item["sha256"], f"{label}.sha256")
    require(type(item["size"]) is int and item["size"] > 0,
            f"{label}.size must be a positive integer")
    return item


def validate_public_keys(value: Any) -> None:
    families = exact_object(value, {"apt", "rpm"}, "base snapshot public_keys")
    all_fingerprints: list[str] = []
    for family in ("apt", "rpm"):
        key = exact_object(families[family], PUBLIC_KEY_FIELDS,
                           f"base snapshot {family} public key")
        require(key["path"] == f"keys/{family}-preview.asc",
                f"base snapshot {family} public key path is invalid")
        sha256(key["sha256"], f"base snapshot {family} public key sha256")
        require(type(key["size"]) is int and key["size"] > 0,
                f"base snapshot {family} public key size must be positive")
        current = fingerprint(
            key["current_signing_subkey_fingerprint"],
            f"base snapshot {family} current signing-subkey fingerprint",
        )
        successor = fingerprint(
            key["next_signing_subkey_fingerprint"],
            f"base snapshot {family} next signing-subkey fingerprint",
        )
        primary = fingerprint(
            key["primary_fingerprint"], f"base snapshot {family} primary fingerprint"
        )
        historical = key["historical_signing_subkey_fingerprints"]
        require(isinstance(historical, list)
                and all(isinstance(item, str) for item in historical)
                and historical == sorted(set(historical)),
                f"base snapshot {family} historical fingerprints must be unique and sorted")
        for item in historical:
            fingerprint(item, f"base snapshot {family} historical fingerprint")
        all_fingerprints.extend([primary, current, successor, *historical])
    require(len(all_fingerprints) == len(set(all_fingerprints)),
            "base snapshot signing fingerprints must all be distinct")
    require(len({value[-16:] for value in all_fingerprints}) == len(all_fingerprints),
            "base snapshot signing fingerprints must have distinct 16-hex key IDs")
    require(len({value[-8:] for value in all_fingerprints}) == len(all_fingerprints),
            "base snapshot signing fingerprints must have distinct 8-hex key IDs")


def validate_source_attestations(value: Any) -> None:
    if value is None:
        return
    source = exact_object(value, SOURCE_ATTESTATION_FIELDS,
                          "base snapshot source_attestations")
    summary_sha = sha256(source["summary_sha256"],
                         "base snapshot source attestation summary_sha256")
    values = source["files"]
    require(isinstance(values, list) and len(values) == 8,
            "base snapshot source attestations must contain eight files")
    paths: list[str] = []
    summary_matches = 0
    for index, raw in enumerate(values):
        item = artifact(raw, f"base snapshot source attestation file {index}")
        path = PurePosixPath(item["path"])
        require(path.parts[:2] == ("audit", "source-attestations")
                and len(path.parts) == 3,
                "base snapshot source attestation paths are invalid")
        paths.append(path.as_posix())
        if path.name == "source-attestations.json":
            require(item["sha256"] == summary_sha,
                    "base snapshot source attestation summary digest is inconsistent")
            summary_matches += 1
    require(paths == sorted(set(paths)),
            "base snapshot source attestation paths must be unique and sorted")
    require(summary_matches == 1,
            "base snapshot source attestations must contain the canonical summary")


def validate_toolchain(value: Any) -> None:
    toolchain = exact_object(value, TOOLCHAIN_FIELDS, "base snapshot toolchain")
    require(toolchain["image"] == SIGNING_TOOLCHAIN_IMAGE,
            "base snapshot toolchain image is invalid")
    require(isinstance(toolchain["digest"], str)
            and OCI_DIGEST.fullmatch(toolchain["digest"]) is not None,
            "base snapshot toolchain digest is invalid")
    require(isinstance(toolchain["workflow_sha"], str)
            and LOWER_SHA.fullmatch(toolchain["workflow_sha"]) is not None,
            "base snapshot toolchain workflow_sha is invalid")
    sha256(toolchain["manifest_sha256"], "base snapshot toolchain manifest_sha256")
    require(type(toolchain["manifest_size"]) is int and toolchain["manifest_size"] > 0,
            "base snapshot toolchain manifest_size must be positive")


def load_base(path: Path | None, expected_id: int | None) -> dict[str, Any] | None:
    if expected_id is None:
        require(path is None, "a base snapshot is forbidden when base_audit_release_id is null")
        return None
    require(path is not None, "a base snapshot is required for this operation")
    snapshot = exact_object(
        load_json(path),
        SNAPSHOT_FIELDS,
        "base snapshot",
    )
    require(snapshot["schema"] == SNAPSHOT_SCHEMA, f"base snapshot schema must be {SNAPSHOT_SCHEMA}")
    require(positive_id(snapshot["audit_release_id"], "base snapshot audit_release_id") == expected_id,
            "base snapshot audit_release_id does not match reviewed control")
    require(isinstance(snapshot["control_sha"], str) and LOWER_SHA.fullmatch(snapshot["control_sha"]),
            "base snapshot control_sha must be a lowercase 40-hex commit")
    require(isinstance(snapshot["retirement"], dict), "base snapshot retirement must be an object")
    require(isinstance(snapshot["payloads"], dict), "base snapshot payloads must be an object")
    validate_public_keys(snapshot["public_keys"])
    validate_source_attestations(snapshot["source_attestations"])
    validate_toolchain(snapshot["toolchain"])
    return snapshot


def build_plan(channels: dict[str, Any], base: dict[str, Any] | None, control_sha: str,
               now: datetime) -> dict[str, Any]:
    require(channels.get("schema") == CHANNELS_SCHEMA, f"channels schema must be {CHANNELS_SCHEMA}")
    require(LOWER_SHA.fullmatch(control_sha) is not None, "control_sha must be a lowercase 40-hex commit")
    require(now.tzinfo is not None and now.utcoffset() is not None,
            "now must be timezone-aware")
    now = now.astimezone(timezone.utc)
    try:
        preview = channels["channels"]["preview"]
        publication = preview["publication"]
    except (KeyError, TypeError) as error:
        raise PlanError("channels preview publication control is missing") from error
    publication = exact_object(
        publication,
        {"audit_release_id", "base_audit_release_id", "operation", "target_version"},
        "preview publication",
    )
    operation = publication["operation"]
    require(
        operation in {
            "none",
            "add_release",
            "remove_indexes",
            "remove_payloads",
            "update_bootstrap",
        },
        "unsupported publication operation",
    )
    current = release_map(preview.get("releases"), "preview releases")
    current_id = publication["audit_release_id"]
    base_id = publication["base_audit_release_id"]
    target = publication["target_version"]

    if operation == "none":
        require(current_id is None and base_id is None and target is None,
                "operation none requires null publication identity")
        require(base is None and not current, "operation none requires no snapshot and no releases")
        return {
            "schema": PLAN_SCHEMA,
            "control_sha": control_sha,
            "operation": operation,
            "audit_release_id": None,
            "base_audit_release_id": None,
            "target_version": None,
            "active_versions": [],
            "retained_versions": [],
            "new_versions": [],
            "removed_versions": [],
            "not_before": None,
        }

    current_id = positive_id(current_id, "publication audit_release_id")
    require(base_id is None or (type(base_id) is int and base_id > 0),
            "publication base_audit_release_id must be null or positive")
    require(current_id != base_id, "publication audit and base Release ids must differ")
    require(isinstance(target, str) and target != "", "publication target_version is required")
    base_releases = release_map(base["releases"], "base releases") if base is not None else {}
    new_versions: list[str] = []
    removed_versions: list[str] = []
    transition_not_before: str | None = None

    if operation == "add_release":
        require(target in current and current[target]["state"] == "active",
                "add_release target must be an active release")
        require(current[target]["package_release_id"] == current_id,
                "new release package_release_id must equal publication audit_release_id")
        require(set(current) == set(base_releases) | {target} and target not in base_releases,
                "add_release must add exactly the target version")
        for version, old in base_releases.items():
            require(current[version] == old, f"add_release changed existing version {version}")
            if old["state"] == "active":
                require(
                    semver_is_greater(target, version),
                    f"add_release target {target} must be newer than active {version}",
                )
        new_versions = [target]
    elif operation == "update_bootstrap":
        require(
            base_id is not None and base is not None,
            "update_bootstrap requires a base audit Release",
        )
        require(
            target in current and current[target]["state"] == "active",
            "update_bootstrap target must be an active release",
        )
        require(
            preview.get("releases") == base["releases"],
            "update_bootstrap must not change releases",
        )
        require(
            preview.get("retirement") == base["retirement"],
            "update_bootstrap must not change retirement",
        )
    elif operation == "remove_indexes":
        require(base is not None and target in current and target in base_releases,
                "remove_indexes target must exist in current and base snapshots")
        require(set(current) == set(base_releases), "remove_indexes must not add or remove versions")
        require(base_releases[target]["state"] == "active" and current[target]["state"] == "index_removed",
                "remove_indexes must transition target from active to index_removed")
        require(same_except(current[target], base_releases[target], {"state", "not_before"}),
                "remove_indexes changed immutable target identity")
        transition_not_before = current[target]["not_before"]
        eligible_at = parse_utc(transition_not_before, "remove_indexes target not_before")
        require(
            eligible_at >= now + RETIREMENT_MINIMUM_DELAY,
            "remove_indexes target not_before must be at least 30 minutes after the current time",
        )
        for version in set(current) - {target}:
            require(current[version] == base_releases[version],
                    f"remove_indexes changed unrelated version {version}")
            if base_releases[version]["state"] == "active":
                require(
                    semver_is_greater(version, target),
                    f"remove_indexes target {target} must be the oldest active version",
                )
    else:
        require(base is not None and target not in current and target in base_releases,
                "remove_payloads must remove exactly a base version")
        require(base_releases[target]["state"] == "index_removed",
                "remove_payloads target must already have indexes removed")
        require(set(base_releases) == set(current) | {target},
                "remove_payloads must remove exactly the target version")
        for version, release in current.items():
            require(release == base_releases[version],
                    f"remove_payloads changed retained version {version}")
        eligible_at = parse_utc(base_releases[target]["not_before"],
                                "remove_payloads target not_before")
        require(now >= eligible_at, "remove_payloads is earlier than the reviewed not_before")
        removed_versions = [target]
        transition_not_before = base_releases[target]["not_before"]

    active = sorted(version for version, release in current.items() if release["state"] == "active")
    retained = sorted(version for version, release in current.items() if release["state"] == "index_removed")
    require(active, "an enabled preview snapshot must retain at least one active version")
    require(len(retained) <= 1, "at most one version may be retained outside indexes")
    return {
        "schema": PLAN_SCHEMA,
        "control_sha": control_sha,
        "operation": operation,
        "audit_release_id": current_id,
        "base_audit_release_id": base_id,
        "target_version": target,
        "active_versions": active,
        "retained_versions": retained,
        "new_versions": new_versions,
        "removed_versions": removed_versions,
        "not_before": transition_not_before,
    }


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--channels", type=Path, required=True)
    parser.add_argument("--base-snapshot", type=Path)
    parser.add_argument("--control-sha", required=True)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        channels = load_json(args.channels)
        preview = channels.get("channels", {}).get("preview", {}) if isinstance(channels, dict) else {}
        publication = preview.get("publication", {}) if isinstance(preview, dict) else {}
        base_id = publication.get("base_audit_release_id") if isinstance(publication, dict) else None
        base = load_base(args.base_snapshot, base_id)
        plan = build_plan(channels, base, args.control_sha, datetime.now(timezone.utc))
        validate_native_version_transition(plan, base)
    except PlanError as error:
        print(f"publication planning failed: {error}", file=sys.stderr)
        return 1
    json.dump(plan, sys.stdout, sort_keys=True, separators=(",", ":"))
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
