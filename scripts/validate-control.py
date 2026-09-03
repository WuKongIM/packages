#!/usr/bin/env python3
"""Validate the reviewed control plane for the native package repository."""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
from datetime import datetime
import time
from pathlib import Path
from typing import Any


CHANNELS_SCHEMA = "wukongim.native_package_channels/v3"
BOOTSTRAP_SCHEMA = "wukongim.native_package_bootstrap/v1"
SIGNING_SCHEMA = "wukongim.native_package_signing/v3"
SIGNING_TOOLCHAIN_SCHEMA = "wukongim.native_package_signing_toolchain/v1"
TOOLCHAIN_SCHEMA = "wukongim.native_package_toolchain/v1"
SOURCE_READ_SCHEMA = "wukongim.native_package_source_read/v1"
AUDIT_ACCESS_SCHEMA = "wukongim.native_package_audit_access/v1"
SOURCE_REPOSITORY = "WuKongIM/WuKongIM"
SITE_LIMIT_BYTES = 750 * 1024 * 1024
SITE_WARNING_BYTES = 600 * 1024 * 1024
MAX_ONLINE_VERSIONS = 4
SIGNING_TOOLCHAIN_IMAGE = "ghcr.io/wukongim/native-package-signing-toolchain"

SEMVER_PRERELEASE = re.compile(
    r"^(?:0|[1-9][0-9]*)\."
    r"(?:0|[1-9][0-9]*)\."
    r"(?:0|[1-9][0-9]*)-"
    r"(?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)"
    r"(?:\.(?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*))*$"
)
SEMVER_RELEASE = re.compile(
    r"^(?:0|[1-9][0-9]*)\."
    r"(?:0|[1-9][0-9]*)\."
    r"(?:0|[1-9][0-9]*)$"
)
LOWER_SHA = re.compile(r"^[0-9a-f]{40}$")
LOWER_SHA256 = re.compile(r"^[0-9a-f]{64}$")
UPPER_FINGERPRINT = re.compile(r"^[0-9A-F]{40}$")
UTC_TIMESTAMP = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
RPM_RSA_ALGORITHM = "1"
RPM_RSA_BITS = frozenset({"3072", "4096"})

CHANNEL_FIELDS = {
    "schema",
    "source_repository",
    "site_limit_bytes",
    "site_warning_bytes",
    "max_online_versions",
    "architectures",
    "channels",
}
BOOTSTRAP_FIELDS = {"schema", "enabled", "version"}
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
KEY_FIELDS = {
    "environment",
    "public_key",
    "primary_fingerprint",
    "signing_subkeys",
    "secret_subkey_env",
    "passphrase_env",
}
SIGNING_SUBKEY_FIELDS = {"current", "next", "historical"}
SIGNING_TOOLCHAIN_FIELDS = {
    "schema",
    "enabled",
    "image",
    "digest",
    "workflow_sha",
}
AUDIT_ACCESS_FIELDS = {"schema", "enabled", "reader", "writer"}
AUDIT_APP_FIELDS = {
    "environment",
    "app_client_id_secret",
    "app_private_key_secret",
    "owner",
    "repositories",
    "permissions",
}
TRUSTED_TOOL_FILES = {
    "scripts/build-native-package-repositories.sh",
    "scripts/generate-native-package-test-keyring.sh",
    "scripts/sign-native-package-repositories.sh",
    "scripts/validate-native-package-repositories-container.sh",
    "scripts/verify-native-package-metadata.py",
    "scripts/verify-native-package-repositories.sh",
}


class ContractError(ValueError):
    """Raised when a reviewed publication contract is violated."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ContractError(message)


def exact_fields(value: Any, expected: set[str], context: str) -> dict[str, Any]:
    require(isinstance(value, dict), f"{context} must be an object")
    actual = set(value)
    require(actual == expected, f"{context} fields must be exactly {sorted(expected)}")
    return value


def reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ContractError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicate_pairs)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ContractError(f"cannot read {path}: {error}") from error


def validate_bootstrap_packages(root: Path) -> dict[str, Any]:
    bootstrap = exact_fields(
        load_json(root / "manifests/bootstrap-packages.json"),
        BOOTSTRAP_FIELDS,
        "bootstrap-packages manifest",
    )
    require(
        bootstrap["schema"] == BOOTSTRAP_SCHEMA,
        f"bootstrap-packages schema must be {BOOTSTRAP_SCHEMA}",
    )
    require(
        type(bootstrap["enabled"]) is bool,
        "bootstrap-packages enabled must be boolean",
    )
    require(
        isinstance(bootstrap["version"], str)
        and SEMVER_RELEASE.fullmatch(bootstrap["version"]),
        "bootstrap-packages version must be strict release SemVer without a v prefix, "
        "prerelease, or build metadata",
    )
    return bootstrap


def positive_integer(value: Any, context: str) -> None:
    require(type(value) is int and value > 0, f"{context} must be a positive integer")


def utc_timestamp(value: Any, context: str) -> None:
    require(isinstance(value, str) and UTC_TIMESTAMP.fullmatch(value) is not None,
            f"{context} must be an RFC3339 UTC timestamp with second precision")
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as error:
        raise ContractError(f"{context} is not a valid timestamp") from error


def validate_release(value: Any, index: int) -> dict[str, Any]:
    release = exact_fields(value, RELEASE_FIELDS, f"preview release {index}")
    prefix = f"preview release {index}"
    require(isinstance(release["version"], str) and SEMVER_PRERELEASE.fullmatch(release["version"]),
            f"{prefix}.version must be strict prerelease SemVer without a v prefix or build metadata")
    require(isinstance(release["source_sha"], str) and LOWER_SHA.fullmatch(release["source_sha"]),
            f"{prefix}.source_sha must be a lowercase 40-hex commit")
    positive_integer(release["source_release_id"], f"{prefix}.source_release_id")
    positive_integer(release["package_release_id"], f"{prefix}.package_release_id")
    for name in ("deb_sha256", "rpm_sha256"):
        require(isinstance(release[name], str) and LOWER_SHA256.fullmatch(release[name]),
                f"{prefix}.{name} must be a lowercase SHA-256")
    require(release["state"] in {"active", "index_removed"},
            f"{prefix}.state must be active or index_removed")
    if release["state"] == "active":
        require(release["not_before"] is None, f"{prefix}.not_before must be null while active")
    else:
        utc_timestamp(release["not_before"], f"{prefix}.not_before")
    return release


def validate_publication(
    value: Any,
    releases: list[dict[str, Any]],
    retirement: dict[str, Any],
    bootstrap_enabled: bool,
) -> dict[str, Any]:
    publication = exact_fields(value, PUBLICATION_FIELDS, "preview publication")
    operation = publication["operation"]
    require(
        operation in {
            "none",
            "add_release",
            "remove_indexes",
            "remove_payloads",
            "update_bootstrap",
        },
        "preview publication.operation must be none, add_release, remove_indexes, "
        "remove_payloads, or update_bootstrap",
    )

    audit_release_id = publication["audit_release_id"]
    base_audit_release_id = publication["base_audit_release_id"]
    target_version = publication["target_version"]
    if operation == "none":
        require(
            audit_release_id is None
            and base_audit_release_id is None
            and target_version is None,
            "publication none requires null audit_release_id, base_audit_release_id, "
            "and target_version",
        )
        require(not releases and retirement["phase"] == "none",
                "publication none requires no releases or retirement")
        return publication

    positive_integer(audit_release_id, "preview publication.audit_release_id")
    require(
        isinstance(target_version, str) and SEMVER_PRERELEASE.fullmatch(target_version),
        "preview publication.target_version must be strict prerelease SemVer",
    )
    matching = [release for release in releases if release["version"] == target_version]

    if operation == "add_release":
        require(retirement["phase"] == "none",
                "add_release is forbidden while retirement is in progress")
        require(len(matching) == 1 and matching[0]["state"] == "active",
                "add_release target must be exactly one active preview release")
        require(matching[0]["package_release_id"] == audit_release_id,
                "add_release audit_release_id must match the target package_release_id")
        if len(releases) == 1:
            require(base_audit_release_id is None,
                    "the first add_release requires a null base_audit_release_id")
        else:
            positive_integer(base_audit_release_id,
                             "preview publication.base_audit_release_id")
            require(base_audit_release_id != audit_release_id,
                    "publication audit and base audit Release IDs must differ")
    elif operation == "remove_indexes":
        positive_integer(base_audit_release_id, "preview publication.base_audit_release_id")
        require(base_audit_release_id != audit_release_id,
                "publication audit and base audit Release IDs must differ")
        require(len(matching) == 1 and matching[0]["state"] == "index_removed",
                "remove_indexes target must be exactly one index_removed preview release")
        require(
            retirement["phase"] == "indexes_removed"
            and retirement["version"] == target_version,
            "remove_indexes target must match the indexes_removed retirement",
        )
    elif operation == "remove_payloads":
        positive_integer(base_audit_release_id, "preview publication.base_audit_release_id")
        require(base_audit_release_id != audit_release_id,
                "publication audit and base audit Release IDs must differ")
        require(not matching, "remove_payloads target must be absent from preview releases")
        require(retirement["phase"] == "none",
                "remove_payloads requires retirement.phase none")
    else:
        positive_integer(
            base_audit_release_id,
            "update_bootstrap requires a base_audit_release_id",
        )
        require(base_audit_release_id != audit_release_id,
                "publication audit and base audit Release IDs must differ")
        require(
            bootstrap_enabled,
            "update_bootstrap requires enabled bootstrap-packages control",
        )
        require(
            len(matching) == 1 and matching[0]["state"] == "active",
            "update_bootstrap target must be exactly one active preview release",
        )
    return publication


def validate_channels(root: Path, bootstrap_enabled: bool) -> dict[str, Any]:
    channels = exact_fields(load_json(root / "manifests/channels.json"), CHANNEL_FIELDS, "channels manifest")
    require(channels["schema"] == CHANNELS_SCHEMA, f"channels schema must be {CHANNELS_SCHEMA}")
    require(channels["source_repository"] == SOURCE_REPOSITORY,
            f"source_repository must be {SOURCE_REPOSITORY}")
    require(channels["site_limit_bytes"] == SITE_LIMIT_BYTES,
            f"site_limit_bytes must remain {SITE_LIMIT_BYTES}")
    require(channels["site_warning_bytes"] == SITE_WARNING_BYTES,
            f"site_warning_bytes must remain {SITE_WARNING_BYTES}")
    require(channels["site_warning_bytes"] < channels["site_limit_bytes"],
            "site warning threshold must remain below the hard limit")
    require(channels["max_online_versions"] == MAX_ONLINE_VERSIONS,
            f"max_online_versions must remain {MAX_ONLINE_VERSIONS}")
    require(channels["architectures"] == ["amd64"], "only amd64 may be published on Pages")

    channel_map = exact_fields(channels["channels"], {"preview", "stable"}, "channels")
    preview = exact_fields(channel_map["preview"], PREVIEW_FIELDS, "preview channel")
    stable = exact_fields(channel_map["stable"], STABLE_FIELDS, "stable channel")
    require(type(preview["enabled"]) is bool, "preview.enabled must be boolean")
    require(isinstance(preview["status"], str), "preview.status must be a string")
    require(isinstance(preview["releases"], list), "preview.releases must be an array")
    require(len(preview["releases"]) <= MAX_ONLINE_VERSIONS,
            f"preview may retain at most {MAX_ONLINE_VERSIONS} versions")
    releases = [validate_release(item, index) for index, item in enumerate(preview["releases"])]

    for field in ("version", "source_sha", "source_release_id", "package_release_id"):
        values = [release[field] for release in releases]
        require(len(values) == len(set(values)), f"preview release {field} values must be unique")

    retirement = exact_fields(preview["retirement"], RETIREMENT_FIELDS, "preview retirement")
    removed = [release for release in releases if release["state"] == "index_removed"]
    require(len(removed) <= 1, "only one preview version may be in retirement")
    if retirement["phase"] == "none":
        require(retirement["version"] is None and retirement["not_before"] is None,
                "retirement none requires null version and not_before")
        require(not removed, "retirement none forbids an index_removed release")
    elif retirement["phase"] == "indexes_removed":
        require(len(removed) == 1, "indexes_removed requires exactly one index_removed release")
        utc_timestamp(retirement["not_before"], "preview retirement.not_before")
        require(retirement["version"] == removed[0]["version"],
                "retirement.version must match the index_removed release")
        require(retirement["not_before"] == removed[0]["not_before"],
                "retirement.not_before must match the index_removed release")
    else:
        raise ContractError("preview retirement.phase must be none or indexes_removed")

    validate_publication(
        preview["publication"], releases, retirement, bootstrap_enabled
    )

    require(type(stable["enabled"]) is bool and stable["enabled"] is False,
            "stable publishing must remain disabled on GitHub Pages")
    require(stable["status"] == "object_storage_required",
            "stable.status must remain object_storage_required")
    require(stable["releases"] == [], "stable releases must remain empty on GitHub Pages")
    return channels


def _key_timestamp(record: list[str], index: int, label: str, *, optional: bool = False) -> int | None:
    require(len(record) > index, f"{label} omits its timestamp")
    value = record[index]
    if optional and value == "":
        return None
    require(value.isascii() and value.isdigit() and int(value) > 0,
            f"{label} has an invalid timestamp")
    return int(value)


def _validate_sign_only(record: list[str], label: str) -> None:
    capabilities = record[11] if len(record) > 11 else ""
    require("s" in capabilities and not any(capability in capabilities for capability in "cea"),
            f"{label} must be sign-only")


def _validate_rpm_rsa_key(record: list[str], label: str) -> None:
    require(
        len(record) > 3 and record[3] == RPM_RSA_ALGORITHM,
        f"{label} must use GnuPG public-key algorithm 1 (RSA)",
    )
    require(
        len(record) > 2 and record[2] in RPM_RSA_BITS,
        f"{label} RSA key must be exactly 3072 or 4096 bits",
    )


def validate_public_certificate(
    path: Path,
    primary_fingerprint: str,
    signing_subkeys: dict[str, Any],
    *,
    family: str,
    minimum_valid_days: int,
    rotation_begin_days: int,
    maximum_lifetime_days: int,
    now: int | None = None,
) -> None:
    try:
        contents = path.read_bytes()
    except OSError as error:
        raise ContractError(f"cannot read public key {path.name}: {error}") from error
    require(
        contents.startswith(b"-----BEGIN PGP PUBLIC KEY BLOCK-----\n")
        and contents.rstrip().endswith(b"-----END PGP PUBLIC KEY BLOCK-----"),
        f"{path.name} must be an ASCII-armored OpenPGP public certificate",
    )

    with tempfile.TemporaryDirectory(prefix="wukongim-public-key-") as home:
        os.chmod(home, 0o700)
        command = [
            "gpg",
            "--batch",
            "--no-options",
            "--homedir",
            home,
            "--no-auto-key-retrieve",
            "--with-colons",
            "--show-keys",
            str(path),
        ]
        try:
            result = subprocess.run(command, check=False, capture_output=True, text=True)
        except OSError as error:
            raise ContractError(f"cannot inspect {path.name} with gpg: {error}") from error
    require(result.returncode == 0, f"gpg rejected public certificate {path.name}")

    records = [line.split(":") for line in result.stdout.splitlines() if line]
    require(not any(record[0] in {"sec", "ssb"} for record in records),
            f"{path.name} must not contain OpenPGP secret-key packets")
    keys = [record for record in records if record[0] in {"pub", "sub"}]
    expected_subkeys = [
        signing_subkeys["current"],
        signing_subkeys["next"],
        *signing_subkeys["historical"],
    ]
    require([record[0] for record in keys] == ["pub"] + ["sub"] * len(expected_subkeys),
            f"{path.name} public key topology does not match reviewed signing subkeys")

    fingerprints: list[tuple[str, str]] = []
    pending_type: str | None = None
    for record in records:
        record_type = record[0]
        if record_type in {"pub", "sub"}:
            pending_type = record_type
        elif record_type == "fpr" and pending_type is not None:
            require(len(record) > 9 and UPPER_FINGERPRINT.fullmatch(record[9]) is not None,
                    f"{path.name} contains an invalid OpenPGP fingerprint")
            fingerprints.append((pending_type, record[9]))
            pending_type = None
    require(fingerprints and fingerprints[0] == ("pub", primary_fingerprint),
            f"{path.name} primary fingerprint does not match the reviewed manifest")
    actual_subkey_fingerprints = [fingerprint for record_type, fingerprint in fingerprints[1:]
                                  if record_type == "sub"]
    require(len(actual_subkey_fingerprints) == len(expected_subkeys)
            and set(actual_subkey_fingerprints) == set(expected_subkeys),
            f"{path.name} subkey fingerprints do not match the reviewed manifest")

    # GnuPG appends uppercase aggregate capabilities from subkeys to the
    # primary record. Lowercase letters describe the packet's own capability.
    primary_capabilities = keys[0][11] if len(keys[0]) > 11 else ""
    require("c" in primary_capabilities and not any(capability in primary_capabilities for capability in "sea"),
            f"{path.name} primary key must be certify-only")
    if family == "rpm":
        _validate_rpm_rsa_key(keys[0], f"{path.name} primary key")
    current_time = int(time.time()) if now is None else now
    minimum_seconds = minimum_valid_days * 86400
    maximum_seconds = maximum_lifetime_days * 86400
    runway_seconds = rotation_begin_days * 86400
    subkey_records = dict(zip(actual_subkey_fingerprints, keys[1:], strict=True))
    for fingerprint, record in subkey_records.items():
        _validate_sign_only(record, f"{path.name} subkey {fingerprint}")
        if family == "rpm":
            _validate_rpm_rsa_key(record, f"{path.name} subkey {fingerprint}")
        created = _key_timestamp(record, 5, f"{path.name} subkey {fingerprint}")
        expires = _key_timestamp(record, 6, f"{path.name} subkey {fingerprint}", optional=True)
        assert created is not None
        require(expires is not None, f"{path.name} subkey {fingerprint} must expire")
        require(expires - created <= maximum_seconds,
                f"{path.name} subkey {fingerprint} lifetime exceeds reviewed policy")

    current = subkey_records[signing_subkeys["current"]]
    current_created = _key_timestamp(current, 5, f"{path.name} current signing subkey")
    current_expires = _key_timestamp(current, 6, f"{path.name} current signing subkey", optional=True)
    assert current_created is not None and current_expires is not None
    require(current[1] not in {"d", "e", "i", "r"} and current_created <= current_time,
            f"{path.name} current signing subkey is not usable")
    require(current_expires - current_time >= minimum_seconds,
            f"{path.name} current signing subkey has less than required validity")

    successor = subkey_records[signing_subkeys["next"]]
    successor_created = _key_timestamp(successor, 5, f"{path.name} next signing subkey")
    successor_expires = _key_timestamp(successor, 6, f"{path.name} next signing subkey", optional=True)
    assert successor_created is not None and successor_expires is not None
    require(successor[1] not in {"d", "e", "r"},
            f"{path.name} next signing subkey is disabled, expired, or revoked")
    require(successor[1] != "i" or successor_created > current_time,
            f"{path.name} next signing subkey is invalid")
    require(successor_expires >= current_expires + runway_seconds,
            f"{path.name} next signing subkey does not extend the rotation runway")

    for fingerprint in signing_subkeys["historical"]:
        record = subkey_records[fingerprint]
        created = _key_timestamp(
            record, 5, f"{path.name} historical subkey {fingerprint}"
        )
        expires = _key_timestamp(record, 6, f"{path.name} historical subkey {fingerprint}", optional=True)
        assert created is not None and expires is not None
        require(record[1] not in {"d", "i"}
                and "D" not in (record[11] if len(record) > 11 else "")
                and created <= current_time,
                f"{path.name} historical signing subkey is not a former usable current")
        require(expires <= current_expires,
                f"{path.name} historical signing subkey expires after the current subkey")


def validate_signing(root: Path) -> dict[str, Any]:
    signing = exact_fields(load_json(root / "manifests/preview-signing.json"), SIGNING_FIELDS,
                           "preview signing manifest")
    require(signing["schema"] == SIGNING_SCHEMA, f"signing schema must be {SIGNING_SCHEMA}")
    require(type(signing["enabled"]) is bool, "signing.enabled must be boolean")
    require(signing["minimum_valid_days"] == 30, "minimum_valid_days must remain 30")
    require(signing["rotation_begin_days"] == 45, "rotation_begin_days must remain 45")
    require(signing["maximum_subkey_lifetime_days"] == 180,
            "maximum_subkey_lifetime_days must remain 180")

    fingerprints: list[str] = []
    certificates: list[tuple[str, Path, str, dict[str, Any]]] = []
    expected = {
        "apt": (
            "native-package-preview-apt-signing",
            "keys/apt-preview.asc",
            "WK_APT_PREVIEW_SECRET_SUBKEY_B64",
            "WK_APT_PREVIEW_PASSPHRASE",
        ),
        "rpm": (
            "native-package-preview-rpm-signing",
            "keys/rpm-preview.asc",
            "WK_RPM_PREVIEW_SECRET_SUBKEY_B64",
            "WK_RPM_PREVIEW_PASSPHRASE",
        ),
    }
    for family, (environment, public_key, secret_env, passphrase_env) in expected.items():
        key = exact_fields(signing[family], KEY_FIELDS, f"signing.{family}")
        require(key["environment"] == environment,
                f"signing.{family}.environment must be {environment}")
        require(key["public_key"] == public_key, f"signing.{family}.public_key must be {public_key}")
        require(key["secret_subkey_env"] == secret_env,
                f"signing.{family}.secret_subkey_env must be {secret_env}")
        require(key["passphrase_env"] == passphrase_env,
                f"signing.{family}.passphrase_env must be {passphrase_env}")
        if signing["enabled"]:
            primary = key["primary_fingerprint"]
            require(isinstance(primary, str) and UPPER_FINGERPRINT.fullmatch(primary),
                    f"signing.{family}.primary_fingerprint must be an uppercase 40-hex fingerprint")
            subkeys = exact_fields(key["signing_subkeys"], SIGNING_SUBKEY_FIELDS,
                                   f"signing.{family}.signing_subkeys")
            for field in ("current", "next"):
                value = subkeys[field]
                require(isinstance(value, str) and UPPER_FINGERPRINT.fullmatch(value),
                        f"signing.{family}.signing_subkeys.{field} must be an uppercase 40-hex fingerprint")
            historical = subkeys["historical"]
            require(isinstance(historical, list),
                    f"signing.{family}.signing_subkeys.historical must be an array")
            require(all(isinstance(value, str) and UPPER_FINGERPRINT.fullmatch(value)
                        for value in historical),
                    f"signing.{family}.signing_subkeys.historical must contain uppercase fingerprints")
            require(len(historical) == len(set(historical)),
                    f"signing.{family}.signing_subkeys.historical must not contain duplicates")
            require(historical == sorted(historical),
                    f"signing.{family}.signing_subkeys.historical must be sorted")
            family_fingerprints = [primary, subkeys["current"], subkeys["next"], *historical]
            require(len(family_fingerprints) == len(set(family_fingerprints)),
                    f"signing.{family} fingerprints must all be distinct")
            fingerprints.extend(family_fingerprints)
            key_path = root / public_key
            try:
                key_mode = key_path.lstat()
            except OSError as error:
                raise ContractError(f"cannot read public key {public_key}: {error}") from error
            require(stat.S_ISREG(key_mode.st_mode) and key_mode.st_nlink == 1,
                    f"{public_key} must be a single-link regular file")
            certificates.append((
                family,
                key_path,
                primary,
                subkeys,
            ))
        else:
            subkeys = exact_fields(key["signing_subkeys"], SIGNING_SUBKEY_FIELDS,
                                   f"signing.{family}.signing_subkeys")
            require(key["primary_fingerprint"] is None
                    and subkeys == {"current": None, "next": None, "historical": []},
                    f"signing.{family} fingerprints must be empty while signing is disabled")

    if signing["enabled"]:
        require(len(set(fingerprints)) == len(fingerprints),
                "APT and RPM signing fingerprints must all be distinct")
        require(len({value[-16:] for value in fingerprints}) == len(fingerprints),
                "APT and RPM signing fingerprints must have globally distinct 16-hex key IDs")
        require(len({value[-8:] for value in fingerprints}) == len(fingerprints),
                "APT and RPM signing fingerprints must have globally distinct 8-hex key IDs")
        expected_key_files = {"README.md", "apt-preview.asc", "rpm-preview.asc"}
    else:
        expected_key_files = {"README.md"}
    actual_key_entries = {path.name: path for path in (root / "keys").iterdir()}
    require(set(actual_key_entries) == expected_key_files,
            f"keys directory entries must be exactly {sorted(expected_key_files)}")
    for name, path in actual_key_entries.items():
        metadata = path.lstat()
        require(stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1,
                f"keys/{name} must be a single-link regular file")
    for family, path, primary_fingerprint, signing_subkeys in certificates:
        validate_public_certificate(
            path,
            primary_fingerprint,
            signing_subkeys,
            family=family,
            minimum_valid_days=signing["minimum_valid_days"],
            rotation_begin_days=signing["rotation_begin_days"],
            maximum_lifetime_days=signing["maximum_subkey_lifetime_days"],
        )
    return signing


def validate_signing_toolchain(root: Path) -> dict[str, Any]:
    toolchain = exact_fields(
        load_json(root / "manifests/signing-toolchain.json"),
        SIGNING_TOOLCHAIN_FIELDS,
        "signing toolchain manifest",
    )
    require(
        toolchain["schema"] == SIGNING_TOOLCHAIN_SCHEMA,
        f"signing toolchain schema must be {SIGNING_TOOLCHAIN_SCHEMA}",
    )
    require(type(toolchain["enabled"]) is bool,
            "signing toolchain.enabled must be boolean")
    require(toolchain["image"] == SIGNING_TOOLCHAIN_IMAGE,
            f"signing toolchain.image must be {SIGNING_TOOLCHAIN_IMAGE}")
    if toolchain["enabled"]:
        require(
            isinstance(toolchain["digest"], str)
            and re.fullmatch(r"sha256:[0-9a-f]{64}", toolchain["digest"]),
            "enabled signing toolchain.digest must be sha256:<64 lowercase hex>",
        )
        require(
            isinstance(toolchain["workflow_sha"], str)
            and LOWER_SHA.fullmatch(toolchain["workflow_sha"]),
            "enabled signing toolchain.workflow_sha must be a lowercase 40-hex commit",
        )
    else:
        require(
            toolchain["digest"] is None and toolchain["workflow_sha"] is None,
            "disabled signing toolchain requires null digest and workflow_sha",
        )
    return toolchain


def validate_toolchain(root: Path) -> dict[str, Any]:
    toolchain = exact_fields(
        load_json(root / "manifests/trusted-toolchain.json"),
        {"schema", "repository", "commit", "files"},
        "trusted toolchain manifest",
    )
    require(toolchain["schema"] == TOOLCHAIN_SCHEMA,
            f"toolchain schema must be {TOOLCHAIN_SCHEMA}")
    require(toolchain["repository"] == SOURCE_REPOSITORY,
            f"toolchain repository must be {SOURCE_REPOSITORY}")
    require(isinstance(toolchain["commit"], str) and LOWER_SHA.fullmatch(toolchain["commit"]),
            "trusted toolchain commit must be a lowercase 40-hex Git commit")
    files = toolchain["files"]
    require(isinstance(files, dict) and set(files) == TRUSTED_TOOL_FILES,
            f"trusted tool files must be exactly {sorted(TRUSTED_TOOL_FILES)}")
    for name, digest in files.items():
        require(isinstance(digest, str) and LOWER_SHA256.fullmatch(digest),
                f"trusted tool digest must be lowercase SHA-256: {name}")
    require(len(set(files.values())) == len(files), "trusted tool digests must be unique")
    return toolchain


def validate_source_read(root: Path) -> dict[str, Any]:
    source_read = exact_fields(
        load_json(root / "manifests/source-read.json"),
        {
            "schema",
            "enabled",
            "environment",
            "app_client_id_secret",
            "app_private_key_secret",
            "owner",
            "repositories",
            "permissions",
        },
        "source-read manifest",
    )
    require(source_read["schema"] == SOURCE_READ_SCHEMA,
            f"source-read schema must be {SOURCE_READ_SCHEMA}")
    require(type(source_read["enabled"]) is bool, "source-read enabled must be boolean")
    require(source_read["environment"] == "native-package-source-read",
            "source-read environment must be native-package-source-read")
    require(source_read["app_client_id_secret"] == "WK_SOURCE_READ_APP_CLIENT_ID",
            "source-read client-id secret name is fixed")
    require(source_read["app_private_key_secret"] == "WK_SOURCE_READ_APP_PRIVATE_KEY",
            "source-read private-key secret name is fixed")
    require(source_read["owner"] == "WuKongIM" and source_read["repositories"] == ["WuKongIM"],
            "source-read GitHub App token must be limited to WuKongIM/WuKongIM")
    permissions = exact_fields(source_read["permissions"], {"contents", "attestations"},
                               "source-read permissions")
    require(permissions == {"contents": "read", "attestations": "read"},
            "source-read GitHub App permissions must remain read-only")
    return source_read


def validate_audit_access(
    root: Path, source_read: dict[str, Any]
) -> dict[str, Any]:
    audit_access = exact_fields(
        load_json(root / "manifests/audit-access.json"),
        AUDIT_ACCESS_FIELDS,
        "audit-access manifest",
    )
    require(
        audit_access["schema"] == AUDIT_ACCESS_SCHEMA,
        f"audit-access schema must be {AUDIT_ACCESS_SCHEMA}",
    )
    require(
        type(audit_access["enabled"]) is bool,
        "audit-access enabled must be boolean",
    )

    reader = exact_fields(
        audit_access["reader"], AUDIT_APP_FIELDS, "audit-access reader"
    )
    writer = exact_fields(
        audit_access["writer"], AUDIT_APP_FIELDS, "audit-access writer"
    )
    for role, value in (("reader", reader), ("writer", writer)):
        require(
            value["owner"] == "WuKongIM" and value["repositories"] == ["packages"],
            f"audit-access {role} App must be limited to WuKongIM/packages",
        )
        require(
            isinstance(value["app_client_id_secret"], str)
            and bool(value["app_client_id_secret"]),
            f"audit-access {role} client-id secret must be a non-empty string",
        )
        require(
            isinstance(value["app_private_key_secret"], str)
            and bool(value["app_private_key_secret"]),
            f"audit-access {role} private-key secret must be a non-empty string",
        )

    require(
        reader["environment"] == "native-package-preview-audit-read",
        "audit-access reader environment must be native-package-preview-audit-read",
    )
    require(
        writer["environment"] == "native-package-preview-audit",
        "audit-access writer environment must be native-package-preview-audit",
    )
    reader_permissions = exact_fields(
        reader["permissions"], {"administration"}, "audit-access reader permissions"
    )
    require(
        reader_permissions == {"administration": "read"},
        "audit-access reader App permissions must be Administration read only",
    )
    writer_permissions = exact_fields(
        writer["permissions"],
        {"administration", "contents"},
        "audit-access writer permissions",
    )
    require(
        writer_permissions == {"administration": "read", "contents": "write"},
        "audit-access writer App permissions must be Administration read and Contents write",
    )

    secret_names = [
        source_read["app_client_id_secret"],
        source_read["app_private_key_secret"],
        reader["app_client_id_secret"],
        reader["app_private_key_secret"],
        writer["app_client_id_secret"],
        writer["app_private_key_secret"],
    ]
    require(
        len(secret_names) == len(set(secret_names)),
        "Source Reader, Audit Reader, and Package Publisher secret names must all be distinct",
    )
    require(
        reader["app_client_id_secret"] == "WK_PACKAGE_AUDIT_READER_APP_CLIENT_ID",
        "audit-access reader client-id secret name is fixed",
    )
    require(
        reader["app_private_key_secret"] == "WK_PACKAGE_AUDIT_READER_APP_PRIVATE_KEY",
        "audit-access reader private-key secret name is fixed",
    )
    require(
        writer["app_client_id_secret"] == "WK_PACKAGE_PUBLISHER_APP_CLIENT_ID",
        "audit-access writer client-id secret name is fixed",
    )
    require(
        writer["app_private_key_secret"] == "WK_PACKAGE_PUBLISHER_APP_PRIVATE_KEY",
        "audit-access writer private-key secret name is fixed",
    )
    return audit_access


def validate_tracked_inputs(root: Path) -> None:
    forbidden_private_markers = (
        b"BEGIN PGP PRIVATE KEY BLOCK",
        b"BEGIN OPENSSH PRIVATE KEY",
        b"BEGIN RSA PRIVATE KEY",
        b"BEGIN EC PRIVATE KEY",
        b"BEGIN DSA PRIVATE KEY",
        b"BEGIN PRIVATE KEY",
    )
    for relative_root in ("keys", "manifests", "site"):
        tree = root / relative_root
        try:
            root_mode = tree.lstat().st_mode
        except OSError as error:
            raise ContractError(f"cannot inspect {relative_root}: {error}") from error
        require(stat.S_ISDIR(root_mode), f"{relative_root} must be a real directory")
        for directory, directories, files in os.walk(tree, followlinks=False):
            for name in directories + files:
                path = Path(directory) / name
                metadata = path.lstat()
                require(not stat.S_ISLNK(metadata.st_mode),
                        f"publication input contains a symbolic link: {path.relative_to(root)}")
                require(stat.S_ISDIR(metadata.st_mode) or stat.S_ISREG(metadata.st_mode),
                        f"publication input contains a special file: {path.relative_to(root)}")
                if stat.S_ISREG(metadata.st_mode):
                    require(metadata.st_nlink == 1,
                            f"publication input contains a hard-linked file: {path.relative_to(root)}")
                    contents = path.read_bytes()
                    require(not any(marker in contents for marker in forbidden_private_markers),
                            f"private key material is forbidden: {path.relative_to(root)}")


def validate_bootstrap_site(root: Path, channels: dict[str, Any], signing: dict[str, Any]) -> None:
    preview = channels["channels"]["preview"]
    retirement = preview["retirement"]
    publication = preview["publication"]
    if not signing["enabled"]:
        require(
            not preview["enabled"]
            and preview["status"] == "signing_not_provisioned"
            and preview["releases"] == [],
            "disabled signing requires a disabled signing_not_provisioned preview with no releases",
        )
        require(
            retirement["phase"] == "none" and publication["operation"] == "none",
            "disabled signing forbids retirement and publication operations",
        )
    elif not preview["enabled"]:
        require(
            preview["status"] == "awaiting_first_release" and preview["releases"] == [],
            "provisioned signing with disabled preview requires awaiting_first_release "
            "and no releases",
        )
        require(
            retirement["phase"] == "none" and publication["operation"] == "none",
            "awaiting_first_release forbids retirement and publication operations",
        )
    else:
        require(
            preview["status"] == "ready" and bool(preview["releases"]),
            "enabled preview requires ready status and at least one release",
        )
        require(
            any(release["state"] == "active" for release in preview["releases"]),
            "enabled preview requires at least one active release",
        )

    site = root / "site"
    files = sorted(path.relative_to(site).as_posix() for path in site.rglob("*") if path.is_file())
    require(files == ["index.html", "status.json"],
            "tracked site must contain only the bootstrap index.html and status.json")
    status_value = exact_fields(load_json(site / "status.json"), {"schema", "apt", "rpm", "reason"},
                                "bootstrap status")
    require(status_value == {
        "schema": "wukongim.native_package_repository_status/v1",
        "apt": False,
        "rpm": False,
        "reason": preview["status"],
    }, "bootstrap status must match the reviewed preview status")
    total = sum((site / relative).stat().st_size for relative in files)
    require(total <= channels["site_limit_bytes"], "bootstrap site exceeds the hard Pages limit")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent.parent,
                        help="repository root (defaults to the script's parent repository)")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    root = args.root.resolve()
    try:
        validate_tracked_inputs(root)
        bootstrap = validate_bootstrap_packages(root)
        channels = validate_channels(root, bootstrap["enabled"])
        signing = validate_signing(root)
        validate_signing_toolchain(root)
        validate_toolchain(root)
        source_read = validate_source_read(root)
        validate_audit_access(root, source_read)
        validate_bootstrap_site(root, channels, signing)
    except ContractError as error:
        print(f"publication control validation failed: {error}", file=sys.stderr)
        return 1
    print("publication control validation passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
