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
from pathlib import Path
from typing import Any


CHANNELS_SCHEMA = "wukongim.native_package_channels/v2"
SIGNING_SCHEMA = "wukongim.native_package_signing/v1"
TOOLCHAIN_SCHEMA = "wukongim.native_package_toolchain/v1"
SOURCE_READ_SCHEMA = "wukongim.native_package_source_read/v1"
SOURCE_REPOSITORY = "WuKongIM/WuKongIM"
SITE_LIMIT_BYTES = 750 * 1024 * 1024
SITE_WARNING_BYTES = 600 * 1024 * 1024
MAX_ONLINE_VERSIONS = 4
SIGNING_ENVIRONMENT = "native-package-preview-signing"

SEMVER_PRERELEASE = re.compile(
    r"^(?:0|[1-9][0-9]*)\."
    r"(?:0|[1-9][0-9]*)\."
    r"(?:0|[1-9][0-9]*)-"
    r"(?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)"
    r"(?:\.(?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*))*$"
)
LOWER_SHA = re.compile(r"^[0-9a-f]{40}$")
LOWER_SHA256 = re.compile(r"^[0-9a-f]{64}$")
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
PREVIEW_FIELDS = {"enabled", "status", "releases", "retirement"}
STABLE_FIELDS = {"enabled", "status", "releases"}
RETIREMENT_FIELDS = {"phase", "version", "not_before"}
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
    "environment",
    "minimum_valid_days",
    "rotation_begin_days",
    "maximum_subkey_lifetime_days",
    "apt",
    "rpm",
}
KEY_FIELDS = {
    "public_key",
    "primary_fingerprint",
    "signing_subkey_fingerprint",
    "secret_subkey_env",
    "passphrase_env",
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


def validate_channels(root: Path) -> dict[str, Any]:
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

    require(type(stable["enabled"]) is bool and stable["enabled"] is False,
            "stable publishing must remain disabled on GitHub Pages")
    require(stable["status"] == "object_storage_required",
            "stable.status must remain object_storage_required")
    require(stable["releases"] == [], "stable releases must remain empty on GitHub Pages")
    return channels


def validate_public_certificate(
    path: Path, primary_fingerprint: str, signing_subkey_fingerprint: str
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
    require([record[0] for record in keys] == ["pub", "sub"],
            f"{path.name} must contain exactly one public primary and one public subkey")

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
    require(fingerprints == [
        ("pub", primary_fingerprint),
        ("sub", signing_subkey_fingerprint),
    ], f"{path.name} fingerprints do not match the reviewed manifest")

    # GnuPG appends uppercase aggregate capabilities from subkeys to the
    # primary record. Lowercase letters describe the packet's own capability.
    primary_capabilities = keys[0][11] if len(keys[0]) > 11 else ""
    subkey_capabilities = keys[1][11] if len(keys[1]) > 11 else ""
    require("c" in primary_capabilities and not any(capability in primary_capabilities for capability in "sea"),
            f"{path.name} primary key must be certify-only")
    require("s" in subkey_capabilities and not any(capability in subkey_capabilities for capability in "cea"),
            f"{path.name} reviewed subkey must be sign-only")


def validate_signing(root: Path) -> dict[str, Any]:
    signing = exact_fields(load_json(root / "manifests/preview-signing.json"), SIGNING_FIELDS,
                           "preview signing manifest")
    require(signing["schema"] == SIGNING_SCHEMA, f"signing schema must be {SIGNING_SCHEMA}")
    require(type(signing["enabled"]) is bool, "signing.enabled must be boolean")
    require(signing["environment"] == SIGNING_ENVIRONMENT,
            f"signing.environment must be {SIGNING_ENVIRONMENT}")
    require(signing["minimum_valid_days"] == 30, "minimum_valid_days must remain 30")
    require(signing["rotation_begin_days"] == 45, "rotation_begin_days must remain 45")
    require(signing["maximum_subkey_lifetime_days"] == 180,
            "maximum_subkey_lifetime_days must remain 180")

    fingerprints: list[str] = []
    certificates: list[tuple[Path, str, str]] = []
    expected = {
        "apt": (
            "keys/apt-preview.asc",
            "WK_APT_PREVIEW_SECRET_SUBKEY_B64",
            "WK_APT_PREVIEW_PASSPHRASE",
        ),
        "rpm": (
            "keys/rpm-preview.asc",
            "WK_RPM_PREVIEW_SECRET_SUBKEY_B64",
            "WK_RPM_PREVIEW_PASSPHRASE",
        ),
    }
    for family, (public_key, secret_env, passphrase_env) in expected.items():
        key = exact_fields(signing[family], KEY_FIELDS, f"signing.{family}")
        require(key["public_key"] == public_key, f"signing.{family}.public_key must be {public_key}")
        require(key["secret_subkey_env"] == secret_env,
                f"signing.{family}.secret_subkey_env must be {secret_env}")
        require(key["passphrase_env"] == passphrase_env,
                f"signing.{family}.passphrase_env must be {passphrase_env}")
        if signing["enabled"]:
            for field in ("primary_fingerprint", "signing_subkey_fingerprint"):
                value = key[field]
                require(isinstance(value, str) and UPPER_FINGERPRINT.fullmatch(value),
                        f"signing.{family}.{field} must be an uppercase 40-hex fingerprint")
                fingerprints.append(value)
            key_path = root / public_key
            try:
                key_mode = key_path.lstat()
            except OSError as error:
                raise ContractError(f"cannot read public key {public_key}: {error}") from error
            require(stat.S_ISREG(key_mode.st_mode) and key_mode.st_nlink == 1,
                    f"{public_key} must be a single-link regular file")
            certificates.append((
                key_path,
                key["primary_fingerprint"],
                key["signing_subkey_fingerprint"],
            ))
        else:
            require(key["primary_fingerprint"] is None and key["signing_subkey_fingerprint"] is None,
                    f"signing.{family} fingerprints must be null while signing is disabled")

    if signing["enabled"]:
        require(len(set(fingerprints)) == 4,
                "APT and RPM primary and signing-subkey fingerprints must all be distinct")
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
    for path, primary_fingerprint, signing_subkey_fingerprint in certificates:
        validate_public_certificate(path, primary_fingerprint, signing_subkey_fingerprint)
    return signing


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
        "reason": "signing_not_provisioned",
    }, "bootstrap status must remain signing_not_provisioned")
    total = sum((site / relative).stat().st_size for relative in files)
    require(total <= channels["site_limit_bytes"], "bootstrap site exceeds the hard Pages limit")

    preview = channels["channels"]["preview"]
    if signing["enabled"]:
        require(preview["enabled"] and preview["status"] == "ready" and preview["releases"],
                "enabled signing requires an enabled, ready preview channel with a release")
    else:
        require(not preview["enabled"] and preview["status"] == "signing_not_provisioned",
                "disabled signing requires a disabled signing_not_provisioned preview channel")


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
        channels = validate_channels(root)
        signing = validate_signing(root)
        validate_toolchain(root)
        validate_source_read(root)
        validate_bootstrap_site(root, channels, signing)
    except ContractError as error:
        print(f"publication control validation failed: {error}", file=sys.stderr)
        return 1
    print("publication control validation passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
