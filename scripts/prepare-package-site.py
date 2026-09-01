#!/usr/bin/env python3
"""Prepare unsigned active indexes while preserving reviewed retired payload bytes."""

from __future__ import annotations

import argparse
import ctypes
import errno
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any


PLAN_SCHEMA = "wukongim.native_package_publication_plan/v1"
SNAPSHOT_SCHEMA = "wukongim.native_package_snapshot/v3"
INVENTORY_SCHEMA = "wukongim.native_package_payload_inventory/v1"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
FINGERPRINT_RE = re.compile(r"^[0-9A-F]{40}$")
OCI_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
ASSET_RE = re.compile(r"^wukongim_[0-9A-Za-z.-]+_linux_amd64\.(deb|rpm)$")
ENTRY_FIELDS = {"version", "path", "source_sha256", "published_sha256", "indexed"}
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
SIGNING_TOOLCHAIN_IMAGE = "ghcr.io/wukongim/native-package-signing-toolchain"


class PreparationError(ValueError):
    """Raised when publication payload preparation violates reviewed inventory."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise PreparationError(message)


def reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in result, f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicate_pairs)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise PreparationError(f"cannot read {path.name}: {error}") from error


def exact_object(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    require(isinstance(value, dict), f"{label} must be an object")
    require(set(value) == fields, f"{label} fields must be exactly {sorted(fields)}")
    return value


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def checked_file(path: Path, label: str, expected: str | None = None) -> Path:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise PreparationError(f"cannot inspect {label}") from error
    require(stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1,
            f"{label} must be a single-link regular file")
    if expected is not None:
        require(SHA256_RE.fullmatch(expected) is not None, f"{label} expected digest is invalid")
        require(digest(path) == expected, f"{label} SHA-256 does not match reviewed inventory")
    return path


def file_facts(path: Path, label: str) -> dict[str, Any]:
    checked_file(path, label)
    metadata = path.stat()
    require(metadata.st_size > 0, f"{label} must not be empty")
    return {"sha256": digest(path), "size": metadata.st_size}


def safe_relative(value: Any, label: str) -> PurePosixPath:
    require(isinstance(value, str) and value != "" and "\\" not in value and "\0" not in value,
            f"{label} must be a path")
    path = PurePosixPath(value)
    require(not path.is_absolute() and path.as_posix() == value
            and ".." not in path.parts and "." not in path.parts,
            f"{label} is unsafe")
    return path


def validate_sha256(value: Any, label: str) -> str:
    require(isinstance(value, str) and SHA256_RE.fullmatch(value) is not None,
            f"{label} must be a lowercase SHA-256")
    return value


def validate_fingerprint(value: Any, label: str) -> str:
    require(isinstance(value, str) and FINGERPRINT_RE.fullmatch(value) is not None,
            f"{label} must be an uppercase 40-hex fingerprint")
    return value


def validate_base_public_keys(snapshot: dict[str, Any], site: Path) -> None:
    families = exact_object(snapshot["public_keys"], {"apt", "rpm"},
                            "base snapshot public_keys")
    fingerprints: list[str] = []
    for family in ("apt", "rpm"):
        item = exact_object(families[family], PUBLIC_KEY_FIELDS,
                            f"base snapshot {family} public key")
        expected_path = f"keys/{family}-preview.asc"
        require(item["path"] == expected_path,
                f"base snapshot {family} public key path is invalid")
        expected = {
            "sha256": validate_sha256(item["sha256"],
                                       f"base snapshot {family} public key sha256"),
            "size": item["size"],
        }
        require(type(expected["size"]) is int and expected["size"] > 0,
                f"base snapshot {family} public key size must be positive")
        require(file_facts(site / expected_path, f"base {family} public certificate") == expected,
                f"base {family} public certificate differs from its snapshot inventory")
        current = validate_fingerprint(
            item["current_signing_subkey_fingerprint"],
            f"base snapshot {family} current signing-subkey fingerprint",
        )
        successor = validate_fingerprint(
            item["next_signing_subkey_fingerprint"],
            f"base snapshot {family} next signing-subkey fingerprint",
        )
        primary = validate_fingerprint(
            item["primary_fingerprint"], f"base snapshot {family} primary fingerprint"
        )
        historical = item["historical_signing_subkey_fingerprints"]
        require(isinstance(historical, list)
                and all(isinstance(value, str) for value in historical)
                and historical == sorted(set(historical)),
                f"base snapshot {family} historical fingerprints must be unique and sorted")
        for value in historical:
            validate_fingerprint(value, f"base snapshot {family} historical fingerprint")
        fingerprints.extend([primary, current, successor, *historical])
    require(len(fingerprints) == len(set(fingerprints)),
            "base snapshot signing fingerprints must all be distinct")
    require(len({value[-16:] for value in fingerprints}) == len(fingerprints),
            "base snapshot signing fingerprints must have distinct 16-hex key IDs")
    require(len({value[-8:] for value in fingerprints}) == len(fingerprints),
            "base snapshot signing fingerprints must have distinct 8-hex key IDs")


def validate_base_source_attestations(snapshot: dict[str, Any], root: Path) -> None:
    value = snapshot["source_attestations"]
    evidence_root = root / "audit/source-attestations"
    if value is None:
        require(not os.path.lexists(evidence_root),
                "base source attestation directory is forbidden when inventory is null")
        return
    source = exact_object(value, SOURCE_ATTESTATION_FIELDS,
                          "base snapshot source_attestations")
    summary_sha = validate_sha256(
        source["summary_sha256"], "base source attestation summary_sha256"
    )
    files = source["files"]
    require(isinstance(files, list) and len(files) == 8,
            "base source attestation inventory must contain eight files")
    paths: list[str] = []
    expected_names: set[str] = set()
    summary_matches = 0
    for index, raw in enumerate(files):
        artifact = exact_object(raw, ARTIFACT_FIELDS,
                                f"base source attestation artifact {index}")
        path = safe_relative(artifact["path"],
                             f"base source attestation artifact {index}.path")
        require(path.parts[:2] == ("audit", "source-attestations")
                and len(path.parts) == 3,
                "base source attestation artifact path is invalid")
        expected = {
            "sha256": validate_sha256(
                artifact["sha256"], f"base source attestation artifact {index}.sha256"
            ),
            "size": artifact["size"],
        }
        require(type(expected["size"]) is int and expected["size"] > 0,
                f"base source attestation artifact {index}.size must be positive")
        require(file_facts(root.joinpath(*path.parts),
                           f"base source attestation {path.name}") == expected,
                f"base source attestation {path.name} differs from its snapshot inventory")
        paths.append(path.as_posix())
        expected_names.add(path.name)
        if path.name == "source-attestations.json":
            require(expected["sha256"] == summary_sha,
                    "base source attestation summary digest is inconsistent")
            summary_matches += 1
    require(paths == sorted(set(paths)),
            "base source attestation paths must be unique and sorted")
    require(summary_matches == 1,
            "base source attestation inventory must contain the canonical summary")
    try:
        actual_names = {entry.name for entry in evidence_root.iterdir()}
    except OSError as error:
        raise PreparationError("cannot enumerate base source attestations") from error
    require(actual_names == expected_names,
            "base source attestation directory differs from its exact inventory")


def validate_base_toolchain(snapshot: dict[str, Any], root: Path) -> None:
    item = exact_object(snapshot["toolchain"], TOOLCHAIN_FIELDS,
                        "base snapshot toolchain")
    require(item["image"] == SIGNING_TOOLCHAIN_IMAGE,
            "base snapshot toolchain image is invalid")
    require(isinstance(item["digest"], str)
            and OCI_DIGEST_RE.fullmatch(item["digest"]) is not None,
            "base snapshot toolchain digest is invalid")
    require(isinstance(item["workflow_sha"], str)
            and SHA_RE.fullmatch(item["workflow_sha"]) is not None,
            "base snapshot toolchain workflow_sha is invalid")
    expected = {
        "sha256": validate_sha256(item["manifest_sha256"],
                                   "base snapshot toolchain manifest_sha256"),
        "size": item["manifest_size"],
    }
    require(type(expected["size"]) is int and expected["size"] > 0,
            "base snapshot toolchain manifest_size must be positive")
    require(file_facts(root / "audit/signing-toolchain.json",
                       "base signing toolchain manifest") == expected,
            "base signing toolchain manifest differs from its snapshot inventory")


def load_base(base_root: Path | None, expected_id: int | None) -> tuple[dict[str, Any] | None, Path | None]:
    if expected_id is None:
        require(base_root is None, "base root is forbidden without a reviewed base snapshot")
        return None, None
    require(base_root is not None, "base root is required by the publication plan")
    try:
        base_metadata = base_root.lstat()
    except OSError as error:
        raise PreparationError("cannot inspect base root") from error
    require(stat.S_ISDIR(base_metadata.st_mode),
            "base root must be a non-symbolic-link directory")
    root = base_root.resolve(strict=True)
    snapshot = exact_object(
        load_json(root / "audit/snapshot.json"), SNAPSHOT_FIELDS, "base snapshot"
    )
    require(snapshot["schema"] == SNAPSHOT_SCHEMA,
            f"base snapshot schema must be {SNAPSHOT_SCHEMA}")
    require(snapshot["audit_release_id"] == expected_id,
            "base snapshot Release id does not match the plan")
    require(isinstance(snapshot["control_sha"], str)
            and SHA_RE.fullmatch(snapshot["control_sha"]) is not None,
            "base snapshot control_sha is invalid")
    require(isinstance(snapshot["releases"], list),
            "base snapshot releases must be an array")
    exact_object(snapshot["retirement"], {"phase", "version", "not_before"},
                 "base snapshot retirement")
    exact_object(snapshot["payloads"], {"apt", "rpm"},
                 "base snapshot payload inventory")
    site = root / "site"
    try:
        site_metadata = site.lstat()
    except OSError as error:
        raise PreparationError("cannot inspect base site") from error
    require(stat.S_ISDIR(site_metadata.st_mode), "base site must be a real directory")
    validate_base_public_keys(snapshot, site)
    validate_base_source_attestations(snapshot, root)
    validate_base_toolchain(snapshot, root)
    return snapshot, site


def indexed_entries(snapshot: dict[str, Any] | None, family: str) -> dict[str, dict[str, Any]]:
    if snapshot is None:
        return {}
    values = snapshot["payloads"].get(family)
    require(isinstance(values, list), f"base {family} payloads must be an array")
    result: dict[str, dict[str, Any]] = {}
    for index, raw in enumerate(values):
        require(isinstance(raw, dict) and set(raw) == ENTRY_FIELDS,
                f"base {family} payload {index} has unexpected fields")
        version = raw["version"]
        require(isinstance(version, str) and version not in result,
                f"base {family} payload version is invalid or duplicated")
        safe_relative(raw["path"], f"base {family} payload path")
        for field in ("source_sha256", "published_sha256"):
            require(isinstance(raw[field], str) and SHA256_RE.fullmatch(raw[field]),
                    f"base {family} payload {field} is invalid")
        require(type(raw["indexed"]) is bool, f"base {family} payload indexed must be boolean")
        result[version] = raw
    return result


def find_new_asset(source_root: Path, release: dict[str, Any], suffix: str) -> Path:
    release_id = release["source_release_id"]
    require(type(release_id) is int and release_id > 0, "source_release_id must be positive")
    directory = source_root / str(release_id)
    require(directory.is_dir() and not directory.is_symlink(),
            f"source assets are missing for Release {release_id}")
    matches = []
    for path in directory.iterdir():
        if path.name.endswith(suffix):
            matches.append(path)
    require(len(matches) == 1, f"source Release {release_id} must contain exactly one {suffix} payload")
    require(ASSET_RE.fullmatch(matches[0].name) is not None, "source package asset name is invalid")
    return matches[0]


def copy_payload(source: Path, destination: Path, expected: str, label: str) -> None:
    checked_file(source, label, expected)
    destination.parent.mkdir(parents=True, exist_ok=True)
    require(not destination.exists(), f"duplicate prepared payload path: {destination.name}")
    shutil.copyfile(source, destination)
    destination.chmod(0o644)
    require(digest(destination) == expected, f"prepared {label} changed during copy")


def _remove_owned_file(path: Path, identity: tuple[int, int]) -> None:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return
    except OSError as error:
        raise PreparationError("cannot inspect inventory output during rollback") from error
    require(
        stat.S_ISREG(metadata.st_mode) and (metadata.st_dev, metadata.st_ino) == identity,
        "inventory output changed before rollback",
    )
    try:
        path.unlink()
    except OSError as error:
        raise PreparationError("cannot roll back inventory output") from error


def _remove_owned_tree(path: Path, identity: tuple[int, int]) -> None:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return
    except OSError as error:
        raise PreparationError("cannot inspect repository output during rollback") from error
    require(
        stat.S_ISDIR(metadata.st_mode) and (metadata.st_dev, metadata.st_ino) == identity,
        "repository output changed before rollback",
    )
    try:
        shutil.rmtree(path)
    except OSError as error:
        raise PreparationError("cannot roll back repository output") from error


def write_inventory_exclusive(path: Path, data: bytes) -> tuple[int, int]:
    """Create the final inventory once without following a raced link."""

    require(hasattr(os, "O_NOFOLLOW"), "platform must support O_NOFOLLOW")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, 0o644)
    except OSError as error:
        raise PreparationError(
            "inventory output appeared or could not be created safely"
        ) from error
    opened = os.fstat(descriptor)
    identity = (opened.st_dev, opened.st_ino)
    try:
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            require(written > 0, "inventory output write made no progress")
            view = view[written:]
        os.fsync(descriptor)
        os.fchmod(descriptor, 0o644)
    except BaseException as error:
        os.close(descriptor)
        _remove_owned_file(path, identity)
        if isinstance(error, OSError):
            raise PreparationError("cannot write inventory output safely") from error
        raise
    os.close(descriptor)
    return identity


def rename_directory_exclusive(source: Path, destination: Path) -> None:
    """Atomically publish a directory without replacing a raced destination."""

    library = ctypes.CDLL(None, use_errno=True)
    if sys.platform == "darwin":
        try:
            rename = library.renamex_np
        except AttributeError as error:
            raise PreparationError("platform lacks exclusive directory rename") from error
        rename.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint]
        rename.restype = ctypes.c_int
        result = rename(os.fsencode(source), os.fsencode(destination), 0x00000004)
    elif sys.platform.startswith("linux"):
        try:
            rename = library.renameat2
        except AttributeError as error:
            raise PreparationError("platform lacks exclusive directory rename") from error
        rename.argtypes = [
            ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint,
        ]
        rename.restype = ctypes.c_int
        result = rename(-100, os.fsencode(source), -100, os.fsencode(destination), 1)
    else:
        raise PreparationError("platform lacks exclusive directory rename")
    if result == 0:
        return
    error_number = ctypes.get_errno()
    if error_number in {errno.EEXIST, errno.ENOTEMPTY}:
        raise PreparationError("output appeared during preparation")
    raise PreparationError(
        f"cannot publish repository output: {os.strerror(error_number)}"
    )


def prepare(args: argparse.Namespace) -> dict[str, Any]:
    channels = load_json(args.channels)
    plan = load_json(args.plan)
    require(isinstance(channels, dict) and channels.get("schema") == "wukongim.native_package_channels/v3",
            "channels manifest must use schema v3")
    require(isinstance(plan, dict) and plan.get("schema") == PLAN_SCHEMA,
            f"publication plan schema must be {PLAN_SCHEMA}")
    audit_id = plan.get("audit_release_id")
    require(type(audit_id) is int and audit_id > 0, "publication plan has no audit Release")
    base_id = plan.get("base_audit_release_id")
    base_snapshot, base_site = load_base(args.base_root, base_id)
    preview = channels.get("channels", {}).get("preview", {})
    releases = preview.get("releases")
    require(isinstance(releases, list), "preview releases must be an array")
    release_by_version = {item.get("version"): item for item in releases if isinstance(item, dict)}
    require(len(release_by_version) == len(releases), "preview release versions must be unique")
    active = plan.get("active_versions")
    retained = plan.get("retained_versions")
    new_versions = plan.get("new_versions")
    require(isinstance(active, list) and active, "publication plan must retain active versions")
    require(isinstance(retained, list) and len(retained) <= 1, "retained version plan is invalid")
    require(isinstance(new_versions, list), "new version plan is invalid")
    require(set(active) | set(retained) == set(release_by_version),
            "publication plan versions do not equal reviewed releases")

    base_entries = {
        "apt": indexed_entries(base_snapshot, "apt"),
        "rpm": indexed_entries(base_snapshot, "rpm"),
    }
    require(not os.path.lexists(args.output), "output must not already exist or be a link")
    require(not os.path.lexists(args.inventory),
            "inventory output must not already exist or be a link")
    output_absolute = Path(os.path.abspath(args.output))
    inventory_absolute = Path(os.path.abspath(args.inventory))
    require(output_absolute != inventory_absolute,
            "repository and inventory outputs must differ")
    require(not inventory_absolute.is_relative_to(output_absolute),
            "inventory output must not be inside repository output")
    checked_file(args.builder, "trusted repository builder")
    try:
        source_metadata = args.source_assets.lstat()
    except OSError as error:
        raise PreparationError("cannot inspect source assets root") from error
    require(stat.S_ISDIR(source_metadata.st_mode),
            "source assets root must be a non-symbolic-link directory")
    source_root = args.source_assets.resolve(strict=True)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.inventory.parent.mkdir(parents=True, exist_ok=True)
    for parent, label in (
        (args.output.parent, "output parent"),
        (args.inventory.parent, "inventory output parent"),
    ):
        require(stat.S_ISDIR(parent.lstat().st_mode), f"{label} must be a real directory")
    output = args.output.parent.resolve(strict=True) / args.output.name
    inventory_output = args.inventory.parent.resolve(strict=True) / args.inventory.name
    require(output != inventory_output, "repository and inventory outputs must differ")
    require(not os.path.lexists(output), "output must not already exist or be a link")
    require(not os.path.lexists(inventory_output),
            "inventory output must not already exist or be a link")

    output_identity: tuple[int, int] | None = None
    inventory_identity: tuple[int, int] | None = None
    try:
        with tempfile.TemporaryDirectory(prefix="wk-package-prepare-", dir=output.parent) as temporary:
            stage = Path(temporary)
            active_packages = stage / "active-packages"
            active_packages.mkdir(mode=0o755)
            prepared: dict[str, list[dict[str, Any]]] = {"apt": [], "rpm": []}

            for version in active + retained:
                release = release_by_version[version]
                is_new = version in new_versions
                is_indexed = version in active
                for family, suffix, digest_field in (
                    ("apt", ".deb", "deb_sha256"),
                    ("rpm", ".rpm", "rpm_sha256"),
                ):
                    expected_source = release[digest_field]
                    require(isinstance(expected_source, str) and SHA256_RE.fullmatch(expected_source),
                            f"reviewed {family} source digest is invalid for {version}")
                    if is_new:
                        source = find_new_asset(source_root, release, suffix)
                        published = expected_source
                        filename = source.name
                    else:
                        entry = base_entries[family].get(version)
                        require(entry is not None, f"base snapshot lacks {family} payload for {version}")
                        require(entry["source_sha256"] == expected_source,
                                f"base {family} source digest changed for {version}")
                        assert base_site is not None
                        relative = safe_relative(entry["path"], f"base {family} path")
                        source = base_site.joinpath(*relative.parts)
                        published = entry["published_sha256"]
                        filename = relative.name

                    if is_indexed:
                        destination = active_packages / filename
                    else:
                        destination = stage / "retained" / family / filename
                    copy_payload(source, destination, published, f"{family} payload {version}")
                    repository_path = (
                        f"apt/pool/main/w/wukongim/{filename}"
                        if family == "apt"
                        else f"rpm/preview/el/9/x86_64/Packages/{filename}"
                    )
                    prepared[family].append({
                        "version": version,
                        "path": repository_path,
                        "source_sha256": expected_source,
                        "published_sha256": published,
                        "indexed": is_indexed,
                        "new": is_new,
                    })

            repository = stage / "repository"
            command = [
                str(args.builder.resolve()),
                "--packages-dir", str(active_packages),
                "--output", str(repository),
                "--apt-suite", "preview",
                "--apt-architecture", "amd64",
                "--rpm-channel", "preview",
                "--rpm-basearch", "x86_64",
            ]
            result = subprocess.run(command, check=False, capture_output=True, text=True)
            require(result.returncode == 0, "trusted repository builder failed")
            for family in ("apt", "rpm"):
                for entry in prepared[family]:
                    destination = repository.joinpath(*PurePosixPath(entry["path"]).parts)
                    if not entry["indexed"]:
                        retained_source = (
                            stage / "retained" / family / PurePosixPath(entry["path"]).name
                        )
                        copy_payload(retained_source, destination, entry["published_sha256"],
                                     f"retained {family} payload {entry['version']}")
                    else:
                        checked_file(destination, f"built {family} payload",
                                     entry["published_sha256"])

            inventory = {
                "schema": INVENTORY_SCHEMA,
                "audit_release_id": audit_id,
                "active_versions": active,
                "retained_versions": retained,
                "payloads": {
                    family: sorted(prepared[family], key=lambda item: item["version"])
                    for family in ("apt", "rpm")
                },
            }
            inventory_raw = (
                json.dumps(inventory, sort_keys=True, separators=(",", ":")) + "\n"
            ).encode("utf-8")
            inventory_identity = write_inventory_exclusive(inventory_output, inventory_raw)
            require(not os.path.lexists(output), "output appeared during preparation")
            repository_metadata = repository.lstat()
            require(stat.S_ISDIR(repository_metadata.st_mode),
                    "trusted repository builder did not create a real repository directory")
            rename_directory_exclusive(repository, output)
            output_identity = (repository_metadata.st_dev, repository_metadata.st_ino)
    except BaseException:
        if output_identity is not None:
            _remove_owned_tree(output, output_identity)
        if inventory_identity is not None:
            _remove_owned_file(inventory_output, inventory_identity)
        raise
    return inventory


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--channels", required=True, type=Path)
    parser.add_argument("--plan", required=True, type=Path)
    parser.add_argument("--base-root", type=Path)
    parser.add_argument("--source-assets", required=True, type=Path)
    parser.add_argument("--builder", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--inventory", required=True, type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        inventory = prepare(args)
    except PreparationError as error:
        print(f"package-site preparation failed: {error}", file=sys.stderr)
        return 1
    json.dump(inventory, sys.stdout, sort_keys=True, separators=(",", ":"))
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
