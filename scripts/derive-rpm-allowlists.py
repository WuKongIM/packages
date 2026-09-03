#!/usr/bin/env python3
"""Derive exact RPM signer allowlists from product and bootstrap inventories."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any


INVENTORY_SCHEMA = "wukongim.native_package_payload_inventory/v1"
BOOTSTRAP_INVENTORY_SCHEMA = "wukongim.native_package_bootstrap_inventory/v1"
PACKAGE_ALLOWLIST_SCHEMA = "wukongim/rpm-package-allowlist/v1"
ACTIVE_ALLOWLIST_SCHEMA = "wukongim/rpm-active-allowlist/v1"
RECEIPT_SCHEMA = "wukongim/rpm-allowlist-derivation/v1"
RPM_PREFIX = "rpm/preview/el/9/x86_64/"
RPM_ENTRY_FIELDS = {
    "indexed",
    "new",
    "path",
    "published_sha256",
    "source_sha256",
    "version",
}
INVENTORY_FIELDS = {
    "active_versions",
    "audit_release_id",
    "payloads",
    "retained_versions",
    "schema",
}
BOOTSTRAP_INVENTORY_FIELDS = {"schema", "version", "packages"}
BOOTSTRAP_ENTRY_FIELDS = {
    "name", "version", "architecture", "filename", "repository_path",
    "download_path", "source_sha256", "source_size", "published_sha256",
    "published_size", "new",
}
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
RELEASE_VERSION_RE = re.compile(
    r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$"
)
SAFE_COMPONENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+~-]{0,254}$")
MAX_INVENTORY_BYTES = 4 * 1024 * 1024
MAX_RPM_BYTES = 1024 * 1024 * 1024
READ_BUFFER_BYTES = 1024 * 1024


class DerivationError(ValueError):
    """Raised when inventory cannot safely and exactly derive signer inputs."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise DerivationError(message)


def canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"


def reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in result, f"duplicate JSON key: {key}")
        result[key] = value
    return result


def read_regular_file(
    path: Path,
    label: str,
    *,
    maximum_bytes: int,
    require_nonempty: bool,
) -> tuple[bytes, os.stat_result]:
    try:
        before = path.lstat()
    except OSError as error:
        raise DerivationError(f"cannot inspect {label}") from error
    require(stat.S_ISREG(before.st_mode), f"{label} must be a regular file, not a link")
    require(before.st_nlink == 1, f"{label} must not be hard linked")
    require((not require_nonempty or before.st_size > 0) and before.st_size <= maximum_bytes,
            f"{label} has an invalid size")
    require(hasattr(os, "O_NOFOLLOW"), "platform must support O_NOFOLLOW")
    flags = os.O_RDONLY | os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise DerivationError(f"cannot safely open {label}") from error
    try:
        opened = os.fstat(descriptor)
        require(
            stat.S_ISREG(opened.st_mode)
            and opened.st_nlink == 1
            and (opened.st_dev, opened.st_ino, opened.st_size)
            == (before.st_dev, before.st_ino, before.st_size),
            f"{label} changed while it was opened",
        )
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(READ_BUFFER_BYTES, maximum_bytes + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            require(total <= maximum_bytes, f"{label} exceeds its size limit")
        after = os.fstat(descriptor)
        require(
            total == opened.st_size
            and (after.st_dev, after.st_ino, after.st_size)
            == (opened.st_dev, opened.st_ino, opened.st_size),
            f"{label} changed while it was read",
        )
        return b"".join(chunks), opened
    finally:
        os.close(descriptor)


def digest_regular_rpm(path: Path, label: str) -> tuple[str, int]:
    try:
        before = path.lstat()
    except OSError as error:
        raise DerivationError(f"cannot inspect {label}") from error
    require(stat.S_ISREG(before.st_mode), f"{label} must be a regular file, not a link")
    require(before.st_nlink == 1, f"{label} must not be hard linked")
    require(0 < before.st_size <= MAX_RPM_BYTES, f"{label} has an invalid size")
    flags = os.O_RDONLY | os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise DerivationError(f"cannot safely open {label}") from error
    digest = hashlib.sha256()
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
            chunk = os.read(descriptor, READ_BUFFER_BYTES)
            if not chunk:
                break
            digest.update(chunk)
            total += len(chunk)
        after = os.fstat(descriptor)
        require(
            total == opened.st_size
            and (after.st_dev, after.st_ino, after.st_size)
            == (opened.st_dev, opened.st_ino, opened.st_size),
            f"{label} changed while it was read",
        )
    finally:
        os.close(descriptor)
    return digest.hexdigest(), total


def load_inventory(path: Path) -> dict[str, Any]:
    raw, _ = read_regular_file(
        path,
        "payload inventory",
        maximum_bytes=MAX_INVENTORY_BYTES,
        require_nonempty=True,
    )
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=reject_duplicate_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise DerivationError("payload inventory is not valid UTF-8 JSON") from error
    require(isinstance(value, dict) and set(value) == INVENTORY_FIELDS,
            "payload inventory has missing or unexpected fields")
    require(value["schema"] == INVENTORY_SCHEMA,
            f"payload inventory schema must be {INVENTORY_SCHEMA}")
    require(type(value["audit_release_id"]) is int and value["audit_release_id"] > 0,
            "payload inventory audit_release_id must be positive")
    require(isinstance(value["payloads"], dict) and set(value["payloads"]) == {"apt", "rpm"},
            "payload inventory payloads must contain exactly apt and rpm")
    require(isinstance(value["payloads"]["apt"], list),
            "payload inventory APT payloads must be an array")
    return value


def load_bootstrap_inventory(path: Path) -> dict[str, Any]:
    raw, _ = read_regular_file(
        path,
        "bootstrap inventory",
        maximum_bytes=MAX_INVENTORY_BYTES,
        require_nonempty=True,
    )
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=reject_duplicate_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise DerivationError("bootstrap inventory is not valid UTF-8 JSON") from error
    require(isinstance(value, dict) and set(value) == BOOTSTRAP_INVENTORY_FIELDS,
            "bootstrap inventory has missing or unexpected fields")
    require(value["schema"] == BOOTSTRAP_INVENTORY_SCHEMA,
            f"bootstrap inventory schema must be {BOOTSTRAP_INVENTORY_SCHEMA}")
    version = value["version"]
    require(isinstance(version, str) and RELEASE_VERSION_RE.fullmatch(version) is not None,
            "bootstrap inventory version must be strict release SemVer")
    packages = value["packages"]
    require(isinstance(packages, dict) and set(packages) == {"apt", "rpm"},
            "bootstrap inventory packages must contain exactly apt and rpm")
    specifications = {
        "apt": ("wukongim-archive-keyring", "all", ".deb"),
        "rpm": ("wukongim-release", "noarch", ".rpm"),
    }
    for family in ("apt", "rpm"):
        item = packages[family]
        require(isinstance(item, dict) and set(item) == BOOTSTRAP_ENTRY_FIELDS,
                f"bootstrap {family} entry has missing or unexpected fields")
        name, architecture, suffix = specifications[family]
        filename = (
            f"wukongim-archive-keyring_{version}_all.deb"
            if family == "apt"
            else f"wukongim-release-{version}-1.noarch.rpm"
        )
        repository_path = (
            f"apt/pool/main/w/wukongim/{filename}"
            if family == "apt"
            else f"{RPM_PREFIX}Packages/{filename}"
        )
        require(item["name"] == name and item["version"] == version
                and item["architecture"] == architecture,
                f"bootstrap {family} package identity is invalid")
        require(item["filename"] == filename and item["repository_path"] == repository_path
                and item["download_path"] == f"bootstrap/{filename}"
                and filename.endswith(suffix),
                f"bootstrap {family} package paths are invalid")
        for field in ("source_sha256", "published_sha256"):
            require(isinstance(item[field], str) and SHA256_RE.fullmatch(item[field]) is not None,
                    f"bootstrap {family} {field} is invalid")
        for field in ("source_size", "published_size"):
            require(type(item[field]) is int and item[field] > 0,
                    f"bootstrap {family} {field} must be positive")
        require(type(item["new"]) is bool,
                f"bootstrap {family} new must be boolean")
        if item["new"] or family == "apt":
            require(item["source_sha256"] == item["published_sha256"]
                    and item["source_size"] == item["published_size"],
                    f"bootstrap {family} source and published bytes must match")
    require(packages["apt"]["new"] == packages["rpm"]["new"],
            "bootstrap package new states must match")
    return value


def version_set(value: Any, label: str) -> set[str]:
    require(isinstance(value, list), f"{label} must be an array")
    result: set[str] = set()
    for version in value:
        require(isinstance(version, str) and version != "" and version not in result,
                f"{label} contains an invalid or duplicate version")
        result.add(version)
    return result


def stripped_rpm_path(value: Any, label: str) -> str:
    require(isinstance(value, str) and value.startswith(RPM_PREFIX),
            f"{label} must begin with the exact preview RPM prefix")
    relative_value = value[len(RPM_PREFIX):]
    require(relative_value != "" and "\\" not in relative_value and "\x00" not in relative_value,
            f"{label} is not a canonical relative path")
    relative = PurePosixPath(relative_value)
    require(not relative.is_absolute() and str(relative) == relative_value,
            f"{label} is not a canonical relative path")
    require(
        len(relative.parts) >= 2
        and relative.parts[0] == "Packages"
        and relative.suffix == ".rpm"
        and all(part not in {"", ".", ".."} and SAFE_COMPONENT_RE.fullmatch(part)
                for part in relative.parts),
        f"{label} must identify a safe .rpm below Packages/",
    )
    return relative_value


def repository_file(root: Path, relative: str, label: str) -> Path:
    current = root
    parts = PurePosixPath(relative).parts
    for index, part in enumerate(parts):
        current = current / part
        try:
            metadata = current.lstat()
        except OSError as error:
            raise DerivationError(f"cannot inspect {label}") from error
        if index == len(parts) - 1:
            require(stat.S_ISREG(metadata.st_mode), f"{label} must be a regular file, not a link")
            require(metadata.st_nlink == 1, f"{label} must not be hard linked")
        else:
            require(stat.S_ISDIR(metadata.st_mode), f"{label} path contains a linked or special directory")
    return current


def package_tree_paths(root: Path) -> list[str]:
    packages = root / "Packages"
    try:
        metadata = packages.lstat()
    except OSError as error:
        raise DerivationError("cannot inspect repository Packages directory") from error
    require(stat.S_ISDIR(metadata.st_mode),
            "repository Packages must be a real directory, not a link")
    paths: list[str] = []

    def walk_error(error: OSError) -> None:
        raise DerivationError("cannot completely inspect repository Packages") from error

    for directory, names, files in os.walk(
        packages, topdown=True, followlinks=False, onerror=walk_error
    ):
        directory_path = Path(directory)
        for name in names:
            path = directory_path / name
            require(stat.S_ISDIR(path.lstat().st_mode),
                    "repository Packages contains a linked or special directory")
        for name in files:
            path = directory_path / name
            relative = path.relative_to(root).as_posix()
            file_metadata = path.lstat()
            require(
                stat.S_ISREG(file_metadata.st_mode)
                and file_metadata.st_nlink == 1
                and name.endswith(".rpm"),
                f"repository Packages contains an unsafe or unsupported entry: {relative}",
            )
            stripped_rpm_path(RPM_PREFIX + relative, "repository RPM path")
            paths.append(relative)
    return sorted(paths)


def derive(
    inventory: dict[str, Any],
    bootstrap_inventory: dict[str, Any],
    repository_root: Path,
) -> tuple[dict[str, Any], ...]:
    try:
        root = repository_root.resolve(strict=True)
        original = repository_root.lstat()
    except OSError as error:
        raise DerivationError("cannot inspect repository root") from error
    require(stat.S_ISDIR(original.st_mode) and root.is_dir(),
            "repository root must be a real directory, not a link")

    active_versions = version_set(inventory["active_versions"], "active_versions")
    retained_versions = version_set(inventory["retained_versions"], "retained_versions")
    require(active_versions and active_versions.isdisjoint(retained_versions),
            "active and retained versions must be non-empty/disjoint as applicable")
    rpm_values = inventory["payloads"]["rpm"]
    require(isinstance(rpm_values, list) and rpm_values,
            "payload inventory RPM payloads must be a non-empty array")

    versions: set[str] = set()
    paths: set[str] = set()
    new_packages: list[dict[str, object]] = []
    signed_packages: list[dict[str, object]] = []
    active_paths: list[str] = []
    for index, entry in enumerate(rpm_values):
        require(isinstance(entry, dict) and set(entry) == RPM_ENTRY_FIELDS,
                f"RPM inventory entry {index} has missing or unexpected fields")
        version = entry["version"]
        require(isinstance(version, str) and version != "" and version not in versions,
                f"RPM inventory entry {index} has an invalid or duplicate version")
        versions.add(version)
        relative = stripped_rpm_path(entry["path"], f"RPM inventory entry {index} path")
        require(relative not in paths, f"RPM inventory contains duplicate path: {relative}")
        paths.add(relative)
        for field in ("source_sha256", "published_sha256"):
            require(isinstance(entry[field], str) and SHA256_RE.fullmatch(entry[field]) is not None,
                    f"RPM inventory entry {index} {field} is invalid")
        require(type(entry["indexed"]) is bool and type(entry["new"]) is bool,
                f"RPM inventory entry {index} indexed/new must be boolean")
        require(entry["indexed"] == (version in active_versions),
                f"RPM inventory entry {index} indexed state disagrees with active_versions")
        require((version in active_versions) or (version in retained_versions),
                f"RPM inventory entry {index} version is neither active nor retained")
        require(not entry["new"] or entry["indexed"],
                f"RPM inventory entry {index} marks a retained payload as new")
        if entry["new"]:
            require(entry["source_sha256"] == entry["published_sha256"],
                    f"new RPM inventory entry {index} source/published digests differ")

        path = repository_file(root, relative, f"repository RPM {relative}")
        actual_digest, size = digest_regular_rpm(path, f"repository RPM {relative}")
        require(actual_digest == entry["published_sha256"],
                f"repository RPM digest does not match inventory: {relative}")
        package = {"path": relative, "sha256": actual_digest, "size": size}
        (new_packages if entry["new"] else signed_packages).append(package)
        if entry["indexed"]:
            active_paths.append(relative)

    require(versions == active_versions | retained_versions,
            "RPM inventory versions do not close over active and retained versions")
    bootstrap_rpm = bootstrap_inventory["packages"]["rpm"]
    bootstrap_relative = stripped_rpm_path(
        bootstrap_rpm["repository_path"], "bootstrap RPM repository_path"
    )
    require(bootstrap_relative not in paths,
            f"RPM inventories contain duplicate path: {bootstrap_relative}")
    paths.add(bootstrap_relative)
    bootstrap_path = repository_file(
        root, bootstrap_relative, f"repository bootstrap RPM {bootstrap_relative}"
    )
    bootstrap_digest, bootstrap_size = digest_regular_rpm(
        bootstrap_path, f"repository bootstrap RPM {bootstrap_relative}"
    )
    require(
        bootstrap_digest == bootstrap_rpm["published_sha256"]
        and bootstrap_size == bootstrap_rpm["published_size"],
        "repository bootstrap RPM facts do not match inventory",
    )
    bootstrap_package = {
        "path": bootstrap_relative,
        "sha256": bootstrap_digest,
        "size": bootstrap_size,
    }
    (new_packages if bootstrap_rpm["new"] else signed_packages).append(
        bootstrap_package
    )
    active_paths.append(bootstrap_relative)
    actual_paths = package_tree_paths(root)
    require(sorted(paths) == actual_paths,
            "RPM inventory does not close over the exact repository Packages set")
    new_packages.sort(key=lambda item: str(item["path"]))
    signed_packages.sort(key=lambda item: str(item["path"]))
    active_paths.sort()
    new_output = {"packages": new_packages, "schema": PACKAGE_ALLOWLIST_SCHEMA}
    signed_output = {"packages": signed_packages, "schema": PACKAGE_ALLOWLIST_SCHEMA}
    active_output = {"paths": active_paths, "schema": ACTIVE_ALLOWLIST_SCHEMA}
    receipt = {
        "active_count": len(active_paths),
        "audit_release_id": inventory["audit_release_id"],
        "new_count": len(new_packages),
        "schema": RECEIPT_SCHEMA,
        "signed_count": len(signed_packages),
    }
    return new_output, signed_output, active_output, receipt


def output_identity(path: Path) -> tuple[Path, Path]:
    require(path.name not in {"", ".", ".."} and SAFE_COMPONENT_RE.fullmatch(path.name) is not None,
            "allowlist output filename is unsafe")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    parent = path.parent.resolve(strict=True)
    output = parent / path.name
    require(not os.path.lexists(output), f"allowlist output already exists or is a link: {path.name}")
    return parent, output


def write_outputs_exclusively(outputs: list[tuple[Path, bytes]]) -> None:
    targets: list[tuple[Path, Path, bytes]] = []
    identities: set[str] = set()
    for requested, contents in outputs:
        parent, target = output_identity(requested)
        identity = str(target)
        require(identity not in identities, "allowlist output paths must be distinct")
        identities.add(identity)
        targets.append((parent, target, contents))

    staged: list[tuple[Path, Path, tuple[int, int]]] = []
    published: list[tuple[Path, tuple[int, int]]] = []
    try:
        for parent, target, contents in targets:
            descriptor, temporary_name = tempfile.mkstemp(
                prefix=f".{target.name}.tmp.", dir=parent
            )
            temporary = Path(temporary_name)
            try:
                os.fchmod(descriptor, 0o644)
                view = memoryview(contents)
                while view:
                    written = os.write(descriptor, view)
                    view = view[written:]
                os.fsync(descriptor)
                metadata = os.fstat(descriptor)
                require(metadata.st_size == len(contents),
                        "allowlist output changed while it was staged")
                inode = (metadata.st_dev, metadata.st_ino)
            except BaseException:
                temporary.unlink(missing_ok=True)
                raise
            finally:
                os.close(descriptor)
            staged.append((temporary, target, inode))

        for temporary, target, inode in staged:
            os.link(temporary, target, follow_symlinks=False)
            published.append((target, inode))
            metadata = target.lstat()
            require(stat.S_ISREG(metadata.st_mode)
                    and (metadata.st_dev, metadata.st_ino) == inode,
                    "allowlist output changed while it was published")
            temporary.unlink()
        for target, _ in published:
            require(target.lstat().st_nlink == 1,
                    "published allowlist output must be single-link")
    except OSError as error:
        for target, inode in published:
            try:
                metadata = target.lstat()
                if (metadata.st_dev, metadata.st_ino) == inode:
                    target.unlink()
            except OSError:
                pass
        for temporary, _, _ in staged:
            temporary.unlink(missing_ok=True)
        raise DerivationError("cannot publish allowlist outputs exclusively") from error
    except BaseException:
        for target, inode in published:
            try:
                metadata = target.lstat()
                if (metadata.st_dev, metadata.st_ino) == inode:
                    target.unlink()
            except OSError:
                pass
        for temporary, _, _ in staged:
            try:
                temporary.unlink()
            except OSError:
                pass
        raise


def run(args: argparse.Namespace) -> dict[str, object]:
    inventory = load_inventory(args.inventory)
    bootstrap_inventory = load_bootstrap_inventory(args.bootstrap_inventory)
    new_output, signed_output, active_output, receipt = derive(
        inventory, bootstrap_inventory, args.repository_root
    )
    write_outputs_exclusively([
        (args.new_output, canonical_json(new_output)),
        (args.signed_output, canonical_json(signed_output)),
        (args.active_output, canonical_json(active_output)),
    ])
    return receipt


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory", required=True, type=Path)
    parser.add_argument("--bootstrap-inventory", required=True, type=Path)
    parser.add_argument("--repository-root", required=True, type=Path)
    parser.add_argument("--new-output", required=True, type=Path)
    parser.add_argument("--signed-output", required=True, type=Path)
    parser.add_argument("--active-output", required=True, type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        receipt = run(args)
    except DerivationError as error:
        print(f"RPM allowlist derivation failed: {error}", file=sys.stderr)
        return 1
    except OSError:
        print("RPM allowlist derivation failed: safe filesystem operation failed", file=sys.stderr)
        return 1
    print(canonical_json(receipt).decode("utf-8"), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
