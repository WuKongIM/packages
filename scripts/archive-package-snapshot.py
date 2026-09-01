#!/usr/bin/env python3
"""Create and safely inspect or extract a canonical package-site snapshot.

The archive is deliberately a small, strict subset of POSIX USTAR.  Only
regular files and explicitly recorded directories are accepted.  This keeps
the publication audit artifact deterministic and avoids delegating path and
link handling to a permissive general-purpose tar extractor.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import stat
import sys
from pathlib import Path
from typing import Any, BinaryIO, NamedTuple


ARCHIVE_SCHEMA = "wukongim/package-site-archive/v1"
BLOCK_SIZE = 512
DEFAULT_MAX_MEMBERS = 100_000
# The deployed site is capped separately at 750 MiB.  A complete audit
# snapshot also contains its bounded audit/snapshot.json control record.
DEFAULT_MAX_TOTAL_SIZE = 800 * 1024 * 1024
COPY_CHUNK_SIZE = 1024 * 1024


class ArchiveError(RuntimeError):
    """A package-site snapshot violated a canonical archive invariant."""


class _SourceMember(NamedTuple):
    name: str
    kind: str
    size: int
    path: Path
    device: int
    inode: int


class _ArchiveMember(NamedTuple):
    name: str
    kind: str
    size: int
    data_offset: int


def _positive_limit(value: int, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise ArchiveError(f"{label} must be a positive integer")
    return value


def _octal(value: int, length: int, label: str) -> bytes:
    if value < 0:
        raise ArchiveError(f"{label} must not be negative")
    digits = format(value, "o").encode("ascii")
    if len(digits) > length - 1:
        raise ArchiveError(f"{label} does not fit in a USTAR numeric field")
    return digits.rjust(length - 1, b"0") + b"\0"


def _split_ustar_name(name: str) -> tuple[bytes, bytes]:
    try:
        encoded = name.encode("utf-8")
    except UnicodeEncodeError as error:
        raise ArchiveError(f"archive path is not valid UTF-8: {name!r}") from error
    if len(encoded) <= 100:
        return encoded, b""
    slash_positions = [index for index, byte in enumerate(encoded) if byte == ord("/")]
    for index in reversed(slash_positions):
        prefix = encoded[:index]
        suffix = encoded[index + 1 :]
        if prefix and suffix and len(prefix) <= 155 and len(suffix) <= 100:
            return suffix, prefix
    raise ArchiveError(f"archive path does not fit in USTAR name fields: {name}")


def _header(name: str, kind: str, size: int) -> bytes:
    name_field, prefix_field = _split_ustar_name(name)
    mode = 0o755 if kind == "directory" else 0o644
    header = bytearray(BLOCK_SIZE)
    header[0 : len(name_field)] = name_field
    header[100:108] = _octal(mode, 8, "mode")
    header[108:116] = _octal(0, 8, "uid")
    header[116:124] = _octal(0, 8, "gid")
    header[124:136] = _octal(size, 12, "size")
    header[136:148] = _octal(0, 12, "mtime")
    header[148:156] = b"        "
    header[156:157] = b"5" if kind == "directory" else b"0"
    header[257:263] = b"ustar\0"
    header[263:265] = b"00"
    header[329:337] = _octal(0, 8, "device major")
    header[337:345] = _octal(0, 8, "device minor")
    header[345 : 345 + len(prefix_field)] = prefix_field
    checksum = sum(header)
    checksum_digits = format(checksum, "06o").encode("ascii")
    if len(checksum_digits) != 6:
        raise ArchiveError("USTAR header checksum overflow")
    header[148:156] = checksum_digits + b"\0 "
    return bytes(header)


def _validate_relative_name(name: str, *, directory: bool) -> str:
    if not name or name.startswith("/") or "\\" in name or "\0" in name:
        raise ArchiveError(f"unsafe archive path: {name!r}")
    if directory:
        if not name.endswith("/"):
            raise ArchiveError(f"directory path must end with '/': {name!r}")
        normalized = name[:-1]
    else:
        if name.endswith("/"):
            raise ArchiveError(f"regular-file path must not end with '/': {name!r}")
        normalized = name
    parts = normalized.split("/")
    if not normalized or any(part in {"", ".", ".."} for part in parts):
        raise ArchiveError(f"unsafe archive path: {name!r}")
    return normalized


def _collect_source_members(
    source_dir: Path, max_members: int, max_total_size: int
) -> list[_SourceMember]:
    try:
        root_stat = source_dir.lstat()
    except OSError as error:
        raise ArchiveError(f"cannot inspect source directory: {error}") from error
    if stat.S_ISLNK(root_stat.st_mode) or not stat.S_ISDIR(root_stat.st_mode):
        raise ArchiveError("source directory must be a real directory")

    members: list[_SourceMember] = []
    seen: set[str] = set()
    total_size = 0

    def walk(directory: Path, relative: str) -> None:
        nonlocal total_size
        try:
            entries = list(os.scandir(directory))
        except OSError as error:
            raise ArchiveError(f"cannot scan source directory {directory}: {error}") from error
        entries.sort(key=lambda entry: entry.name.encode("utf-8", "strict"))
        for entry in entries:
            name = f"{relative}/{entry.name}" if relative else entry.name
            try:
                entry_stat = entry.stat(follow_symlinks=False)
            except OSError as error:
                raise ArchiveError(f"cannot inspect source member {name}: {error}") from error
            mode = entry_stat.st_mode
            if stat.S_ISLNK(mode):
                raise ArchiveError(f"source member must not be a symbolic link: {name}")
            if stat.S_ISDIR(mode):
                archive_name = f"{name}/"
                _validate_relative_name(archive_name, directory=True)
                kind = "directory"
                size = 0
            elif stat.S_ISREG(mode):
                _validate_relative_name(name, directory=False)
                if entry_stat.st_nlink != 1:
                    raise ArchiveError(f"source member must not be hard-linked: {name}")
                archive_name = name
                kind = "file"
                size = entry_stat.st_size
                if size < 0:
                    raise ArchiveError(f"source member has a negative size: {name}")
                total_size += size
                if total_size > max_total_size:
                    raise ArchiveError("source files exceed the total-size limit")
            else:
                raise ArchiveError(f"source member has a special file type: {name}")
            if archive_name in seen:
                raise ArchiveError(f"source contains a duplicate archive path: {archive_name}")
            seen.add(archive_name)
            members.append(
                _SourceMember(
                    name=archive_name,
                    kind=kind,
                    size=size,
                    path=Path(entry.path),
                    device=entry_stat.st_dev,
                    inode=entry_stat.st_ino,
                )
            )
            if len(members) > max_members:
                raise ArchiveError("source contains more members than the member-count limit")
            if kind == "directory":
                walk(Path(entry.path), name)

    try:
        walk(source_dir, "")
    except UnicodeEncodeError as error:
        raise ArchiveError("source member name is not valid UTF-8") from error
    members.sort(key=lambda member: member.name.encode("utf-8"))
    return members


def _write_file_payload(output: BinaryIO, member: _SourceMember) -> None:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(member.path, flags)
    except OSError as error:
        raise ArchiveError(f"cannot open source file {member.name}: {error}") from error
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_dev != member.device
            or before.st_ino != member.inode
            or before.st_size != member.size
        ):
            raise ArchiveError(f"source file changed while archiving: {member.name}")
        remaining = member.size
        with os.fdopen(descriptor, "rb", closefd=False) as source:
            while remaining:
                chunk = source.read(min(COPY_CHUNK_SIZE, remaining))
                if not chunk:
                    raise ArchiveError(f"source file was truncated while archiving: {member.name}")
                output.write(chunk)
                remaining -= len(chunk)
            if source.read(1):
                raise ArchiveError(f"source file grew while archiving: {member.name}")
        after = os.fstat(descriptor)
        if (
            after.st_dev != before.st_dev
            or after.st_ino != before.st_ino
            or after.st_size != before.st_size
            or after.st_mtime_ns != before.st_mtime_ns
        ):
            raise ArchiveError(f"source file changed while archiving: {member.name}")
    finally:
        os.close(descriptor)


def create_snapshot(
    *,
    source_dir: Path,
    archive_path: Path,
    max_members: int = DEFAULT_MAX_MEMBERS,
    max_total_size: int = DEFAULT_MAX_TOTAL_SIZE,
) -> dict[str, Any]:
    """Create a new deterministic USTAR snapshot and return its receipt."""

    max_members = _positive_limit(max_members, "member-count limit")
    max_total_size = _positive_limit(max_total_size, "total-size limit")
    source_dir = Path(source_dir)
    archive_path = Path(archive_path)
    source_absolute = source_dir.absolute()
    archive_absolute = archive_path.absolute()
    try:
        archive_absolute.relative_to(source_absolute)
    except ValueError:
        pass
    else:
        raise ArchiveError("archive output must not be inside the source directory")
    if os.path.lexists(archive_path):
        raise ArchiveError("archive output must not already exist")
    try:
        parent_stat = archive_path.parent.lstat()
    except OSError as error:
        raise ArchiveError(f"cannot inspect archive output directory: {error}") from error
    if stat.S_ISLNK(parent_stat.st_mode) or not stat.S_ISDIR(parent_stat.st_mode):
        raise ArchiveError("archive output parent must be a real directory")

    members = _collect_source_members(source_dir, max_members, max_total_size)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(archive_path, flags, 0o600)
    except OSError as error:
        raise ArchiveError(f"cannot create archive output: {error}") from error
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as output:
            for member in members:
                if member.kind == "directory":
                    current = member.path.lstat()
                    if (
                        not stat.S_ISDIR(current.st_mode)
                        or current.st_dev != member.device
                        or current.st_ino != member.inode
                    ):
                        raise ArchiveError(
                            f"source directory changed while archiving: {member.name}"
                        )
                output.write(_header(member.name, member.kind, member.size))
                if member.kind == "file":
                    _write_file_payload(output, member)
                    padding = (-member.size) % BLOCK_SIZE
                    if padding:
                        output.write(b"\0" * padding)
            output.write(b"\0" * (2 * BLOCK_SIZE))
            output.flush()
            os.fsync(descriptor)
        os.fchmod(descriptor, 0o644)
    except Exception:
        os.close(descriptor)
        archive_path.unlink(missing_ok=True)
        raise
    else:
        os.close(descriptor)
    try:
        return inspect_snapshot(
            archive_path=archive_path,
            max_members=max_members,
            max_total_size=max_total_size,
        )
    except Exception:
        archive_path.unlink(missing_ok=True)
        raise


def _field_text(field: bytes, label: str) -> bytes:
    if b"\0" in field:
        value, padding = field.split(b"\0", 1)
        if any(padding):
            raise ArchiveError(f"{label} has non-zero bytes after its terminator")
        return value
    return field


def _parse_octal(field: bytes, label: str) -> int:
    if not field.endswith(b"\0") or any(byte not in b"01234567" for byte in field[:-1]):
        raise ArchiveError(f"{label} is not canonical USTAR octal")
    return int(field[:-1], 8)


def _read_exact(stream: BinaryIO, length: int, label: str) -> bytes:
    data = stream.read(length)
    if len(data) != length:
        raise ArchiveError(f"archive is truncated while reading {label}")
    return data


def _parse_header(block: bytes) -> tuple[str, str, int]:
    if block[148:156][6:] != b"\0 " or any(
        byte not in b"01234567" for byte in block[148:154]
    ):
        raise ArchiveError("header checksum field is not canonical USTAR")
    expected_checksum = int(block[148:154], 8)
    checksum_block = bytearray(block)
    checksum_block[148:156] = b"        "
    if sum(checksum_block) != expected_checksum:
        raise ArchiveError("archive header checksum mismatch")
    if block[257:263] != b"ustar\0" or block[263:265] != b"00":
        raise ArchiveError("archive member is not canonical POSIX USTAR")
    typeflag = block[156:157]
    if typeflag not in {b"0", b"5"}:
        raise ArchiveError("archive contains a link, special, PAX, or GNU member")
    kind = "directory" if typeflag == b"5" else "file"
    expected_mode = 0o755 if kind == "directory" else 0o644
    if _parse_octal(block[100:108], "mode") != expected_mode:
        raise ArchiveError(f"{kind} mode is not canonical")
    if _parse_octal(block[108:116], "uid") != 0:
        raise ArchiveError("archive uid must be zero")
    if _parse_octal(block[116:124], "gid") != 0:
        raise ArchiveError("archive gid must be zero")
    size = _parse_octal(block[124:136], "size")
    if _parse_octal(block[136:148], "mtime") != 0:
        raise ArchiveError("archive mtime must be zero")
    if any(block[157:257]):
        raise ArchiveError("archive link name must be empty")
    if any(block[265:329]):
        raise ArchiveError("archive owner names must be empty")
    if _parse_octal(block[329:337], "device major") != 0:
        raise ArchiveError("archive device major must be zero")
    if _parse_octal(block[337:345], "device minor") != 0:
        raise ArchiveError("archive device minor must be zero")
    if any(block[500:512]):
        raise ArchiveError("archive header padding must be zero")
    try:
        name_part = _field_text(block[0:100], "name").decode("utf-8", "strict")
        prefix_part = _field_text(block[345:500], "prefix").decode("utf-8", "strict")
    except UnicodeDecodeError as error:
        raise ArchiveError("archive member path must be valid UTF-8") from error
    if not name_part:
        raise ArchiveError("archive member name must not be empty")
    name = f"{prefix_part}/{name_part}" if prefix_part else name_part
    normalized = _validate_relative_name(name, directory=kind == "directory")
    canonical_name, canonical_prefix = _split_ustar_name(name)
    if (
        block[0:100] != canonical_name.ljust(100, b"\0")
        or block[345:500] != canonical_prefix.ljust(155, b"\0")
    ):
        raise ArchiveError(f"archive path fields are not canonical: {normalized}")
    if kind == "directory" and size != 0:
        raise ArchiveError(f"archive directory has a non-zero size: {name}")
    return name, kind, size


def _open_regular_readonly(path: Path) -> tuple[int, os.stat_result]:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
        metadata = os.fstat(descriptor)
    except OSError as error:
        raise ArchiveError(f"cannot open archive: {error}") from error
    if not stat.S_ISREG(metadata.st_mode):
        os.close(descriptor)
        raise ArchiveError("archive must be a regular file")
    return descriptor, metadata


def _scan_snapshot(
    archive_path: Path, max_members: int, max_total_size: int
) -> tuple[dict[str, Any], list[_ArchiveMember], os.stat_result]:
    descriptor, initial_stat = _open_regular_readonly(archive_path)
    digest = hashlib.sha256()
    members: list[_ArchiveMember] = []
    seen: dict[str, str] = {}
    prior_sort_key: bytes | None = None
    total_size = 0
    consumed = 0
    try:
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            while True:
                block = _read_exact(stream, BLOCK_SIZE, "member header")
                digest.update(block)
                consumed += BLOCK_SIZE
                if block == b"\0" * BLOCK_SIZE:
                    second_zero = _read_exact(stream, BLOCK_SIZE, "end-of-archive marker")
                    digest.update(second_zero)
                    consumed += BLOCK_SIZE
                    if second_zero != b"\0" * BLOCK_SIZE:
                        raise ArchiveError("archive has only one zero end marker")
                    if stream.read(1):
                        raise ArchiveError("archive contains trailing bytes after its end marker")
                    break
                name, kind, size = _parse_header(block)
                normalized = name[:-1] if kind == "directory" else name
                sort_key = name.encode("utf-8")
                if prior_sort_key is not None and sort_key <= prior_sort_key:
                    raise ArchiveError("archive members are not in strict bytewise path order")
                prior_sort_key = sort_key
                if normalized in seen:
                    raise ArchiveError(f"archive contains a duplicate path: {normalized}")
                parts = normalized.split("/")
                for index in range(1, len(parts)):
                    parent = "/".join(parts[:index])
                    if seen.get(parent) != "directory":
                        raise ArchiveError(
                            f"archive member parent is missing or not a directory: {name}"
                        )
                seen[normalized] = kind
                members.append(
                    _ArchiveMember(
                        name=name,
                        kind=kind,
                        size=size,
                        data_offset=stream.tell(),
                    )
                )
                if len(members) > max_members:
                    raise ArchiveError("archive exceeds the member-count limit")
                if kind == "file":
                    total_size += size
                    if total_size > max_total_size:
                        raise ArchiveError("archive exceeds the total-size limit")
                remaining = size
                while remaining:
                    chunk = _read_exact(
                        stream, min(COPY_CHUNK_SIZE, remaining), f"payload for {name}"
                    )
                    digest.update(chunk)
                    consumed += len(chunk)
                    remaining -= len(chunk)
                padding_size = (-size) % BLOCK_SIZE
                if padding_size:
                    padding = _read_exact(stream, padding_size, f"padding for {name}")
                    digest.update(padding)
                    consumed += padding_size
                    if any(padding):
                        raise ArchiveError(f"archive member padding is not zero: {name}")
        final_stat = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if (
        initial_stat.st_dev != final_stat.st_dev
        or initial_stat.st_ino != final_stat.st_ino
        or initial_stat.st_size != final_stat.st_size
        or initial_stat.st_mtime_ns != final_stat.st_mtime_ns
        or consumed != initial_stat.st_size
    ):
        raise ArchiveError("archive changed while it was being inspected")
    summary = {
        "schema": ARCHIVE_SCHEMA,
        "archive": archive_path.name,
        "size": consumed,
        "sha256": digest.hexdigest(),
        "member_count": len(members),
        "total_file_size": total_size,
        "members": [
            {"name": member.name, "type": member.kind, "size": member.size}
            for member in members
        ],
    }
    return summary, members, final_stat


def inspect_snapshot(
    *,
    archive_path: Path,
    max_members: int = DEFAULT_MAX_MEMBERS,
    max_total_size: int = DEFAULT_MAX_TOTAL_SIZE,
) -> dict[str, Any]:
    """Validate a canonical snapshot without extracting it."""

    max_members = _positive_limit(max_members, "member-count limit")
    max_total_size = _positive_limit(max_total_size, "total-size limit")
    summary, _, _ = _scan_snapshot(Path(archive_path), max_members, max_total_size)
    return summary


def _empty_real_directory(path: Path) -> tuple[bool, bool]:
    """Prepare an output directory and return (created, usable)."""

    if os.path.lexists(path):
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            return False, False
        return False, not any(path.iterdir())
    path.mkdir(mode=0o700, parents=False)
    return True, True


def _remove_output_children(output_dir: Path) -> None:
    for child in output_dir.iterdir():
        if child.is_dir() and not child.is_symlink():
            shutil.rmtree(child)
        else:
            child.unlink(missing_ok=True)


def _write_all(descriptor: int, data: bytes, label: str) -> None:
    offset = 0
    while offset < len(data):
        try:
            written = os.write(descriptor, data[offset:])
        except OSError as error:
            raise ArchiveError(f"cannot write extracted file {label}: {error}") from error
        if written <= 0:
            raise ArchiveError(f"cannot make progress writing extracted file {label}")
        offset += written


def _open_directory_chain(root_descriptor: int, parts: list[str]) -> int:
    descriptor = os.dup(root_descriptor)
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        for part in parts:
            child = os.open(part, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def extract_snapshot(
    *,
    archive_path: Path,
    output_dir: Path,
    max_members: int = DEFAULT_MAX_MEMBERS,
    max_total_size: int = DEFAULT_MAX_TOTAL_SIZE,
) -> dict[str, Any]:
    """Validate and safely extract a canonical snapshot into an empty directory."""

    max_members = _positive_limit(max_members, "member-count limit")
    max_total_size = _positive_limit(max_total_size, "total-size limit")
    archive_path = Path(archive_path)
    output_dir = Path(output_dir)
    summary, members, scanned_stat = _scan_snapshot(
        archive_path, max_members, max_total_size
    )
    try:
        created_output, usable = _empty_real_directory(output_dir)
    except OSError as error:
        raise ArchiveError(f"cannot prepare extraction directory: {error}") from error
    if not usable:
        raise ArchiveError("extraction directory must not exist or must be an empty real directory")

    descriptor = -1
    output_root_descriptor = -1
    try:
        descriptor, opened_stat = _open_regular_readonly(archive_path)
        if (
            opened_stat.st_dev != scanned_stat.st_dev
            or opened_stat.st_ino != scanned_stat.st_ino
            or opened_stat.st_size != scanned_stat.st_size
            or opened_stat.st_mtime_ns != scanned_stat.st_mtime_ns
        ):
            raise ArchiveError("archive changed before extraction")
        output_flags = os.O_RDONLY
        if hasattr(os, "O_DIRECTORY"):
            output_flags |= os.O_DIRECTORY
        if hasattr(os, "O_NOFOLLOW"):
            output_flags |= os.O_NOFOLLOW
        output_root_descriptor = os.open(output_dir, output_flags)
        for member in members:
            normalized = member.name[:-1] if member.kind == "directory" else member.name
            parts = normalized.split("/")
            parent_descriptor = _open_directory_chain(
                output_root_descriptor, parts[:-1]
            )
            try:
                if member.kind == "directory":
                    os.mkdir(parts[-1], mode=0o755, dir_fd=parent_descriptor)
                    directory_descriptor = _open_directory_chain(
                        parent_descriptor, [parts[-1]]
                    )
                    try:
                        os.fchmod(directory_descriptor, 0o755)
                    finally:
                        os.close(directory_descriptor)
                    continue
                flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
                if hasattr(os, "O_NOFOLLOW"):
                    flags |= os.O_NOFOLLOW
                output_descriptor = os.open(
                    parts[-1], flags, 0o600, dir_fd=parent_descriptor
                )
                try:
                    os.lseek(descriptor, member.data_offset, os.SEEK_SET)
                    remaining = member.size
                    while remaining:
                        chunk = os.read(descriptor, min(COPY_CHUNK_SIZE, remaining))
                        if not chunk:
                            raise ArchiveError(
                                f"archive was truncated during extraction: {member.name}"
                            )
                        _write_all(output_descriptor, chunk, member.name)
                        remaining -= len(chunk)
                    os.fchmod(output_descriptor, 0o644)
                finally:
                    os.close(output_descriptor)
            finally:
                os.close(parent_descriptor)
        final_stat = os.fstat(descriptor)
        if (
            final_stat.st_dev != scanned_stat.st_dev
            or final_stat.st_ino != scanned_stat.st_ino
            or final_stat.st_size != scanned_stat.st_size
            or final_stat.st_mtime_ns != scanned_stat.st_mtime_ns
        ):
            raise ArchiveError("archive changed during extraction")
    except Exception:
        if descriptor >= 0:
            os.close(descriptor)
        if output_root_descriptor >= 0:
            os.close(output_root_descriptor)
        if created_output:
            shutil.rmtree(output_dir, ignore_errors=True)
        else:
            _remove_output_children(output_dir)
        raise
    else:
        os.close(descriptor)
        os.close(output_root_descriptor)
    return summary


def _write_receipt(path: Path, receipt: dict[str, Any]) -> None:
    if os.path.lexists(path):
        raise ArchiveError("snapshot receipt output must not already exist")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, 0o644)
    except OSError as error:
        raise ArchiveError(f"cannot create snapshot receipt: {error}") from error
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            json.dump(receipt, output, sort_keys=True, separators=(",", ":"))
            output.write("\n")
    except Exception as error:
        path.unlink(missing_ok=True)
        raise ArchiveError(f"cannot write snapshot receipt: {error}") from error


def _add_limits(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--max-members", type=int, default=DEFAULT_MAX_MEMBERS)
    parser.add_argument("--max-total-size", type=int, default=DEFAULT_MAX_TOTAL_SIZE)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Create, inspect, or safely extract a canonical package-site USTAR snapshot."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    create = subparsers.add_parser("create")
    create.add_argument("--source-dir", required=True, type=Path)
    create.add_argument("--archive", required=True, type=Path)
    create.add_argument("--receipt-output", type=Path)
    _add_limits(create)

    inspect = subparsers.add_parser("inspect")
    inspect.add_argument("--archive", required=True, type=Path)
    _add_limits(inspect)

    extract = subparsers.add_parser("extract")
    extract.add_argument("--archive", required=True, type=Path)
    extract.add_argument("--output-dir", required=True, type=Path)
    _add_limits(extract)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "create":
            if args.receipt_output is not None and os.path.lexists(args.receipt_output):
                raise ArchiveError("snapshot receipt output must not already exist")
            receipt = create_snapshot(
                source_dir=args.source_dir,
                archive_path=args.archive,
                max_members=args.max_members,
                max_total_size=args.max_total_size,
            )
            if args.receipt_output is not None:
                try:
                    _write_receipt(args.receipt_output, receipt)
                except Exception:
                    args.archive.unlink(missing_ok=True)
                    raise
        elif args.command == "inspect":
            receipt = inspect_snapshot(
                archive_path=args.archive,
                max_members=args.max_members,
                max_total_size=args.max_total_size,
            )
        else:
            receipt = extract_snapshot(
                archive_path=args.archive,
                output_dir=args.output_dir,
                max_members=args.max_members,
                max_total_size=args.max_total_size,
            )
    except (ArchiveError, OSError) as error:
        print(f"package snapshot operation failed: {error}", file=sys.stderr)
        return 1
    json.dump(receipt, sys.stdout, sort_keys=True, separators=(",", ":"))
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
