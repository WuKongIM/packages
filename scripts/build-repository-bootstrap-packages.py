#!/usr/bin/env python3
"""Build deterministic, data-only APT and RPM repository bootstrap packages."""

from __future__ import annotations

import argparse
import base64
import binascii
import ctypes
import errno
import gzip
import hashlib
import io
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path
from typing import Any


MANIFEST_SCHEMA = "wukongim.native_package_bootstrap/v1"
INVENTORY_SCHEMA = "wukongim.native_package_bootstrap_inventory/v1"
MANIFEST_FIELDS = {"schema", "enabled", "version"}
RELEASE_VERSION_RE = re.compile(
    r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$"
)
SOURCE_DATE_EPOCH = 946684800  # 2000-01-01T00:00:00Z
APT_NAME = "wukongim-archive-keyring"
RPM_NAME = "wukongim-release"
APT_KEYRING_PATH = "usr/share/keyrings/wukongim-archive-keyring.pgp"
APT_SOURCE_PATH = "etc/apt/sources.list.d/wukongim-preview.sources"
RPM_KEY_PATH = "etc/pki/rpm-gpg/RPM-GPG-KEY-wukongim-preview"
RPM_REPO_PATH = "etc/yum.repos.d/wukongim-preview.repo"
MAX_INPUT_BYTES = 4 * 1024 * 1024
MAX_TOOL_OUTPUT_BYTES = 1024 * 1024
ARMOR_BEGIN = "-----BEGIN PGP PUBLIC KEY BLOCK-----"
ARMOR_END = "-----END PGP PUBLIC KEY BLOCK-----"
ARMOR_HEADER_RE = re.compile(r"^[A-Za-z0-9-]+: [\x20-\x7e]+$")

APT_SOURCE = b"""Types: deb
URIs: https://packages.githubim.com/apt
Suites: preview
Components: main
Architectures: amd64
Signed-By: /usr/share/keyrings/wukongim-archive-keyring.pgp
Enabled: yes
"""

RPM_REPOSITORY = b"""[wukongim-preview]
name=WuKongIM preview
baseurl=https://packages.githubim.com/rpm/preview/el/9/x86_64
enabled=1
includepkgs=wukongim,wukongim-release
gpgcheck=1
repo_gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-wukongim-preview
sslverify=1
metadata_expire=0
skip_if_unavailable=0
"""

RPM_SPEC_TEMPLATE = """Name: wukongim-release
Version: @VERSION@
Release: 1
Summary: WuKongIM preview repository configuration and signing certificate
License: Apache-2.0
URL: https://github.com/WuKongIM/WuKongIM
Source0: RPM-GPG-KEY-wukongim-preview
Source1: wukongim-preview.repo
BuildArch: noarch
AutoReqProv: no

%description
Installs the WuKongIM preview RPM repository configuration and its dedicated
public signing certificate. Package and repository-metadata signature checks
remain enabled.

%prep

%build

%install
rm -rf %{buildroot}
install -D -p -m 0644 %{SOURCE0} %{buildroot}/etc/pki/rpm-gpg/RPM-GPG-KEY-wukongim-preview
install -D -p -m 0644 %{SOURCE1} %{buildroot}/etc/yum.repos.d/wukongim-preview.repo
touch -h -d "@${SOURCE_DATE_EPOCH}" \
  %{buildroot}/etc/pki/rpm-gpg/RPM-GPG-KEY-wukongim-preview \
  %{buildroot}/etc/yum.repos.d/wukongim-preview.repo

%files
%defattr(-,root,root,-)
/etc/pki/rpm-gpg/RPM-GPG-KEY-wukongim-preview
%config(noreplace) /etc/yum.repos.d/wukongim-preview.repo
"""


class BootstrapBuildError(RuntimeError):
    """A bootstrap build input, tool, or package violated the contract."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise BootstrapBuildError(message)


def canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"


def reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in result, f"duplicate JSON key: {key}")
        result[key] = value
    return result


def checked_regular_file(path: Path, label: str) -> bytes:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise BootstrapBuildError(f"cannot inspect {label}: {error}") from error
    require(
        stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1,
        f"{label} must be a single-link regular file",
    )
    require(0 < metadata.st_size <= MAX_INPUT_BYTES, f"{label} size is invalid")
    try:
        data = path.read_bytes()
    except OSError as error:
        raise BootstrapBuildError(f"cannot read {label}: {error}") from error
    require(len(data) == metadata.st_size, f"{label} changed while it was read")
    after = path.stat()
    require(
        (after.st_dev, after.st_ino, after.st_size)
        == (metadata.st_dev, metadata.st_ino, metadata.st_size),
        f"{label} changed while it was read",
    )
    return data


def load_manifest(path: Path) -> dict[str, Any]:
    raw = checked_regular_file(path, "bootstrap manifest")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=reject_duplicate_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise BootstrapBuildError(f"cannot parse bootstrap manifest: {error}") from error
    require(isinstance(value, dict), "bootstrap manifest must be an object")
    require(
        set(value) == MANIFEST_FIELDS,
        f"bootstrap manifest fields must be exactly {sorted(MANIFEST_FIELDS)}",
    )
    require(value["schema"] == MANIFEST_SCHEMA, f"bootstrap manifest schema must be {MANIFEST_SCHEMA}")
    require(value["enabled"] is True, "bootstrap manifest must be enabled")
    require(
        isinstance(value["version"], str)
        and RELEASE_VERSION_RE.fullmatch(value["version"]) is not None,
        "bootstrap manifest version must be strict release SemVer",
    )
    return value


def _crc24(data: bytes) -> int:
    value = 0xB704CE
    for byte in data:
        value ^= byte << 16
        for _ in range(8):
            value <<= 1
            if value & 0x1000000:
                value ^= 0x1864CFB
    return value & 0xFFFFFF


def dearmor_public_certificate(data: bytes, label: str) -> bytes:
    require(b"PGP PRIVATE KEY" not in data, f"{label} must not contain a private key")
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError as error:
        raise BootstrapBuildError(f"{label} must be an ASCII-armored public certificate") from error
    require("\r" not in text and text.endswith("\n"), f"{label} must use canonical LF text")
    lines = text.splitlines()
    require(lines and lines[0] == ARMOR_BEGIN and lines[-1] == ARMOR_END,
            f"{label} is not one public-key armor block")
    require(lines.count(ARMOR_BEGIN) == 1 and lines.count(ARMOR_END) == 1,
            f"{label} must contain exactly one public-key armor block")
    try:
        separator = lines.index("", 1)
    except ValueError as error:
        raise BootstrapBuildError(f"{label} armor headers have no separator") from error
    for header in lines[1:separator]:
        require(ARMOR_HEADER_RE.fullmatch(header) is not None,
                f"{label} contains an invalid armor header")
    encoded = lines[separator + 1 : -1]
    require(encoded, f"{label} armor body is empty")
    checksum: str | None = None
    if encoded[-1].startswith("="):
        checksum = encoded.pop()[1:]
    require(encoded and all(line and not line.startswith("=") for line in encoded),
            f"{label} armor body is malformed")
    try:
        packets = base64.b64decode("".join(encoded), validate=True)
    except (ValueError, binascii.Error) as error:
        raise BootstrapBuildError(f"{label} armor body is invalid base64") from error
    require(packets, f"{label} contains no OpenPGP packets")
    if checksum is not None:
        try:
            checksum_bytes = base64.b64decode(checksum, validate=True)
        except (ValueError, binascii.Error) as error:
            raise BootstrapBuildError(f"{label} armor checksum is invalid") from error
        require(len(checksum_bytes) == 3, f"{label} armor checksum length is invalid")
        require(int.from_bytes(checksum_bytes, "big") == _crc24(packets),
                f"{label} armor checksum does not match")
    first = packets[0]
    require(first & 0x80 != 0, f"{label} does not start with an OpenPGP packet")
    packet_tag = first & 0x3F if first & 0x40 else (first >> 2) & 0x0F
    require(packet_tag == 6, f"{label} does not start with a public-key packet")
    return packets


def _tar_info(name: str, *, directory: bool, size: int = 0) -> tarfile.TarInfo:
    item = tarfile.TarInfo(name)
    item.type = tarfile.DIRTYPE if directory else tarfile.REGTYPE
    item.mode = 0o755 if directory else 0o644
    item.uid = 0
    item.gid = 0
    item.uname = "root"
    item.gname = "root"
    item.mtime = SOURCE_DATE_EPOCH
    item.size = 0 if directory else size
    return item


def _tar_gzip(files: list[tuple[str, bytes]], directories: list[str]) -> bytes:
    archive = io.BytesIO()
    with tarfile.open(fileobj=archive, mode="w", format=tarfile.USTAR_FORMAT) as output:
        for name in directories:
            output.addfile(_tar_info(name, directory=True))
        for name, data in files:
            output.addfile(_tar_info(name, directory=False, size=len(data)), io.BytesIO(data))
    compressed = io.BytesIO()
    with gzip.GzipFile(
        filename="", mode="wb", compresslevel=9, fileobj=compressed, mtime=SOURCE_DATE_EPOCH
    ) as output:
        output.write(archive.getvalue())
    return compressed.getvalue()


def _ar_member(name: str, data: bytes) -> bytes:
    require(len(name) <= 15 and "/" not in name, f"invalid ar member name: {name}")
    header = (
        f"{name + '/':<16}{SOURCE_DATE_EPOCH:<12}{0:<6}{0:<6}{format(0o100644, 'o'):<8}"
        f"{len(data):<10}`\n"
    ).encode("ascii")
    require(len(header) == 60, "internal ar header length is invalid")
    return header + data + (b"\n" if len(data) % 2 else b"")


def _deb_control(version: str, installed_size: int) -> bytes:
    return (
        "Package: wukongim-archive-keyring\n"
        f"Version: {version}\n"
        "Section: misc\n"
        "Priority: optional\n"
        "Architecture: all\n"
        "Maintainer: WuKongIM Team <support@wukongim.com>\n"
        f"Installed-Size: {installed_size}\n"
        "Homepage: https://github.com/WuKongIM/WuKongIM\n"
        "Description: WuKongIM preview repository signing keyring\n"
        " Installs the dedicated OpenPGP keyring used to authenticate the\n"
        " WuKongIM preview APT repository.\n"
    ).encode("utf-8")


def _deb_installed_size(keyring: bytes) -> int:
    keyring_size = max(1, (len(keyring) + 1023) // 1024)
    source_size = max(1, (len(APT_SOURCE) + 1023) // 1024)
    return keyring_size + source_size


def build_deb(path: Path, version: str, keyring: bytes) -> None:
    installed_size = _deb_installed_size(keyring)
    control = _deb_control(version, installed_size)
    conffiles = f"/{APT_SOURCE_PATH}\n".encode("utf-8")
    control_tar = _tar_gzip([("./control", control), ("./conffiles", conffiles)], [])
    data_tar = _tar_gzip(
        [(f"./{APT_SOURCE_PATH}", APT_SOURCE), (f"./{APT_KEYRING_PATH}", keyring)],
        [
            "./etc",
            "./etc/apt",
            "./etc/apt/sources.list.d",
            "./usr",
            "./usr/share",
            "./usr/share/keyrings",
        ],
    )
    package = b"!<arch>\n"
    package += _ar_member("debian-binary", b"2.0\n")
    package += _ar_member("control.tar.gz", control_tar)
    package += _ar_member("data.tar.gz", data_tar)
    path.write_bytes(package)
    path.chmod(0o644)
    os.utime(path, (SOURCE_DATE_EPOCH, SOURCE_DATE_EPOCH))


def _parse_ar(data: bytes) -> dict[str, bytes]:
    require(data.startswith(b"!<arch>\n"), "DEB has no ar archive signature")
    cursor = 8
    result: dict[str, bytes] = {}
    while cursor < len(data):
        require(cursor + 60 <= len(data), "DEB has a truncated ar header")
        header = data[cursor : cursor + 60]
        cursor += 60
        require(header[58:60] == b"`\n", "DEB has an invalid ar member header")
        try:
            raw_name = header[:16].decode("ascii").rstrip()
            size = int(header[48:58].decode("ascii").strip())
        except (UnicodeDecodeError, ValueError) as error:
            raise BootstrapBuildError("DEB has malformed ar metadata") from error
        name = raw_name.removesuffix("/")
        require(name and name not in result and size >= 0, "DEB has an invalid ar member")
        require(cursor + size <= len(data), "DEB has a truncated ar member")
        result[name] = data[cursor : cursor + size]
        cursor += size
        if size % 2:
            require(cursor < len(data) and data[cursor : cursor + 1] == b"\n",
                    "DEB has invalid ar padding")
            cursor += 1
    require(cursor == len(data), "DEB has trailing bytes")
    return result


def _inspect_tar_gzip(data: bytes, label: str) -> dict[str, tuple[tarfile.TarInfo, bytes]]:
    try:
        uncompressed = gzip.decompress(data)
        archive = tarfile.open(fileobj=io.BytesIO(uncompressed), mode="r:")
    except (OSError, tarfile.TarError) as error:
        raise BootstrapBuildError(f"{label} is not a valid gzip-compressed tar archive") from error
    result: dict[str, tuple[tarfile.TarInfo, bytes]] = {}
    with archive:
        for item in archive.getmembers():
            require(item.name not in result, f"{label} contains a duplicate member")
            require(item.isdir() or item.isfile(), f"{label} contains a non-file member")
            require(item.uid == 0 and item.gid == 0 and item.mtime == SOURCE_DATE_EPOCH,
                    f"{label} contains non-canonical ownership or time metadata")
            expected_mode = 0o755 if item.isdir() else 0o644
            require(item.mode == expected_mode, f"{label} contains a non-canonical mode")
            content = b""
            if item.isfile():
                stream = archive.extractfile(item)
                require(stream is not None, f"cannot read {label} member")
                content = stream.read()
            result[item.name] = (item, content)
    return result


def inspect_deb(path: Path, version: str, keyring: bytes) -> None:
    members = _parse_ar(checked_regular_file(path, "built DEB"))
    require(list(members) == ["debian-binary", "control.tar.gz", "data.tar.gz"],
            "DEB member inventory is invalid")
    require(members["debian-binary"] == b"2.0\n", "DEB format version is invalid")
    control_members = _inspect_tar_gzip(members["control.tar.gz"], "DEB control archive")
    require(set(control_members) == {"./control", "./conffiles"},
            "DEB control archive contains scripts or unexpected files")
    installed_size = _deb_installed_size(keyring)
    require(control_members["./control"][1] == _deb_control(version, installed_size),
            "DEB control metadata is invalid")
    require(control_members["./conffiles"][1] == f"/{APT_SOURCE_PATH}\n".encode("utf-8"),
            "DEB conffile inventory is invalid")
    data_members = _inspect_tar_gzip(members["data.tar.gz"], "DEB data archive")
    expected = {
        "./usr",
        "./usr/share",
        "./usr/share/keyrings",
        "./etc",
        "./etc/apt",
        "./etc/apt/sources.list.d",
        f"./{APT_SOURCE_PATH}",
        f"./{APT_KEYRING_PATH}",
    }
    require(set(data_members) == expected, "DEB payload inventory is invalid")
    require(data_members[f"./{APT_KEYRING_PATH}"][1] == keyring,
            "DEB keyring payload differs from the reviewed certificate")
    require(data_members[f"./{APT_SOURCE_PATH}"][1] == APT_SOURCE,
            "DEB source configuration payload is invalid")


def _tool(name: str) -> str:
    path = shutil.which(name)
    require(path is not None, f"required package build tool is unavailable: {name}")
    return path


def _run(command: list[str], label: str, *, environment: dict[str, str]) -> subprocess.CompletedProcess[bytes]:
    try:
        result = subprocess.run(command, check=False, capture_output=True, env=environment)
    except OSError as error:
        raise BootstrapBuildError(f"cannot run {label}: {error}") from error
    require(len(result.stdout) <= MAX_TOOL_OUTPUT_BYTES and len(result.stderr) <= MAX_TOOL_OUTPUT_BYTES,
            f"{label} output exceeds the safety limit")
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", "replace").strip()
        raise BootstrapBuildError(f"{label} failed" + (f": {detail}" if detail else ""))
    return result


def _rpm_environment(state_root: Path) -> dict[str, str]:
    environment = os.environ.copy()
    environment.update({
        "HOME": str(state_root / "HOME"),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "SOURCE_DATE_EPOCH": str(SOURCE_DATE_EPOCH),
        "TMPDIR": str(state_root / "TMP"),
        "TZ": "UTC",
    })
    return environment


def _write_build_source(path: Path, data: bytes) -> None:
    path.write_bytes(data)
    path.chmod(0o644)
    os.utime(path, (SOURCE_DATE_EPOCH, SOURCE_DATE_EPOCH))


def build_rpm(path: Path, version: str, certificate: bytes, build_root: Path) -> tuple[str, dict[str, str]]:
    top = build_root / "rpm"
    for directory in (
        "BUILD", "BUILDROOT", "HOME", "RPMDB", "RPMS", "SOURCES", "SPECS", "SRPMS", "TMP"
    ):
        (top / directory).mkdir(parents=True, exist_ok=False)
    _write_build_source(top / "SOURCES/RPM-GPG-KEY-wukongim-preview", certificate)
    _write_build_source(top / "SOURCES/wukongim-preview.repo", RPM_REPOSITORY)
    spec_path = top / "SPECS/wukongim-release.spec"
    _write_build_source(spec_path, RPM_SPEC_TEMPLATE.replace("@VERSION@", version).encode("utf-8"))

    rpmbuild = _tool("rpmbuild")
    rpm = _tool("rpm")
    environment = _rpm_environment(top)
    _run(
        [
            rpmbuild,
            "--define", f"_topdir {top}",
            "--define", f"_dbpath {top / 'RPMDB'}",
            "--define", f"_tmppath {top / 'TMP'}",
            "--define", "_buildhost packages.githubim.com",
            "--define", "_build_name_fmt %{ARCH}/%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}.rpm",
            "--define", "_binary_payload w9.gzdio",
            "--define", "_source_filedigest_algorithm 8",
            "--define", "_binary_filedigest_algorithm 8",
            "--define", "_build_id_links none",
            "--define", "source_date_epoch_from_changelog 0",
            "--define", "use_source_date_epoch_as_buildtime 1",
            "--define", "clamp_mtime_to_source_date_epoch 1",
            "-bb", str(spec_path),
        ],
        "rpmbuild",
        environment=environment,
    )
    expected = top / "RPMS/noarch" / path.name
    require(expected.is_file(), "rpmbuild did not create the canonical RPM filename")
    candidates = list((top / "RPMS").glob("**/*.rpm"))
    require(candidates == [expected], "rpmbuild created an unexpected RPM inventory")
    shutil.copyfile(expected, path)
    path.chmod(0o644)
    os.utime(path, (SOURCE_DATE_EPOCH, SOURCE_DATE_EPOCH))
    expected_digests = {
        f"/{RPM_KEY_PATH}": hashlib.sha256(certificate).hexdigest(),
        f"/{RPM_REPO_PATH}": hashlib.sha256(RPM_REPOSITORY).hexdigest(),
    }
    return rpm, expected_digests


def inspect_rpm(
    path: Path,
    version: str,
    rpm: str,
    expected_digests: dict[str, str],
    state_root: Path,
) -> None:
    environment = _rpm_environment(state_root)
    rpm_command = [rpm, "--dbpath", str(state_root / "RPMDB")]
    try:
        identity = _run(
            [
                *rpm_command,
                "-qp",
                "--queryformat",
                "%{NAME}\\t%{EPOCHNUM}\\t%{VERSION}\\t%{RELEASE}\\t%{ARCH}\\n",
                str(path),
            ],
            "RPM identity query",
            environment=environment,
        ).stdout.decode("utf-8", "strict")
    except UnicodeDecodeError as error:
        raise BootstrapBuildError("RPM identity is not UTF-8") from error
    require(identity == f"{RPM_NAME}\t0\t{version}\t1\tnoarch\n", "RPM identity is invalid")
    files = _run(
        [*rpm_command, "-qpl", str(path)],
        "RPM file-list query",
        environment=environment,
    ).stdout
    try:
        file_list = files.decode("utf-8", "strict").splitlines()
    except UnicodeDecodeError as error:
        raise BootstrapBuildError("RPM file list is not UTF-8") from error
    require(set(file_list) == set(expected_digests) and len(file_list) == 2,
            "RPM payload inventory is invalid")
    scripts = _run(
        [*rpm_command, "-qp", "--scripts", str(path)],
        "RPM script query",
        environment=environment,
    )
    require(not scripts.stdout.strip(), "RPM must not contain package scriptlets")
    digest_algorithm = _run(
        [*rpm_command, "-qp", "--queryformat", "%{FILEDIGESTALGO}\\n", str(path)],
        "RPM digest-algorithm query",
        environment=environment,
    ).stdout
    require(digest_algorithm == b"8\n", "RPM file digests must use SHA-256")
    facts = _run(
        [
            *rpm_command,
            "-qp",
            "--queryformat",
            "[%{FILENAMES}\\t%{FILEDIGESTS}\\t%{FILEFLAGS}\\t%{FILEMODES:perms}\\n]",
            str(path),
        ],
        "RPM file-metadata query",
        environment=environment,
    ).stdout
    try:
        lines = facts.decode("utf-8", "strict").splitlines()
        parsed = {parts[0]: parts[1:] for parts in (line.split("\t") for line in lines)}
    except UnicodeDecodeError as error:
        raise BootstrapBuildError("RPM file metadata is not UTF-8") from error
    require(len(lines) == 2 and len(parsed) == 2 and all(len(value) == 3 for value in parsed.values()),
            "RPM file metadata is malformed")
    for filename, expected_digest in expected_digests.items():
        require(filename in parsed, "RPM file metadata omits an expected payload")
        digest, flags, mode = parsed[filename]
        expected_flags = "17" if filename == f"/{RPM_REPO_PATH}" else "0"
        require(digest == expected_digest and flags == expected_flags and mode == "-rw-r--r--",
                f"RPM file metadata is invalid for {filename}")
    _run(
        [*rpm_command, "-K", "--nosignature", str(path)],
        "RPM digest verification",
        environment=environment,
    )


def file_facts(path: Path) -> tuple[str, int]:
    data = checked_regular_file(path, path.name)
    return hashlib.sha256(data).hexdigest(), len(data)


def _inventory_entry(
    *, name: str, version: str, architecture: str, filename: str, repository_path: str,
    digest: str, size: int,
) -> dict[str, object]:
    return {
        "name": name,
        "version": version,
        "architecture": architecture,
        "filename": filename,
        "repository_path": repository_path,
        "download_path": f"bootstrap/{filename}",
        "source_sha256": digest,
        "source_size": size,
        "published_sha256": digest,
        "published_size": size,
        "new": True,
    }


def rename_directory_exclusive(source: Path, destination: Path) -> None:
    library = ctypes.CDLL(None, use_errno=True)
    if sys.platform == "darwin":
        try:
            rename = library.renamex_np
        except AttributeError as error:
            raise BootstrapBuildError("platform lacks exclusive directory rename") from error
        rename.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint]
        rename.restype = ctypes.c_int
        result = rename(os.fsencode(source), os.fsencode(destination), 0x00000004)
    elif sys.platform.startswith("linux"):
        try:
            rename = library.renameat2
        except AttributeError as error:
            raise BootstrapBuildError("platform lacks exclusive directory rename") from error
        rename.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        rename.restype = ctypes.c_int
        result = rename(-100, os.fsencode(source), -100, os.fsencode(destination), 1)
    else:
        raise BootstrapBuildError("platform lacks exclusive directory rename")
    if result == 0:
        return
    error_number = ctypes.get_errno()
    if error_number in {errno.EEXIST, errno.ENOTEMPTY}:
        raise BootstrapBuildError("output directory appeared during bootstrap build")
    raise BootstrapBuildError(f"cannot publish bootstrap output: {os.strerror(error_number)}")


def build(args: argparse.Namespace) -> dict[str, object]:
    manifest = load_manifest(args.manifest)
    apt_certificate = checked_regular_file(args.apt_public_cert, "APT public certificate")
    rpm_certificate = checked_regular_file(args.rpm_public_cert, "RPM public certificate")
    apt_keyring = dearmor_public_certificate(apt_certificate, "APT public certificate")
    rpm_keyring = dearmor_public_certificate(rpm_certificate, "RPM public certificate")
    require(apt_keyring != rpm_keyring,
            "APT and RPM public certificates must remain distinct")

    output = Path(os.path.abspath(args.output_dir))
    require(not os.path.lexists(output), "output directory must not already exist or be a link")
    parent = output.parent
    try:
        parent_metadata = parent.lstat()
    except OSError as error:
        raise BootstrapBuildError(f"cannot inspect output parent: {error}") from error
    require(stat.S_ISDIR(parent_metadata.st_mode), "output parent must be a real directory")

    version = manifest["version"]
    apt_filename = f"{APT_NAME}_{version}_all.deb"
    rpm_filename = f"{RPM_NAME}-{version}-1.noarch.rpm"
    stage = Path(tempfile.mkdtemp(prefix=f".{output.name}.build-", dir=parent))
    rpm_build_root: Path | None = None
    try:
        apt_path = stage / apt_filename
        rpm_path = stage / rpm_filename
        build_deb(apt_path, version, apt_keyring)
        inspect_deb(apt_path, version, apt_keyring)
        rpm_build_root = Path(tempfile.mkdtemp(prefix=f".{output.name}.rpm-", dir=parent))
        rpm_tool, expected_rpm_digests = build_rpm(
            rpm_path, version, rpm_certificate, rpm_build_root
        )
        inspect_rpm(
            rpm_path,
            version,
            rpm_tool,
            expected_rpm_digests,
            rpm_build_root / "rpm",
        )
        shutil.rmtree(rpm_build_root)
        rpm_build_root = None
        require({entry.name for entry in stage.iterdir()} == {apt_filename, rpm_filename},
                "bootstrap output contains unexpected files")
        apt_digest, apt_size = file_facts(apt_path)
        rpm_digest, rpm_size = file_facts(rpm_path)
        inventory = {
            "schema": INVENTORY_SCHEMA,
            "version": version,
            "packages": {
                "apt": _inventory_entry(
                    name=APT_NAME,
                    version=version,
                    architecture="all",
                    filename=apt_filename,
                    repository_path=f"apt/pool/main/w/wukongim/{apt_filename}",
                    digest=apt_digest,
                    size=apt_size,
                ),
                "rpm": _inventory_entry(
                    name=RPM_NAME,
                    version=version,
                    architecture="noarch",
                    filename=rpm_filename,
                    repository_path=f"rpm/preview/el/9/x86_64/Packages/{rpm_filename}",
                    digest=rpm_digest,
                    size=rpm_size,
                ),
            },
        }
        rename_directory_exclusive(stage, output)
        return inventory
    except BaseException:
        if rpm_build_root is not None and os.path.lexists(rpm_build_root):
            shutil.rmtree(rpm_build_root)
        if os.path.lexists(stage):
            shutil.rmtree(stage)
        raise


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--apt-public-cert", required=True, type=Path)
    parser.add_argument("--rpm-public-cert", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        inventory = build(args)
    except BootstrapBuildError as error:
        print(f"repository bootstrap package build failed: {error}", file=sys.stderr)
        return 1
    sys.stdout.buffer.write(canonical_json(inventory))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
