#!/usr/bin/env python3
"""Atomically sign one isolated APT or RPM repository family."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path, PurePosixPath
from typing import Sequence


ROOT = Path(__file__).resolve().parents[1]
VALIDATOR_PATH = ROOT / "scripts" / "validate-signing-material.py"
VALIDATOR_SPEC = importlib.util.spec_from_file_location(
    "wukongim_validate_signing_material", VALIDATOR_PATH
)
if VALIDATOR_SPEC is None or VALIDATOR_SPEC.loader is None:
    raise RuntimeError("cannot load signing-material validator")
validator = importlib.util.module_from_spec(VALIDATOR_SPEC)
sys.modules[VALIDATOR_SPEC.name] = validator
VALIDATOR_SPEC.loader.exec_module(validator)


SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
FINGERPRINT_RE = re.compile(r"^[0-9A-F]{40}$")
HASHED_ISSUER_FINGERPRINT_RE = re.compile(
    rb"^[ \t]*hashed subpkt 33 len 21 \(issuer fpr v4 "
    rb"([0-9A-Fa-f]{40})\)[ \t]*$",
    re.IGNORECASE,
)
ISSUER_FINGERPRINT_MARKER_RE = re.compile(rb"issuer[ \t]+fpr", re.IGNORECASE)
SIGNATURE_PACKET_RE = re.compile(
    rb"^:signature packet: algo ([0-9]+)(?:[^0-9]|$)", re.IGNORECASE | re.MULTILINE
)
DIGEST_ALGORITHM_RE = re.compile(
    rb"(?:^|\n)[ \t]*digest algo ([0-9]+)(?:[^0-9]|$)", re.IGNORECASE
)
SAFE_COMPONENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+~-]{0,254}$")
MAX_ALLOWLIST_BYTES = 1024 * 1024
MAX_RPM_BYTES = 1024 * 1024 * 1024
COPY_BUFFER_BYTES = 1024 * 1024


class FamilySigningError(ValueError):
    """Raised when a family repository violates the signing contract."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise FamilySigningError(message)


def canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"


def reject_duplicate_key(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise FamilySigningError(f"allowlist contains duplicate JSON key: {key}")
        result[key] = value
    return result


def parse_relative_path(value: str, label: str) -> PurePosixPath:
    require(value != "" and "\\" not in value and "\x00" not in value,
            f"{label} must be a canonical relative POSIX path")
    path = PurePosixPath(value)
    require(not path.is_absolute() and str(path) == value and value not in {".", ".."},
            f"{label} must be a canonical relative POSIX path")
    require(all(part not in {"", ".", ".."} and SAFE_COMPONENT_RE.fullmatch(part)
                for part in path.parts),
            f"{label} contains an unsafe path component")
    return path


def checked_path(root: Path, relative: PurePosixPath, label: str, *, directory: bool) -> Path:
    current = root
    for part in relative.parts:
        current = current / part
        try:
            metadata = current.lstat()
        except OSError as error:
            raise FamilySigningError(f"cannot inspect {label}") from error
        if current == root / Path(*relative.parts) and not directory:
            require(stat.S_ISREG(metadata.st_mode), f"{label} must be a regular file")
            require(metadata.st_nlink == 1, f"{label} must not be hard linked")
        else:
            require(stat.S_ISDIR(metadata.st_mode), f"{label} path must contain only directories")
    if directory:
        require(current.is_dir() and not current.is_symlink(), f"{label} must be a directory")
    return current


def hash_regular_file(path: Path, label: str, *, maximum_bytes: int | None = None) -> dict[str, object]:
    try:
        before = path.lstat()
    except OSError as error:
        raise FamilySigningError(f"cannot inspect {label}") from error
    require(stat.S_ISREG(before.st_mode), f"{label} must be a regular file")
    require(before.st_nlink == 1, f"{label} must not be hard linked")
    require(before.st_size > 0, f"{label} must not be empty")
    if maximum_bytes is not None:
        require(before.st_size <= maximum_bytes, f"{label} exceeds its size limit")
    require(hasattr(os, "O_NOFOLLOW"), "platform must support O_NOFOLLOW")
    flags = os.O_RDONLY | os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise FamilySigningError(f"cannot safely open {label}") from error
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
            block = os.read(descriptor, COPY_BUFFER_BYTES)
            if not block:
                break
            total += len(block)
            digest.update(block)
        after = os.fstat(descriptor)
        require(
            (after.st_dev, after.st_ino, after.st_size)
            == (opened.st_dev, opened.st_ino, opened.st_size)
            and total == opened.st_size,
            f"{label} changed while it was read",
        )
    finally:
        os.close(descriptor)
    return {"sha256": digest.hexdigest(), "size": total}


def copy_file_safely(source: Path, target: Path, label: str) -> None:
    facts = hash_regular_file(source, label)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    descriptor = os.open(target, flags, 0o600)
    try:
        source_descriptor = os.open(source, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            while True:
                block = os.read(source_descriptor, COPY_BUFFER_BYTES)
                if not block:
                    break
                view = memoryview(block)
                while view:
                    written = os.write(descriptor, view)
                    view = view[written:]
        finally:
            os.close(source_descriptor)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.chmod(target, 0o644)
    copied = hash_regular_file(target, f"copied {label}")
    require(copied == facts, f"{label} changed while it was copied")


def copy_tree_safely(source: Path, target: Path) -> None:
    try:
        root_metadata = source.lstat()
    except OSError as error:
        raise FamilySigningError("cannot inspect input repository") from error
    require(stat.S_ISDIR(root_metadata.st_mode), "input repository must be a real directory")
    for directory, names, files in os.walk(source, topdown=True, followlinks=False):
        directory_path = Path(directory)
        relative = directory_path.relative_to(source)
        target_directory = target / relative
        target_directory.mkdir(mode=0o755, parents=True, exist_ok=True)
        for name in sorted(names):
            metadata = (directory_path / name).lstat()
            require(stat.S_ISDIR(metadata.st_mode),
                    f"input repository contains a linked or special directory: {(relative / name).as_posix()}")
        for name in sorted(files):
            source_file = directory_path / name
            metadata = source_file.lstat()
            require(stat.S_ISREG(metadata.st_mode),
                    f"input repository contains a linked or special file: {(relative / name).as_posix()}")
            require(metadata.st_nlink == 1,
                    f"input repository contains a hard-linked file: {(relative / name).as_posix()}")
            copy_file_safely(
                source_file,
                target_directory / name,
                f"input {(relative / name).as_posix()}",
            )


def load_json_file(path: Path, label: str) -> object:
    raw = validator.checked_regular_file(path, label, MAX_ALLOWLIST_BYTES, secret=False)
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=reject_duplicate_key)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise FamilySigningError(f"{label} is not canonical JSON") from error
    require(raw == canonical_json(value), f"{label} must use canonical JSON encoding")
    return value


def load_package_allowlist(path: Path, label: str) -> dict[str, dict[str, object]]:
    value = load_json_file(path, label)
    require(isinstance(value, dict) and set(value) == {"packages", "schema"},
            f"{label} has unexpected fields")
    require(value["schema"] == "wukongim/rpm-package-allowlist/v1",
            f"{label} schema is unsupported")
    packages = value["packages"]
    require(isinstance(packages, list), f"{label} packages must be an array")
    result: dict[str, dict[str, object]] = {}
    previous = ""
    for index, entry in enumerate(packages):
        require(isinstance(entry, dict) and set(entry) == {"path", "sha256", "size"},
                f"{label} package {index} has unexpected fields")
        path_value = entry["path"]
        digest = entry["sha256"]
        size = entry["size"]
        require(isinstance(path_value, str), f"{label} package {index} path must be a string")
        relative = parse_relative_path(path_value, f"{label} package path")
        require(relative.parts[0] == "Packages" and relative.suffix == ".rpm",
                f"{label} package paths must be RPMs below Packages/")
        require(path_value > previous, f"{label} package paths must be unique and sorted")
        require(isinstance(digest, str) and SHA256_RE.fullmatch(digest) is not None,
                f"{label} package {path_value} has an invalid SHA-256")
        require(isinstance(size, int) and not isinstance(size, bool) and 0 < size <= MAX_RPM_BYTES,
                f"{label} package {path_value} has an invalid size")
        result[path_value] = {"sha256": digest, "size": size}
        previous = path_value
    return result


def load_active_allowlist(path: Path) -> list[str]:
    label = "active RPM allowlist"
    value = load_json_file(path, label)
    require(isinstance(value, dict) and set(value) == {"paths", "schema"},
            f"{label} has unexpected fields")
    require(value["schema"] == "wukongim/rpm-active-allowlist/v1",
            f"{label} schema is unsupported")
    paths = value["paths"]
    require(isinstance(paths, list) and paths, f"{label} paths must be a non-empty array")
    result: list[str] = []
    previous = ""
    for index, path_value in enumerate(paths):
        require(isinstance(path_value, str), f"{label} path {index} must be a string")
        relative = parse_relative_path(path_value, f"{label} path")
        require(relative.parts[0] == "Packages" and relative.suffix == ".rpm",
                f"{label} paths must be RPMs below Packages/")
        require(path_value > previous, f"{label} paths must be unique and sorted")
        result.append(path_value)
        previous = path_value
    return result


def artifact(path: Path, relative: str) -> dict[str, object]:
    return {"path": relative, **hash_regular_file(path, relative)}


def require_tool(name: str) -> str:
    tool = shutil.which(name)
    require(tool is not None, f"required repository tool is unavailable: {name}")
    return tool


def run_tool(
    command: Sequence[str],
    *,
    label: str,
    environment: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[bytes]:
    result = subprocess.run(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=environment,
        check=False,
    )
    if result.returncode != 0:
        raise FamilySigningError(f"repository tool failed during {label}")
    return result


def exact_signature_status(output: bytes, signing_fingerprint: str, label: str) -> None:
    try:
        lines = output.decode("utf-8", errors="strict").splitlines()
    except UnicodeDecodeError as error:
        raise FamilySigningError(f"{label} returned non-UTF-8 signature status") from error
    signatures = [line.split() for line in lines if line.startswith("[GNUPG:] VALIDSIG ")]
    require(len(signatures) == 1 and len(signatures[0]) >= 10,
            f"{label} did not produce one exact signature")
    require(signatures[0][2] == signing_fingerprint,
            f"{label} used an unexpected signing subkey")
    require(signatures[0][9] == str(validator.OPENPGP_SHA256_ALGORITHM),
            f"{label} did not use SHA-256")


def verify_detached(session: object, signature: Path, source: Path, label: str) -> None:
    result = session.gpg.run(
        ["--status-fd", "1", "--verify", str(signature), str(source)],
        stage=label,
    )
    exact_signature_status(result.stdout, session.signing_subkey_fingerprint, label)


def sign_apt(stage: Path, args: argparse.Namespace, session: object) -> dict[str, object]:
    release_relative = parse_relative_path(args.apt_release, "APT Release path")
    release = checked_path(stage, release_relative, "APT Release", directory=False)
    require(release.name == "Release", "APT Release path must end with /Release")
    release_facts = artifact(release, release_relative.as_posix())
    inrelease = release.parent / "InRelease"
    detached = release.parent / "Release.gpg"
    require(not os.path.lexists(inrelease) and not os.path.lexists(detached),
            "APT input must not contain pre-existing Release signatures")

    session.sign(
        release,
        inrelease,
        armor=True,
        cleartext=True,
        stage="APT InRelease signing",
    )
    session.sign(
        release,
        detached,
        armor=True,
        stage="APT Release.gpg signing",
    )
    verify_detached(session, detached, release, "APT Release.gpg verification")
    extracted = session.gpg.home / "verified-apt-release"
    result = session.gpg.run(
        ["--status-fd", "1", "--output", str(extracted), "--decrypt", str(inrelease)],
        stage="APT InRelease verification",
    )
    exact_signature_status(
        result.stdout, session.signing_subkey_fingerprint, "APT InRelease verification"
    )
    require(extracted.read_bytes() == release.read_bytes(),
            "APT InRelease cleartext differs from the exact Release bytes")
    require(artifact(release, release_relative.as_posix()) == release_facts,
            "APT Release bytes changed during signing")
    return {
        "inrelease": artifact(inrelease, (release_relative.parent / "InRelease").as_posix()),
        "release": release_facts,
        "release_gpg": artifact(detached, (release_relative.parent / "Release.gpg").as_posix()),
    }


def rpm_signature_issuer_fingerprint(
    rpm: str,
    gpg: object,
    rpm_database: Path,
    package: Path,
    *,
    environment: dict[str, str],
) -> str:
    result = run_tool(
        [
            rpm,
            "--dbpath",
            str(rpm_database),
            "-qp",
            "--queryformat",
            "%{RSAHEADER:armor}\n",
            str(package),
        ],
        label="RPM header signature extraction",
        environment=environment,
    )
    require(0 < len(result.stdout) <= 1024 * 1024,
            "RPM header signature extraction returned an invalid size")
    with tempfile.TemporaryDirectory(prefix="wk-rpm-signature-", dir=gpg.home) as temporary:
        signature = Path(temporary) / "header-signature.asc"
        signature.write_bytes(result.stdout)
        signature.chmod(0o600)
        packets = gpg.run(
            ["--list-packets", str(signature)],
            stage="RPM header signature packet inspection",
            check=False,
        )
    require(packets.returncode == 0,
            "RPM header signature is not a valid OpenPGP packet")
    listing = packets.stdout + b"\n" + packets.stderr
    signature_algorithms = [int(value) for value in SIGNATURE_PACKET_RE.findall(listing)]
    require(signature_algorithms == [validator.OPENPGP_RSA_ALGORITHM],
            "RPM header signature must contain exactly one RSA signature packet")
    issuer_lines = [
        line for line in listing.splitlines()
        if ISSUER_FINGERPRINT_MARKER_RE.search(line)
    ]
    require(len(issuer_lines) == 1,
            "RPM header signature must contain exactly one hashed issuer fingerprint")
    issuer_match = HASHED_ISSUER_FINGERPRINT_RE.fullmatch(issuer_lines[0])
    require(issuer_match is not None,
            "RPM header signature issuer fingerprint must be a hashed subpacket")
    issuer = issuer_match.group(1).decode("ascii").upper()
    require(FINGERPRINT_RE.fullmatch(issuer) is not None,
            "RPM header signature issuer fingerprint is invalid")
    digest_algorithms = [
        int(value)
        for value in DIGEST_ALGORITHM_RE.findall(
            listing
        )
    ]
    require(
        digest_algorithms == [validator.OPENPGP_SHA256_ALGORITHM],
        "RPM header signature must use SHA-256 in exactly one digest declaration",
    )
    return issuer


def rpmkeys_signature_is_valid(result: subprocess.CompletedProcess[bytes]) -> bool:
    """Return whether fixed-locale rpmkeys reported one successful signature."""
    output = result.stdout + b"\n" + result.stderr
    try:
        text = output.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise FamilySigningError("rpmkeys returned non-UTF-8 signature status") from error
    lowered = text.lower()
    return (
        result.returncode == 0
        and "signature" in lowered
        and "noke" not in lowered
        and "not ok" not in lowered
        and "bad" not in lowered
    )


def rpm_verifying_fingerprints(
    rpm: str,
    rpmkeys: str,
    gpg: object,
    package: Path,
    signing_fingerprints: Sequence[str],
    *,
    environment: dict[str, str],
) -> tuple[str, ...]:
    """Cryptographically identify the exact reviewed subkey that verifies an RPM.

    An OpenPGP issuer-fingerprint subpacket is a signer-controlled claim, even
    when it is hashed.  Each candidate is therefore exported into its own
    minimal certificate and isolated RPM database.  A candidate counts only
    when the package verifies with that candidate as the sole signing subkey.
    """
    verified: list[str] = []
    for fingerprint in signing_fingerprints:
        require(FINGERPRINT_RE.fullmatch(fingerprint) is not None,
                "RPM verification candidate fingerprint is invalid")
        with tempfile.TemporaryDirectory(
            prefix="wk-rpm-exact-key-", dir=gpg.home
        ) as temporary_name:
            temporary = Path(temporary_name)
            certificate = temporary / "candidate.asc"
            database = temporary / "rpmdb"
            database.mkdir(mode=0o700)
            gpg.run(
                [
                    "--armor",
                    "--output", str(certificate),
                    "--export-options", "export-minimal",
                    "--export-filter", f"drop-subkey=fpr != {fingerprint}",
                    "--export", fingerprint,
                ],
                stage="exact RPM verification-certificate export",
            )
            hash_regular_file(
                certificate,
                "exact RPM verification certificate",
                maximum_bytes=validator.MAX_PUBLIC_CERT_BYTES,
            )
            shown = gpg.run(
                [
                    "--with-colons",
                    "--fixed-list-mode",
                    "--with-fingerprint",
                    "--with-subkey-fingerprint",
                    "--import-options", "show-only",
                    "--import", str(certificate),
                ],
                stage="exact RPM verification-certificate inspection",
            )
            records = validator.parse_colon_keys(shown.stdout)
            require(
                len(records) == 2
                and records[0].record_type == "pub"
                and records[1].record_type == "sub"
                and records[1].fingerprint == fingerprint,
                "filtered RPM verification certificate did not isolate one exact subkey",
            )
            validator.validate_rpm_rsa_key(records[0], "filtered RPM primary key")
            validator.validate_rpm_rsa_key(records[1], "filtered RPM signing subkey")
            candidate = records[1]
            now = int(time.time())
            if (
                candidate.validity in validator.BAD_VALIDITY
                or "D" in candidate.capabilities
                or candidate.created > now
                or candidate.expires is None
                or candidate.expires <= now
            ):
                # Historical keys remain in the reviewed certificate for
                # audit topology after expiry/revocation, but they cannot
                # authorize a deployable package snapshot.
                continue
            run_tool(
                [rpm, "--dbpath", str(database), "--initdb"],
                label="exact RPM verification database initialization",
                environment=environment,
            )
            run_tool(
                [rpm, "--dbpath", str(database), "--import", str(certificate)],
                label="exact RPM verification certificate import",
                environment=environment,
            )
            result = subprocess.run(
                [rpmkeys, "--dbpath", str(database), "--verbose", "--checksig", str(package)],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=environment,
                check=False,
            )
            if rpmkeys_signature_is_valid(result):
                verified.append(fingerprint)
    return tuple(verified)


def rpm_signature_check(
    rpm: str,
    rpmkeys: str,
    gpg: object,
    rpm_database: Path,
    package: Path,
    signing_fingerprints: Sequence[str],
    *,
    expect_signed: bool,
    environment: dict[str, str],
) -> None:
    require(bool(signing_fingerprints), "RPM signature verification requires an allowed key")
    require(len({value[-16:] for value in signing_fingerprints}) == len(signing_fingerprints)
            and len({value[-8:] for value in signing_fingerprints}) == len(signing_fingerprints),
            "RPM signature verification requires unambiguous reviewed key IDs")
    result = subprocess.run(
        [rpmkeys, "--dbpath", str(rpm_database), "--verbose", "--checksig", str(package)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=environment,
        check=False,
    )
    output = result.stdout + b"\n" + result.stderr
    try:
        text = output.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise FamilySigningError("rpmkeys returned non-UTF-8 signature status") from error
    lowered = text.lower()
    has_signature = "signature" in lowered
    if expect_signed:
        require(rpmkeys_signature_is_valid(result),
                "RPM package signature verification failed")
        issuer = rpm_signature_issuer_fingerprint(
            rpm, gpg, rpm_database, package, environment=environment
        )
        verified = rpm_verifying_fingerprints(
            rpm,
            rpmkeys,
            gpg,
            package,
            signing_fingerprints,
            environment=environment,
        )
        require(
            len(verified) == 1,
            "RPM package was not signed by exactly one reviewed current or historical signing subkey",
        )
        require(
            issuer == verified[0],
            "RPM header issuer fingerprint differs from the cryptographically verified subkey",
        )
    else:
        require(result.returncode == 0 and not has_signature,
                "new RPM allowlist contains an already-signed or invalid package")


def list_rpm_payloads(rpm_root: Path) -> list[str]:
    packages = checked_path(rpm_root, PurePosixPath("Packages"), "RPM Packages", directory=True)
    result: list[str] = []
    for directory, names, files in os.walk(packages, topdown=True, followlinks=False):
        directory_path = Path(directory)
        for name in names:
            require(stat.S_ISDIR((directory_path / name).lstat().st_mode),
                    "RPM Packages contains a linked or special directory")
        for name in files:
            path = directory_path / name
            relative = path.relative_to(rpm_root).as_posix()
            require(name.endswith(".rpm") and stat.S_ISREG(path.lstat().st_mode),
                    f"RPM Packages contains an unsupported entry: {relative}")
            require(path.lstat().st_nlink == 1, f"RPM payload must not be hard linked: {relative}")
            result.append(relative)
    return sorted(result)


def validate_allowlisted_inputs(
    rpm_root: Path,
    entries: dict[str, dict[str, object]],
    label: str,
) -> None:
    for relative, expected in entries.items():
        path = checked_path(rpm_root, PurePosixPath(relative), f"{label} {relative}", directory=False)
        actual = hash_regular_file(path, f"{label} {relative}", maximum_bytes=MAX_RPM_BYTES)
        require(actual == expected, f"{label} identity mismatch: {relative}")


def sign_rpm(stage: Path, args: argparse.Namespace, session: object) -> dict[str, object]:
    rpm_relative = parse_relative_path(args.rpm_repository, "RPM repository path")
    rpm_root = checked_path(stage, rpm_relative, "RPM repository", directory=True)
    new_entries = load_package_allowlist(args.new_rpm_allowlist, "new unsigned RPM allowlist")
    signed_entries = load_package_allowlist(args.signed_rpm_allowlist, "preserved signed RPM allowlist")
    active_paths = load_active_allowlist(args.active_rpm_allowlist)
    require(set(new_entries).isdisjoint(signed_entries),
            "new and preserved-signed RPM allowlists must be disjoint")
    all_entries = {**new_entries, **signed_entries}
    actual_paths = list_rpm_payloads(rpm_root)
    require(sorted(all_entries) == actual_paths,
            "RPM allowlists do not close over the exact Packages payload set")
    require(set(active_paths).issubset(all_entries),
            "active RPM allowlist references a package outside the exact payload allowlists")
    require(set(new_entries).issubset(active_paths),
            "every newly signed RPM must be present in the active allowlist")
    validate_allowlisted_inputs(rpm_root, new_entries, "new unsigned RPM")
    validate_allowlisted_inputs(rpm_root, signed_entries, "preserved signed RPM")

    rpm = require_tool("rpm")
    rpmkeys = require_tool("rpmkeys")
    rpmsign = require_tool("rpmsign")
    createrepo = require_tool("createrepo_c")
    environment = dict(session.gpg.environment)
    rpm_database = session.gpg.home / "rpm-verify-db"
    rpm_database.mkdir(mode=0o700)
    public_cert = session.gpg.home / "reviewed-rpm-public-cert.asc"
    session.gpg.run(
        [
            "--armor",
            "--export-options",
            "export-minimal",
            "--output",
            str(public_cert),
            "--export",
            session.primary_fingerprint,
        ],
        stage="RPM public-certificate export",
    )
    run_tool([rpm, "--dbpath", str(rpm_database), "--initdb"],
             label="RPM verification database initialization", environment=environment)
    run_tool([rpm, "--dbpath", str(rpm_database), "--import", str(public_cert)],
             label="RPM public-certificate import", environment=environment)

    preserved_before = {
        path: artifact(rpm_root / Path(*PurePosixPath(path).parts), path)
        for path in sorted(signed_entries)
    }
    preserved_signing_fingerprints = (
        session.signing_subkey_fingerprint,
        *session.historical_signing_subkey_fingerprints,
    )
    for relative in sorted(signed_entries):
        rpm_signature_check(
            rpm,
            rpmkeys,
            session.gpg,
            rpm_database,
            rpm_root / Path(*PurePosixPath(relative).parts),
            preserved_signing_fingerprints,
            expect_signed=True,
            environment=environment,
        )
    for relative in sorted(new_entries):
        package = rpm_root / Path(*PurePosixPath(relative).parts)
        rpm_signature_check(
            rpm,
            rpmkeys,
            session.gpg,
            rpm_database,
            package,
            (session.signing_subkey_fingerprint,),
            expect_signed=False,
            environment=environment,
        )
        before = artifact(package, relative)
        run_tool(
            [
                rpmsign,
                "--define",
                f"_gpg_name {session.signing_subkey_fingerprint}!",
                "--define",
                f"_gpg_path {session.gpg.home}",
                "--define",
                f"__gpg {session.gpg.gpg}",
                "--define",
                "_gpg_digest_algo sha256",
                "--addsign",
                str(package),
            ],
            label=f"RPM payload signing: {relative}",
            environment=environment,
        )
        require(artifact(package, relative) != before,
                f"RPM signer did not change the unsigned package: {relative}")
        rpm_signature_check(
            rpm,
            rpmkeys,
            session.gpg,
            rpm_database,
            package,
            (session.signing_subkey_fingerprint,),
            expect_signed=True,
            environment=environment,
        )

    preserved_after = {
        path: artifact(rpm_root / Path(*PurePosixPath(path).parts), path)
        for path in sorted(signed_entries)
    }
    require(preserved_after == preserved_before,
            "a preserved signed RPM changed while new RPMs were signed")

    existing_repodata = rpm_root / "repodata"
    if os.path.lexists(existing_repodata):
        require(existing_repodata.is_dir() and not existing_repodata.is_symlink(),
                "existing RPM repodata must be a real directory")
        shutil.rmtree(existing_repodata)
    metadata_view = stage / ".wk-rpm-active-metadata-view"
    require(not os.path.lexists(metadata_view), "reserved RPM metadata-view path already exists")
    (metadata_view / "Packages").mkdir(parents=True, mode=0o755)
    for relative in active_paths:
        source = rpm_root / Path(*PurePosixPath(relative).parts)
        target = metadata_view / Path(*PurePosixPath(relative).parts)
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
        copy_file_safely(source, target, f"active RPM {relative}")
    run_tool(
        [createrepo, "--quiet", "--simple-md-filenames", str(metadata_view)],
        label="active RPM metadata generation",
        environment=environment,
    )
    generated_repodata = checked_path(
        metadata_view, PurePosixPath("repodata"), "generated RPM repodata", directory=True
    )
    os.replace(generated_repodata, existing_repodata)
    shutil.rmtree(metadata_view)
    repomd = checked_path(
        rpm_root, PurePosixPath("repodata/repomd.xml"), "RPM repomd.xml", directory=False
    )
    repomd_signature = rpm_root / "repodata" / "repomd.xml.asc"
    require(not os.path.lexists(repomd_signature), "generated repodata contains a signature")
    session.sign(
        repomd,
        repomd_signature,
        armor=True,
        stage="RPM repomd.xml signing",
    )
    verify_detached(session, repomd_signature, repomd, "RPM repomd.xml verification")

    post_entries = {
        path: artifact(rpm_root / Path(*PurePosixPath(path).parts), path)
        for path in sorted(all_entries)
    }
    active_set = set(active_paths)
    repodata_files: list[dict[str, object]] = []
    for path in sorted((rpm_root / "repodata").iterdir(), key=lambda item: item.name):
        require(path.is_file() and not path.is_symlink() and path.stat().st_nlink == 1,
                "generated repodata contains a linked or special entry")
        relative = f"repodata/{path.name}"
        repodata_files.append(artifact(path, relative))
    return {
        "active": [post_entries[path] for path in active_paths],
        "new_unsigned_inputs": [
            {"path": path, **new_entries[path]} for path in sorted(new_entries)
        ],
        "newly_signed": [post_entries[path] for path in sorted(new_entries)],
        "preserved_signed": [post_entries[path] for path in sorted(signed_entries)],
        "repodata": repodata_files,
        "repository": rpm_relative.as_posix(),
        "retired": [post_entries[path] for path in sorted(set(all_entries) - active_set)],
    }


def prepare_roots(input_root: Path, output_root: Path) -> tuple[Path, Path]:
    try:
        source = input_root.resolve(strict=True)
    except OSError as error:
        raise FamilySigningError("input repository does not exist") from error
    require(source.is_dir() and not input_root.is_symlink(),
            "input repository must be a real directory")
    require(not os.path.lexists(output_root), "output repository already exists or is a link")
    output_parent = output_root.parent
    output_parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    parent = output_parent.resolve(strict=True)
    require(output_root.name not in {"", ".", ".."}
            and SAFE_COMPONENT_RE.fullmatch(output_root.name) is not None,
            "output repository name is unsafe")
    output = parent / output_root.name
    try:
        common = Path(os.path.commonpath((str(source), str(output))))
    except ValueError as error:
        raise FamilySigningError("input and output repositories are incompatible") from error
    require(common != source, "output repository must not be inside the input repository")
    return source, output


def sign_family(args: argparse.Namespace) -> dict[str, object]:
    source, output = prepare_roots(args.input_root, args.output_root)
    if args.family == "apt":
        require(args.apt_release is not None, "APT signing requires --apt-release")
        require(all(value is None for value in (
            args.rpm_repository, args.new_rpm_allowlist,
            args.signed_rpm_allowlist, args.active_rpm_allowlist,
        )), "APT signing forbids RPM-specific arguments")
    else:
        require(args.apt_release is None, "RPM signing forbids --apt-release")
        require(all(value is not None for value in (
            args.rpm_repository, args.new_rpm_allowlist,
            args.signed_rpm_allowlist, args.active_rpm_allowlist,
        )), "RPM signing requires its repository and three exact allowlists")

    stage = Path(tempfile.mkdtemp(prefix=f".{output.name}.{args.family}.tmp.", dir=output.parent))
    try:
        copy_tree_safely(source, stage)
        with validator.validated_signing_session(args) as session:
            family_receipt = (
                sign_apt(stage, args, session)
                if args.family == "apt"
                else sign_rpm(stage, args, session)
            )
            receipt = {
                "family": args.family,
                "key": session.receipt(),
                "result": family_receipt,
                "schema": "wukongim/package-family-signing-receipt/v1",
            }
        for directory, _, files in os.walk(stage):
            os.chmod(directory, 0o755)
            for name in files:
                os.chmod(Path(directory) / name, 0o644)
        require(not os.path.lexists(output), "output repository appeared during signing")
        os.replace(stage, output)
        return receipt
    except BaseException:
        if os.path.lexists(stage):
            shutil.rmtree(stage)
        raise


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Validate and atomically sign exactly one APT or RPM repository family."
    )
    parser.add_argument("--family", required=True, choices=("apt", "rpm"))
    parser.add_argument("--input-root", required=True, type=Path)
    parser.add_argument("--output-root", required=True, type=Path)
    parser.add_argument("--public-cert", required=True, type=Path)
    parser.add_argument("--secret-subkey-base64-env", required=True)
    parser.add_argument("--passphrase-env", required=True)
    parser.add_argument("--primary-fingerprint", required=True)
    parser.add_argument("--signing-subkey-fingerprint", required=True)
    parser.add_argument("--next-signing-subkey-fingerprint")
    parser.add_argument(
        "--historical-signing-subkey-fingerprint", action="append", default=[]
    )
    parser.add_argument("--minimum-valid-days", type=int, default=validator.POLICY_MINIMUM_VALID_DAYS)
    parser.add_argument("--rotation-begin-days", type=int, default=45)
    parser.add_argument("--maximum-lifetime-days", type=int,
                        default=validator.POLICY_MAXIMUM_LIFETIME_DAYS)
    parser.add_argument("--apt-release")
    parser.add_argument("--rpm-repository")
    parser.add_argument("--new-rpm-allowlist", type=Path)
    parser.add_argument("--signed-rpm-allowlist", type=Path)
    parser.add_argument("--active-rpm-allowlist", type=Path)
    parser.set_defaults(
        secret_subkey_base64_file=None,
        secret_subkey_base64_stdin=False,
        passphrase_file=None,
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        receipt = sign_family(args)
    except (FamilySigningError, validator.SigningMaterialError) as error:
        print(f"package-family signing failed: {error}", file=sys.stderr)
        return 1
    print(canonical_json(receipt).decode("utf-8"), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
