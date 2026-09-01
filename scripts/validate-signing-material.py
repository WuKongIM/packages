#!/usr/bin/env python3
"""Fail-closed validation for one APT or RPM OpenPGP signing subkey."""

from __future__ import annotations

import argparse
import base64
import binascii
import json
import os
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Sequence


FINGERPRINT_RE = re.compile(r"^[0-9A-F]{40}$")
ENVIRONMENT_NAME_RE = re.compile(r"^[A-Z_][A-Z0-9_]*$")
MAX_PUBLIC_CERT_BYTES = 1024 * 1024
MAX_SECRET_BASE64_BYTES = 2 * 1024 * 1024
MAX_PASSPHRASE_BYTES = 4096
POLICY_MINIMUM_VALID_DAYS = 30
POLICY_MAXIMUM_LIFETIME_DAYS = 180
BAD_VALIDITY = frozenset({"d", "e", "i", "r"})
KNOWN_COLON_RECORDS = frozenset(
    {"cfg", "fpr", "grp", "pub", "rev", "rvk", "sec", "ssb", "sub", "tru", "uat", "uid"}
)


class SigningMaterialError(ValueError):
    """Raised when signing material violates the reviewed custody contract."""


@dataclass(frozen=True)
class KeyRecord:
    record_type: str
    validity: str
    created: int
    expires: int | None
    capabilities: str
    secret_marker: str
    fingerprint: str


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SigningMaterialError(message)


def require_tool(name: str) -> str:
    path = shutil.which(name)
    require(path is not None, f"required OpenPGP tool is unavailable: {name}")
    return path


def checked_regular_file(
    path: Path,
    label: str,
    maximum_bytes: int,
    *,
    secret: bool,
    _after_lstat: Callable[[], None] | None = None,
) -> bytes:
    try:
        path_metadata = path.lstat()
    except OSError as error:
        raise SigningMaterialError(f"cannot inspect {label}") from error
    require(stat.S_ISREG(path_metadata.st_mode),
            f"{label} must be a regular file, not a link or special file")
    require(hasattr(os, "O_NOFOLLOW"), "platform must support O_NOFOLLOW for signer inputs")
    if _after_lstat is not None:
        _after_lstat()
    flags = os.O_RDONLY | os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise SigningMaterialError(f"cannot safely open {label}") from error
    try:
        metadata = os.fstat(descriptor)
        require(stat.S_ISREG(metadata.st_mode), f"{label} must remain a regular file")
        require((metadata.st_dev, metadata.st_ino) == (path_metadata.st_dev, path_metadata.st_ino),
                f"{label} changed while it was opened")
        require(metadata.st_size == path_metadata.st_size,
                f"{label} size changed while it was opened")
        require(metadata.st_nlink == 1, f"{label} must not be hard linked")
        require(0 < metadata.st_size <= maximum_bytes, f"{label} has an invalid size")
        if secret:
            require(metadata.st_mode & 0o077 == 0,
                    f"{label} permissions must not grant group or other access")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            contents = stream.read(maximum_bytes + 1)
        require(len(contents) == metadata.st_size, f"{label} changed while it was read")
        final_metadata = os.fstat(descriptor)
        require(
            (final_metadata.st_dev, final_metadata.st_ino, final_metadata.st_size)
            == (metadata.st_dev, metadata.st_ino, metadata.st_size),
            f"{label} changed while it was read",
        )
        return contents
    except OSError as error:
        raise SigningMaterialError(f"cannot safely read {label}") from error
    finally:
        os.close(descriptor)


def read_environment(name: str, label: str) -> bytes:
    require(ENVIRONMENT_NAME_RE.fullmatch(name) is not None, f"{label} environment name is invalid")
    value = os.environ.pop(name, None)
    require(value is not None, f"{label} environment variable is not set")
    try:
        return value.encode("utf-8")
    except UnicodeEncodeError as error:
        raise SigningMaterialError(f"{label} environment value is not valid UTF-8") from error


def read_secret_base64(args: argparse.Namespace) -> bytes:
    if args.secret_subkey_base64_file is not None:
        encoded = checked_regular_file(
            args.secret_subkey_base64_file,
            "base64 secret-subkey file",
            MAX_SECRET_BASE64_BYTES,
            secret=True,
        )
    elif args.secret_subkey_base64_env is not None:
        encoded = read_environment(args.secret_subkey_base64_env, "base64 secret-subkey")
    else:
        encoded = sys.stdin.buffer.read(MAX_SECRET_BASE64_BYTES + 1)
        require(len(encoded) <= MAX_SECRET_BASE64_BYTES, "base64 secret-subkey input is too large")
    encoded = encoded.strip()
    require(encoded != b"", "base64 secret-subkey input must not be empty")
    require(not any(byte in b" \t\r\n" for byte in encoded),
            "base64 secret-subkey input must be one canonical line")
    try:
        decoded = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError) as error:
        raise SigningMaterialError("secret-subkey input is not canonical base64") from error
    require(0 < len(decoded) <= MAX_PUBLIC_CERT_BYTES, "decoded secret-subkey material has an invalid size")
    return decoded


def read_passphrase(args: argparse.Namespace) -> bytes:
    if args.passphrase_file is not None:
        value = checked_regular_file(
            args.passphrase_file,
            "passphrase file",
            MAX_PASSPHRASE_BYTES,
            secret=True,
        )
        if value.endswith(b"\n"):
            value = value[:-1]
    else:
        value = read_environment(args.passphrase_env, "passphrase")
    require(0 < len(value) <= MAX_PASSPHRASE_BYTES, "passphrase has an invalid size")
    require(b"\x00" not in value and b"\r" not in value and b"\n" not in value,
            "passphrase must be a single non-empty line")
    return value


def parse_timestamp(value: str, label: str, *, optional: bool) -> int | None:
    if value == "" and optional:
        return None
    require(value.isascii() and value.isdigit(), f"{label} must be an integer timestamp")
    timestamp = int(value)
    require(timestamp > 0, f"{label} must be positive")
    return timestamp


def parse_colon_keys(output: bytes, *, allow_no_keys: bool = False) -> list[KeyRecord]:
    try:
        text = output.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise SigningMaterialError("GnuPG returned non-UTF-8 colon data") from error
    if text == "" and allow_no_keys:
        return []
    require(text.endswith("\n"), "GnuPG colon data must be line terminated")
    records: list[KeyRecord] = []
    pending: tuple[str, list[str]] | None = None
    for line in text.splitlines():
        require(line != "", "GnuPG colon data contains an empty record")
        fields = line.split(":")
        require(len(fields) >= 2, "GnuPG colon data contains a truncated record")
        record_type = fields[0]
        require(record_type in KNOWN_COLON_RECORDS,
                f"GnuPG colon data contains unsupported record type: {record_type}")
        if pending is not None:
            require(record_type == "fpr", "GnuPG key record is not followed by its fingerprint")
            require(len(fields) >= 10, "GnuPG fingerprint record is truncated")
            key_type, key_fields = pending
            fingerprint = fields[9]
            require(FINGERPRINT_RE.fullmatch(fingerprint) is not None,
                    "GnuPG returned a non-canonical key fingerprint")
            require(len(key_fields) >= 15, "GnuPG key record omits required secret-key fields")
            created = parse_timestamp(key_fields[5], "key creation", optional=False)
            assert created is not None
            records.append(
                KeyRecord(
                    record_type=key_type,
                    validity=key_fields[1],
                    created=created,
                    expires=parse_timestamp(key_fields[6], "key expiration", optional=True),
                    capabilities=key_fields[11],
                    secret_marker=key_fields[14],
                    fingerprint=fingerprint,
                )
            )
            pending = None
            continue
        if record_type in {"pub", "sub", "sec", "ssb"}:
            require(len(fields) >= 15, "GnuPG key record omits required fields")
            pending = (record_type, fields)
        elif record_type == "fpr":
            require(len(fields) >= 10, "GnuPG fingerprint record is truncated")
            raise SigningMaterialError("GnuPG returned an unbound fingerprint record")
    require(pending is None, "GnuPG colon data ends before a key fingerprint")
    require(allow_no_keys or records, "GnuPG colon data contains no keys")
    fingerprints = [record.fingerprint for record in records]
    require(len(fingerprints) == len(set(fingerprints)), "GnuPG returned duplicate key fingerprints")
    return records


class IsolatedGPG:
    def __init__(self, home: Path, gpg: str, gpgconf: str) -> None:
        self.home = home
        self.gpg = gpg
        self.gpgconf = gpgconf
        self.environment = {
            "GNUPGHOME": str(home),
            "HOME": str(home),
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        }

    def run(
        self,
        arguments: Sequence[str],
        *,
        stage: str,
        input_bytes: bytes | None = None,
        check: bool = True,
    ) -> subprocess.CompletedProcess[bytes]:
        command = [
            self.gpg,
            "--no-options",
            "--homedir",
            str(self.home),
            "--batch",
            "--no-tty",
            *arguments,
        ]
        result = subprocess.run(
            command,
            input=input_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=self.environment,
            check=False,
        )
        if check and result.returncode != 0:
            raise SigningMaterialError(f"OpenPGP command failed during {stage}")
        return result

    def kill_agent(self) -> None:
        subprocess.run(
            [self.gpgconf, "--homedir", str(self.home), "--kill", "gpg-agent"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=self.environment,
            check=False,
        )


def public_key_records(gpg: IsolatedGPG) -> list[KeyRecord]:
    result = gpg.run(
        [
            "--with-colons",
            "--fixed-list-mode",
            "--with-fingerprint",
            "--with-subkey-fingerprint",
            "--list-options",
            "show-unusable-subkeys",
            "--list-keys",
        ],
        stage="public-key inspection",
    )
    return parse_colon_keys(result.stdout)


def validate_public_key(
    records: list[KeyRecord],
    primary_fingerprint: str,
    signing_subkey_fingerprint: str,
    minimum_valid_days: int,
    maximum_lifetime_days: int,
    now: int,
) -> KeyRecord:
    primary_records = [record for record in records if record.record_type == "pub"]
    subkey_records = [record for record in records if record.record_type == "sub"]
    require(len(primary_records) == 1, "public certificate must contain exactly one primary key")
    require(len(subkey_records) == 1, "public certificate must contain exactly one subkey")
    primary = primary_records[0]
    require(
        primary.fingerprint == primary_fingerprint,
        "public primary fingerprint does not match reviewed control",
    )
    require("c" in primary.capabilities, "public primary key must have its own certify capability")
    require(not any(capability in primary.capabilities for capability in "sea"),
            "public primary key own capabilities must be certify-only")
    validate_usable(primary, "public primary key", minimum_valid_days, now, require_expiration=False)

    signing_subkey = subkey_records[0]
    require("s" in signing_subkey.capabilities,
            "public signing subkey must have its own signing capability")
    require(not any(capability in signing_subkey.capabilities for capability in "cea"),
            "public signing subkey must be sign-only")
    require(signing_subkey.fingerprint == signing_subkey_fingerprint,
            "public signing-subkey fingerprint does not match reviewed control")
    validate_usable(signing_subkey, "public signing subkey", minimum_valid_days, now,
                    require_expiration=True)
    assert signing_subkey.expires is not None
    require(signing_subkey.expires - signing_subkey.created <= maximum_lifetime_days * 86400,
            "public signing subkey lifetime exceeds reviewed policy")
    return signing_subkey


def validate_usable(
    record: KeyRecord,
    label: str,
    minimum_valid_days: int,
    now: int,
    *,
    require_expiration: bool,
) -> None:
    require(record.validity not in BAD_VALIDITY, f"{label} is revoked, disabled, expired, or invalid")
    require("D" not in record.capabilities, f"{label} is disabled")
    require(record.created <= now, f"{label} creation time is in the future")
    if require_expiration:
        require(record.expires is not None, f"{label} must have an expiration")
    if record.expires is not None:
        require(record.expires > now, f"{label} is expired")
        require(record.expires - now >= minimum_valid_days * 86400,
                f"{label} has less than the required remaining validity")


def secret_key_records(gpg: IsolatedGPG) -> list[KeyRecord]:
    result = gpg.run(
        [
            "--with-colons",
            "--fixed-list-mode",
            "--with-fingerprint",
            "--with-subkey-fingerprint",
            "--list-options",
            "show-unusable-subkeys",
            "--list-secret-keys",
        ],
        stage="secret-key inspection",
    )
    return parse_colon_keys(result.stdout)


def secret_key_records_before_import(gpg: IsolatedGPG) -> list[KeyRecord]:
    result = gpg.run(
        [
            "--with-colons",
            "--fixed-list-mode",
            "--with-fingerprint",
            "--with-subkey-fingerprint",
            "--list-secret-keys",
        ],
        stage="public-certificate secret-material check",
        check=False,
    )
    require(
        result.returncode in {0, 2},
        "OpenPGP command failed during public-certificate secret-material check",
    )
    return parse_colon_keys(result.stdout, allow_no_keys=True)


def public_topology(records: list[KeyRecord]) -> list[tuple[object, ...]]:
    return [
        (
            record.record_type,
            record.created,
            record.expires,
            record.capabilities,
            record.fingerprint,
        )
        for record in records
    ]


def validate_secret_key(
    records: list[KeyRecord], primary_fingerprint: str, signing_subkey_fingerprint: str
) -> None:
    primary_records = [record for record in records if record.record_type == "sec"]
    subkey_records = [record for record in records if record.record_type == "ssb"]
    require(len(primary_records) == 1, "secret material must correspond to exactly one primary certificate")
    primary = primary_records[0]
    require(primary.fingerprint == primary_fingerprint, "secret material primary fingerprint is unexpected")
    require(primary.secret_marker == "#", "secret material must not contain a private primary key")

    local_subkeys = [record for record in subkey_records if record.secret_marker in {"", "+"}]
    token_subkeys = [record for record in subkey_records if record.secret_marker not in {"", "+", "#"}]
    require(not token_subkeys, "secret material must contain a local encrypted subkey, not a token reference")
    require(len(local_subkeys) == 1, "secret material must contain exactly one private subkey")
    require(local_subkeys[0].fingerprint == signing_subkey_fingerprint,
            "secret material does not contain only the reviewed signing subkey")


def sign_and_verify(
    gpg: IsolatedGPG,
    passphrase: bytes,
    primary_fingerprint: str,
    signing_subkey_fingerprint: str,
) -> None:
    payload = gpg.home / "signing-material-proof.txt"
    signature = gpg.home / "signing-material-proof.sig"
    payload.write_bytes(b"WuKongIM OpenPGP signing-material proof\n")
    payload.chmod(0o600)
    common = [
        "--pinentry-mode",
        "loopback",
        "--passphrase-fd",
        "0",
        "--local-user",
        f"{signing_subkey_fingerprint}!",
        "--output",
        str(signature),
        "--detach-sign",
        str(payload),
    ]

    wrong = secrets.token_bytes(48).hex().encode("ascii")
    while wrong == passphrase:
        wrong = secrets.token_bytes(48).hex().encode("ascii")
    wrong_result = gpg.run(common, stage="secret-key protection check",
                           input_bytes=wrong + b"\n", check=False)
    require(wrong_result.returncode != 0, "secret signing subkey is not protected by the supplied passphrase")
    signature.unlink(missing_ok=True)
    gpg.kill_agent()

    gpg.run(common, stage="signing-subkey unlock proof", input_bytes=passphrase + b"\n")
    verify = gpg.run(
        ["--status-fd", "1", "--verify", str(signature), str(payload)],
        stage="signing-subkey signature verification",
    )
    valid_signatures: list[list[str]] = []
    for line in verify.stdout.decode("utf-8", errors="strict").splitlines():
        if line.startswith("[GNUPG:] VALIDSIG "):
            valid_signatures.append(line.split())
    require(len(valid_signatures) == 1, "proof signature did not produce exactly one VALIDSIG status")
    status = valid_signatures[0]
    require(len(status) >= 12, "proof signature VALIDSIG status is truncated")
    require(status[2] == signing_subkey_fingerprint, "proof signature used an unexpected signing subkey")
    require(status[-1] == primary_fingerprint, "proof signature belongs to an unexpected primary key")


def validate_material(args: argparse.Namespace) -> dict[str, object]:
    require(FINGERPRINT_RE.fullmatch(args.primary_fingerprint) is not None,
            "reviewed primary fingerprint must be uppercase 40-hex")
    require(FINGERPRINT_RE.fullmatch(args.signing_subkey_fingerprint) is not None,
            "reviewed signing-subkey fingerprint must be uppercase 40-hex")
    require(args.primary_fingerprint != args.signing_subkey_fingerprint,
            "primary and signing-subkey fingerprints must differ")
    require(args.minimum_valid_days >= POLICY_MINIMUM_VALID_DAYS,
            f"minimum_valid_days must be at least {POLICY_MINIMUM_VALID_DAYS}")
    require(0 < args.maximum_lifetime_days <= POLICY_MAXIMUM_LIFETIME_DAYS,
            f"maximum_lifetime_days must be at most {POLICY_MAXIMUM_LIFETIME_DAYS}")
    require(args.minimum_valid_days <= args.maximum_lifetime_days,
            "minimum_valid_days must not exceed maximum_lifetime_days")

    public_cert = checked_regular_file(
        args.public_cert, "public certificate", MAX_PUBLIC_CERT_BYTES, secret=False
    )
    secret_material = read_secret_base64(args)
    passphrase = read_passphrase(args)
    gpg_path = require_tool("gpg")
    gpgconf_path = require_tool("gpgconf")
    now = int(time.time())

    # A short base path avoids GnuPG agent socket-length failures on macOS while
    # TemporaryDirectory still creates an unpredictable mode-0700 child.
    temporary_base = "/tmp" if Path("/tmp").is_dir() else None
    with tempfile.TemporaryDirectory(
        prefix=f"wk-{args.family}-signer-", dir=temporary_base
    ) as directory:
        home = Path(directory)
        home.chmod(0o700)
        gpg = IsolatedGPG(home, gpg_path, gpgconf_path)
        try:
            public_path = home / "reviewed-public-cert.gpg"
            secret_path = home / "encrypted-secret-subkey.gpg"
            public_path.write_bytes(public_cert)
            public_path.chmod(0o600)
            secret_path.write_bytes(secret_material)
            secret_path.chmod(0o600)

            gpg.run(["--import-options", "import-minimal", "--import", str(public_path)],
                    stage="public-certificate import")
            public_before = public_key_records(gpg)
            signing_subkey = validate_public_key(
                public_before,
                args.primary_fingerprint,
                args.signing_subkey_fingerprint,
                args.minimum_valid_days,
                args.maximum_lifetime_days,
                now,
            )
            require(not secret_key_records_before_import(gpg),
                    "public certificate must not contain secret key material")

            gpg.run(["--import-options", "import-minimal", "--import", str(secret_path)],
                    stage="secret-subkey import")
            validate_secret_key(
                secret_key_records(gpg),
                args.primary_fingerprint,
                args.signing_subkey_fingerprint,
            )
            public_after = public_key_records(gpg)
            require(public_topology(public_after) == public_topology(public_before),
                    "secret material changed the reviewed public certificate topology")
            validate_public_key(
                public_after,
                args.primary_fingerprint,
                args.signing_subkey_fingerprint,
                args.minimum_valid_days,
                args.maximum_lifetime_days,
                now,
            )
            sign_and_verify(
                gpg,
                passphrase,
                args.primary_fingerprint,
                args.signing_subkey_fingerprint,
            )
        finally:
            gpg.kill_agent()

    assert signing_subkey.expires is not None
    return {
        "schema": "wukongim/openpgp-signing-material-validation/v1",
        "family": args.family,
        "primary_fingerprint": args.primary_fingerprint,
        "signing_subkey_fingerprint": args.signing_subkey_fingerprint,
        "minimum_valid_days": args.minimum_valid_days,
        "maximum_lifetime_days": args.maximum_lifetime_days,
        "signing_subkey_created": datetime.fromtimestamp(
            signing_subkey.created, timezone.utc
        ).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "signing_subkey_expires": datetime.fromtimestamp(
            signing_subkey.expires, timezone.utc
        ).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "validated": True,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Validate one fail-closed APT or RPM encrypted OpenPGP signing subkey."
    )
    parser.add_argument("--family", required=True, choices=("apt", "rpm"))
    parser.add_argument("--public-cert", required=True, type=Path)
    secret_group = parser.add_mutually_exclusive_group(required=True)
    secret_group.add_argument("--secret-subkey-base64-file", type=Path)
    secret_group.add_argument("--secret-subkey-base64-env")
    secret_group.add_argument("--secret-subkey-base64-stdin", action="store_true")
    passphrase_group = parser.add_mutually_exclusive_group(required=True)
    passphrase_group.add_argument("--passphrase-file", type=Path)
    passphrase_group.add_argument("--passphrase-env")
    parser.add_argument("--primary-fingerprint", required=True)
    parser.add_argument("--signing-subkey-fingerprint", required=True)
    parser.add_argument("--minimum-valid-days", type=int, default=POLICY_MINIMUM_VALID_DAYS)
    parser.add_argument("--maximum-lifetime-days", type=int, default=POLICY_MAXIMUM_LIFETIME_DAYS)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        receipt = validate_material(args)
    except SigningMaterialError as error:
        print(f"OpenPGP signing material validation failed: {error}", file=sys.stderr)
        return 1
    json.dump(receipt, sys.stdout, sort_keys=True, separators=(",", ":"))
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
