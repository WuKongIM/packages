#!/usr/bin/env python3
"""Inspect resolved source DEB/RPM metadata without installing or running payloads."""

from __future__ import annotations

import argparse
import importlib.util
import json
import importlib.util
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


# Reuse the source verifier's strict receipt and byte-closure boundary. Loading
# this reviewed sibling does not invoke GitHub or run attestation verification.
SPEC = importlib.util.spec_from_file_location(
    "source_attestations", Path(__file__).with_name("verify-source-attestations.py")
)
assert SPEC is not None and SPEC.loader is not None
SOURCE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SOURCE)
VerificationError = SOURCE.VerificationError
MAX_QUERY_BYTES = 4096
QUERY_TIMEOUT_SECONDS = 15


def _query(command: list[str], environment: dict[str, str], owned: Any = None) -> str:
    """Run only a fixed native metadata query, with no inherited credentials."""
    if owned is not None:
        runtime=_owned_runtime()
        result=runtime.run_fixed_process(command,env=environment,shared=owned,stdout_cap=MAX_QUERY_BYTES,
            timeout=min(QUERY_TIMEOUT_SECONDS,owned.remaining()))
        if result.returncode != 0:
            raise VerificationError('bounded metadata query failed')
        data=result.stdout
        if not data:
            raise VerificationError('metadata query output is empty')
        return data.decode('utf-8').rstrip('\n')
    with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors:
        try:
            result = subprocess.run(
                command, stdin=subprocess.DEVNULL, stdout=output, stderr=errors,
                env=environment, timeout=QUERY_TIMEOUT_SECONDS, check=False,
            )
        except FileNotFoundError as error:
            raise VerificationError(f"metadata inspector {command[0]} is unavailable") from error
        except subprocess.TimeoutExpired as error:
            raise VerificationError(f"metadata query {command[0]} exceeded its deadline") from error
        if result.returncode != 0:
            raise VerificationError(f"metadata query {command[0]} failed with exit {result.returncode}")
        output.seek(0)
        data = output.read(MAX_QUERY_BYTES + 1)
    if not data or len(data) > MAX_QUERY_BYTES:
        raise VerificationError("metadata query output is empty or exceeds its size limit")
    try:
        return data.decode("utf-8").rstrip("\n")
    except UnicodeDecodeError as error:
        raise VerificationError("metadata query output is not UTF-8") from error


def _expect(label: str, expected: str, actual: str) -> None:
    if expected != actual:
        raise VerificationError(f"{label} mismatch: expected {expected!r}, got {actual!r}")


def verify_metadata(receipt_path: Path, asset_dir: Path, channel: str, owned: Any = None) -> dict[str, Any]:
    """Bind metadata-only evidence to the same complete source receipt and bytes."""
    original = SOURCE._read_safe_json(receipt_path, "source receipt")
    receipt = SOURCE._validate_receipt(original, channel)
    SOURCE._validate_asset_directory(asset_dir, receipt["assets"])
    version = receipt["version"]
    core, separator, prerelease = version.partition("-")
    deb_version = f"{core}~{prerelease}" if separator else core
    rpm_version = deb_version.replace("-", "_")
    deb_name = f"wukongim_{version}_linux_amd64.deb"
    rpm_name = f"wukongim_{version}_linux_amd64.rpm"
    deb = str((asset_dir / deb_name).resolve(strict=True))
    rpm = str((asset_dir / rpm_name).resolve(strict=True))

    # A fresh home avoids user RPM configuration; only tool lookup and locale
    # survive into the inspector processes. No package payload is executed.
    with tempfile.TemporaryDirectory(prefix="wk-source-metadata-") as home:
        environment = {"PATH": os.environ.get("PATH", os.defpath), "HOME": home, "LC_ALL": "C"}
        for field, expected in (("Package", "wukongim"), ("Architecture", "amd64"),
                                ("Version", deb_version)):
            _expect(f"DEB {field}", expected,
                    _query(["dpkg-deb", "--field", deb, field], environment, owned))
        rpm_fields = (("NAME", "wukongim"), ("ARCH", "x86_64"),
                      ("VERSION", rpm_version), ("RELEASE", "1"), ("EPOCHNUM", "0"),
                      ("SIGPGP:pgpsig", "(none)"), ("SIGGPG:pgpsig", "(none)"),
                      ("RSAHEADER:pgpsig", "(none)"), ("DSAHEADER:pgpsig", "(none)"))
        for field, expected in rpm_fields:
            _expect(f"RPM {field}", expected,
                    _query(["rpm", "-qp", "--queryformat", f"%{{{field}}}", rpm], environment, owned))

    # Native inspectors run outside Python. Recheck all seven assets and the
    # original receipt after those subprocesses before emitting any success.
    SOURCE._validate_asset_directory(asset_dir, receipt["assets"])
    if SOURCE._read_safe_json(receipt_path, "source receipt") != original:
        raise VerificationError("source receipt changed during metadata inspection")

    def asset(name: str) -> dict[str, Any]:
        fact = receipt["assets"][name]
        return {key: fact[key] for key in ("id", "name", "size", "sha256")}

    return {
        "schema": "wukongim/source-package-metadata/v2",
        "channel": channel,
        "source": {"repository": SOURCE.SOURCE_REPOSITORY, "release_id": receipt["release_id"],
                   "tag": receipt["tag"], "source_sha": receipt["source_sha"]},
        "package": "wukongim",
        "version": version,
        "deb": {"asset": asset(deb_name), "version": deb_version, "architecture": "amd64"},
        "rpm": {"asset": asset(rpm_name), "version": rpm_version, "release": "1", "epoch": "0",
                "architecture": "x86_64", "signed": False},
        "assets_revalidated_after_metadata": True,
    }


def _owned_runtime():
    spec=importlib.util.spec_from_file_location('owned_runtime',Path(__file__).with_name('object-storage-owned-execution.py'))
    runtime=importlib.util.module_from_spec(spec);spec.loader.exec_module(runtime);return runtime


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--receipt", required=True, type=Path)
    parser.add_argument("--asset-dir", required=True, type=Path)
    parser.add_argument("--channel", choices=("preview", "stable"), default="preview",
                        help="expected source classification; does not enable publication")
    parser.add_argument('--owned-budget-fd',type=int)
    parser.add_argument('--owned-request-sha256')
    args = parser.parse_args()
    owned=_owned_runtime().helper_context(args.owned_budget_fd,args.owned_request_sha256)
    try:
        receipt = verify_metadata(args.receipt, args.asset_dir, args.channel, owned)
    except (VerificationError, OSError) as error:
        print(f"source package metadata verification failed: {error}", file=sys.stderr)
        return 1
    if owned is not None:
        owned.close()
    json.dump(receipt, sys.stdout, sort_keys=True, separators=(",", ":"))
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
