from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import unittest
from contextlib import contextmanager
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any, Iterator


ROOT = Path(__file__).resolve().parents[1]
VALIDATOR = ROOT / "scripts" / "validate-control.py"


def preview_release(
    *,
    version: str = "3.1.0-rc.1",
    state: str = "active",
    not_before: str | None = None,
) -> dict[str, Any]:
    return {
        "version": version,
        "source_sha": "1" * 40,
        "source_release_id": 1001,
        "package_release_id": 2001,
        "deb_sha256": "2" * 64,
        "rpm_sha256": "3" * 64,
        "state": state,
        "not_before": not_before,
    }


@contextmanager
def copied_control_root() -> Iterator[Path]:
    with TemporaryDirectory() as temporary:
        root = Path(temporary)
        for relative in ("keys", "manifests", "site"):
            shutil.copytree(ROOT / relative, root / relative)
        yield root


def load_manifest(root: Path, name: str) -> dict[str, Any]:
    return json.loads((root / "manifests" / name).read_text(encoding="utf-8"))


def write_manifest(root: Path, name: str, value: dict[str, Any]) -> None:
    (root / "manifests" / name).write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def run_gpg(home: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            "gpg",
            "--batch",
            "--no-options",
            "--homedir",
            str(home),
            "--pinentry-mode",
            "loopback",
            "--passphrase",
            "",
            *arguments,
        ],
        check=True,
        capture_output=True,
        text=True,
    )


def generate_signing_certificate(
    family: str,
    *,
    subkey_usage: str = "sign",
) -> tuple[str, str, str, str]:
    with TemporaryDirectory() as temporary:
        home = Path(temporary)
        os.chmod(home, 0o700)
        identity = f"WuKongIM {family.upper()} Preview Test <{family}@example.invalid>"
        run_gpg(home, "--quick-generate-key", identity, "rsa2048", "cert", "90d")
        initial = run_gpg(home, "--with-colons", "--fingerprint", identity)
        primary_fingerprint = next(
            line.split(":")[9]
            for line in initial.stdout.splitlines()
            if line.startswith("fpr:")
        )
        run_gpg(
            home,
            "--quick-add-key",
            primary_fingerprint,
            "rsa2048",
            subkey_usage,
            "90d",
        )
        listing = run_gpg(
            home,
            "--with-colons",
            "--fingerprint",
            "--fingerprint",
            primary_fingerprint,
        )
        fingerprints = [
            line.split(":")[9]
            for line in listing.stdout.splitlines()
            if line.startswith("fpr:")
        ]
        if len(fingerprints) != 2:
            raise AssertionError(f"expected primary and subkey fingerprints: {listing.stdout}")
        public_certificate = run_gpg(home, "--armor", "--export", primary_fingerprint).stdout
        secret_certificate = run_gpg(
            home, "--armor", "--export-secret-keys", primary_fingerprint
        ).stdout
        return fingerprints[0], fingerprints[1], public_certificate, secret_certificate


def enable_signing(
    root: Path,
    *,
    apt_subkey_usage: str = "sign",
) -> dict[str, str]:
    channels = load_manifest(root, "channels.json")
    preview = channels["channels"]["preview"]
    preview["enabled"] = True
    preview["status"] = "ready"
    preview["releases"] = [preview_release()]
    write_manifest(root, "channels.json", channels)

    signing = load_manifest(root, "preview-signing.json")
    signing["enabled"] = True
    secret_certificates: dict[str, str] = {}
    for family in ("apt", "rpm"):
        primary, subkey, public_certificate, secret_certificate = (
            generate_signing_certificate(
                family,
                subkey_usage=apt_subkey_usage if family == "apt" else "sign",
            )
        )
        signing[family]["primary_fingerprint"] = primary
        signing[family]["signing_subkey_fingerprint"] = subkey
        (root / signing[family]["public_key"]).write_text(
            public_certificate,
            encoding="ascii",
        )
        secret_certificates[family] = secret_certificate
    write_manifest(root, "preview-signing.json", signing)
    return secret_certificates


class ValidateControlTest(unittest.TestCase):
    def run_validator(self, root: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(VALIDATOR), "--root", str(root)],
            check=False,
            capture_output=True,
            text=True,
        )

    def assert_rejected(self, root: Path, diagnostic: str) -> None:
        result = self.run_validator(root)
        self.assertNotEqual(0, result.returncode, result.stdout)
        self.assertIn(diagnostic, result.stderr)
        self.assertNotIn("publication control validation passed", result.stdout)

    def test_rejects_duplicate_json_key(self) -> None:
        with copied_control_root() as root:
            path = root / "manifests" / "channels.json"
            original = path.read_text(encoding="utf-8")
            path.write_text(
                '{\n  "schema": "duplicate",' + original.lstrip()[1:],
                encoding="utf-8",
            )

            self.assert_rejected(root, "duplicate JSON key: schema")

    def test_rejects_stable_or_malformed_preview_version(self) -> None:
        cases = (
            ("3.1.0", "strict prerelease SemVer"),
            ("3.1.0-rc.01", "strict prerelease SemVer"),
            ("3.1.0-rc..1", "strict prerelease SemVer"),
            ("v3.1.0-rc.1", "strict prerelease SemVer"),
            ("3.1.0-rc.1+build.1", "strict prerelease SemVer"),
        )
        for version, diagnostic in cases:
            with self.subTest(version=version), copied_control_root() as root:
                channels = load_manifest(root, "channels.json")
                channels["channels"]["preview"]["releases"] = [
                    preview_release(version=version)
                ]
                write_manifest(root, "channels.json", channels)

                self.assert_rejected(root, diagnostic)

    def test_rejects_reused_fingerprints_when_signing_is_enabled(self) -> None:
        with copied_control_root() as root:
            channels = load_manifest(root, "channels.json")
            preview = channels["channels"]["preview"]
            preview["enabled"] = True
            preview["status"] = "ready"
            preview["releases"] = [preview_release()]
            write_manifest(root, "channels.json", channels)

            signing = load_manifest(root, "preview-signing.json")
            signing["enabled"] = True
            for family in ("apt", "rpm"):
                signing[family]["primary_fingerprint"] = "A" * 40
                signing[family]["signing_subkey_fingerprint"] = "A" * 40
                (root / signing[family]["public_key"]).write_text(
                    f"{family} public key fixture\n",
                    encoding="utf-8",
                )
            write_manifest(root, "preview-signing.json", signing)

            self.assert_rejected(
                root,
                "APT and RPM primary and signing-subkey fingerprints must all be distinct",
            )

    def test_rejects_extra_binary_key_file_while_signing_is_disabled(self) -> None:
        with copied_control_root() as root:
            (root / "keys" / "unarmored-secret-subkey.gpg").write_bytes(
                b"\x95\x01\x02binary-secret-key-packet\n"
            )

            self.assert_rejected(
                root,
                "keys directory entries must be exactly ['README.md']",
            )

    def test_rejects_readme_directory_hiding_binary_key_material(self) -> None:
        with copied_control_root() as root:
            readme = root / "keys" / "README.md"
            readme.unlink()
            readme.mkdir()
            (readme / "unarmored-secret-subkey.gpg").write_bytes(
                b"\x95\x01\x02binary-secret-key-packet\n"
            )

            self.assert_rejected(
                root,
                "keys/README.md must be a single-link regular file",
            )

    def test_accepts_reviewed_public_certificates_when_signing_is_enabled(self) -> None:
        with copied_control_root() as root:
            enable_signing(root)

            result = self.run_validator(root)

            self.assertEqual(0, result.returncode, result.stderr)
            self.assertIn("publication control validation passed", result.stdout)

    def test_rejects_secret_key_packets_disguised_as_public_certificate(self) -> None:
        with copied_control_root() as root:
            secret_certificates = enable_signing(root)
            disguised = secret_certificates["apt"].replace(
                "BEGIN PGP PRIVATE KEY BLOCK", "BEGIN PGP PUBLIC KEY BLOCK"
            ).replace(
                "END PGP PRIVATE KEY BLOCK", "END PGP PUBLIC KEY BLOCK"
            )
            (root / "keys" / "apt-preview.asc").write_text(
                disguised,
                encoding="ascii",
            )

            self.assert_rejected(
                root,
                "apt-preview.asc must not contain OpenPGP secret-key packets",
            )

    def test_rejects_signing_subkey_with_encryption_capability(self) -> None:
        with copied_control_root() as root:
            enable_signing(root, apt_subkey_usage="sign,encr")

            self.assert_rejected(
                root,
                "apt-preview.asc reviewed subkey must be sign-only",
            )

    def test_rejects_inconsistent_second_stage_retirement_fields(self) -> None:
        removed_at = "2026-10-01T00:00:00Z"
        cases = (
            ("version", "3.1.0-rc.2", "retirement.version must match"),
            ("not_before", "2026-10-02T00:00:00Z", "retirement.not_before must match"),
        )
        for field, value, diagnostic in cases:
            with self.subTest(field=field), copied_control_root() as root:
                channels = load_manifest(root, "channels.json")
                preview = channels["channels"]["preview"]
                preview["releases"] = [
                    preview_release(state="index_removed", not_before=removed_at)
                ]
                preview["retirement"] = {
                    "phase": "indexes_removed",
                    "version": "3.1.0-rc.1",
                    "not_before": removed_at,
                }
                preview["retirement"][field] = value
                write_manifest(root, "channels.json", channels)

                self.assert_rejected(root, diagnostic)

    def test_rejects_extra_tracked_site_file(self) -> None:
        with copied_control_root() as root:
            (root / "site" / "unexpected.txt").write_text("unexpected\n", encoding="utf-8")

            self.assert_rejected(
                root,
                "tracked site must contain only the bootstrap index.html and status.json",
            )

    def test_rejects_private_key_block_in_site(self) -> None:
        with copied_control_root() as root:
            index = root / "site" / "index.html"
            index.write_text(
                index.read_text(encoding="utf-8")
                + "\n-----BEGIN PRIVATE KEY-----\nforbidden\n",
                encoding="utf-8",
            )

            self.assert_rejected(root, "private key material is forbidden: site/index.html")

    def test_rejects_stable_publication_on_pages(self) -> None:
        with copied_control_root() as root:
            channels = load_manifest(root, "channels.json")
            channels["channels"]["stable"]["enabled"] = True
            write_manifest(root, "channels.json", channels)

            self.assert_rejected(root, "stable publishing must remain disabled on GitHub Pages")


if __name__ == "__main__":
    unittest.main()
