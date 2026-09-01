from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import unittest
from contextlib import contextmanager
from functools import lru_cache
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any, Iterator


ROOT = Path(__file__).resolve().parents[1]
VALIDATOR = ROOT / "scripts" / "validate-control.py"


def preview_release(
    *,
    version: str = "3.1.0-rc.1",
    source_sha: str = "1" * 40,
    source_release_id: int = 1001,
    package_release_id: int = 2001,
    deb_sha256: str = "2" * 64,
    rpm_sha256: str = "3" * 64,
    state: str = "active",
    not_before: str | None = None,
) -> dict[str, Any]:
    return {
        "version": version,
        "source_sha": source_sha,
        "source_release_id": source_release_id,
        "package_release_id": package_release_id,
        "deb_sha256": deb_sha256,
        "rpm_sha256": rpm_sha256,
        "state": state,
        "not_before": not_before,
    }


def publication(
    operation: str = "none",
    *,
    audit_release_id: int | None = None,
    base_audit_release_id: int | None = None,
    target_version: str | None = None,
) -> dict[str, Any]:
    return {
        "audit_release_id": audit_release_id,
        "base_audit_release_id": base_audit_release_id,
        "operation": operation,
        "target_version": target_version,
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


def write_bootstrap_reason(root: Path, reason: str) -> None:
    status = json.loads((root / "site" / "status.json").read_text(encoding="utf-8"))
    status["reason"] = reason
    (root / "site" / "status.json").write_text(
        json.dumps(status, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def configure_ready_preview(
    root: Path,
    releases: list[dict[str, Any]],
    requested_publication: dict[str, Any],
    *,
    retirement: dict[str, Any] | None = None,
) -> None:
    channels = load_manifest(root, "channels.json")
    preview = channels["channels"]["preview"]
    preview["enabled"] = True
    preview["status"] = "ready"
    preview["releases"] = releases
    preview["publication"] = requested_publication
    preview["retirement"] = retirement or {
        "phase": "none",
        "version": None,
        "not_before": None,
    }
    write_manifest(root, "channels.json", channels)
    write_bootstrap_reason(root, "ready")


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


@lru_cache(maxsize=None)
def generate_signing_certificate(
    family: str,
    *,
    key_algorithm: str,
    subkey_usage: str = "sign",
    next_expiration: str = "180d",
    historical_expiration: str | None = None,
) -> tuple[str, str, str, str | None, str, str]:
    with TemporaryDirectory() as temporary:
        home = Path(temporary)
        os.chmod(home, 0o700)
        identity = f"WuKongIM {family.upper()} Preview Test <{family}@example.invalid>"
        run_gpg(home, "--quick-generate-key", identity, key_algorithm, "cert", "90d")
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
            key_algorithm,
            subkey_usage,
            "90d",
        )
        run_gpg(
            home,
            "--quick-add-key",
            primary_fingerprint,
            key_algorithm,
            "sign",
            next_expiration,
        )
        if historical_expiration is not None:
            run_gpg(
                home,
                "--quick-add-key",
                primary_fingerprint,
                key_algorithm,
                "sign",
                historical_expiration,
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
        expected_count = 4 if historical_expiration is not None else 3
        if len(fingerprints) != expected_count:
            raise AssertionError(
                f"expected primary and reviewed subkey fingerprints: {listing.stdout}"
            )
        public_certificate = run_gpg(home, "--armor", "--export", primary_fingerprint).stdout
        secret_certificate = run_gpg(
            home, "--armor", "--export-secret-keys", primary_fingerprint
        ).stdout
        historical = fingerprints[3] if historical_expiration is not None else None
        return (
            fingerprints[0], fingerprints[1], fingerprints[2], historical,
            public_certificate, secret_certificate,
        )


def enable_signing(
    root: Path,
    *,
    apt_subkey_usage: str = "sign",
    apt_next_expiration: str = "180d",
    apt_historical_expiration: str | None = None,
    rpm_key_algorithm: str = "rsa3072",
    preview_ready: bool = False,
) -> dict[str, str]:
    channels = load_manifest(root, "channels.json")
    preview = channels["channels"]["preview"]
    preview["enabled"] = preview_ready
    preview["status"] = "ready" if preview_ready else "awaiting_first_release"
    preview["releases"] = [preview_release()] if preview_ready else []
    if preview_ready:
        preview["publication"] = publication(
            "add_release",
            audit_release_id=2001,
            target_version="3.1.0-rc.1",
        )
    write_manifest(root, "channels.json", channels)
    write_bootstrap_reason(root, preview["status"])

    signing = load_manifest(root, "preview-signing.json")
    signing["enabled"] = True
    secret_certificates: dict[str, str] = {}
    for family in ("apt", "rpm"):
        primary, current, next_subkey, historical, public_certificate, secret_certificate = (
            generate_signing_certificate(
                family,
                key_algorithm="rsa2048" if family == "apt" else rpm_key_algorithm,
                subkey_usage=apt_subkey_usage if family == "apt" else "sign",
                next_expiration=apt_next_expiration if family == "apt" else "180d",
                historical_expiration=(
                    apt_historical_expiration if family == "apt" else None
                ),
            )
        )
        signing[family]["primary_fingerprint"] = primary
        signing[family]["signing_subkeys"] = {
            "current": current,
            "next": next_subkey,
            "historical": [historical] if historical is not None else [],
        }
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

    def test_accepts_exact_enabled_audit_access_boundary(self) -> None:
        with copied_control_root() as root:
            audit_access = load_manifest(root, "audit-access.json")
            self.assertIs(audit_access["enabled"], True)

            result = self.run_validator(root)

            self.assertEqual(0, result.returncode, result.stderr)
            self.assertIn("publication control validation passed", result.stdout)

    def test_rejects_unreviewed_or_shared_audit_access_controls(self) -> None:
        cases = (
            (
                "extra field",
                lambda value: value.update({"unexpected": True}),
                "audit-access manifest fields must be exactly",
            ),
            (
                "non-boolean enablement",
                lambda value: value.update({"enabled": "false"}),
                "audit-access enabled must be boolean",
            ),
            (
                "reader environment",
                lambda value: value["reader"].update(
                    {"environment": "native-package-preview-audit"}
                ),
                "audit-access reader environment must be",
            ),
            (
                "reader contents permission",
                lambda value: value["reader"]["permissions"].update(
                    {"contents": "read"}
                ),
                "audit-access reader permissions fields must be exactly",
            ),
            (
                "writer read-only contents",
                lambda value: value["writer"]["permissions"].update(
                    {"contents": "read"}
                ),
                "writer App permissions must be Administration read and Contents write",
            ),
            (
                "wrong repository",
                lambda value: value["reader"].update(
                    {"repositories": ["WuKongIM"]}
                ),
                "reader App must be limited to WuKongIM/packages",
            ),
            (
                "shared source private key secret",
                lambda value: value["reader"].update(
                    {"app_private_key_secret": "WK_SOURCE_READ_APP_PRIVATE_KEY"}
                ),
                "secret names must all be distinct",
            ),
        )
        for name, mutate, diagnostic in cases:
            with self.subTest(case=name), copied_control_root() as root:
                audit_access = load_manifest(root, "audit-access.json")
                mutate(audit_access)
                write_manifest(root, "audit-access.json", audit_access)

                self.assert_rejected(root, diagnostic)

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
            preview["publication"] = publication(
                "add_release",
                audit_release_id=2001,
                target_version="3.1.0-rc.1",
            )
            write_manifest(root, "channels.json", channels)

            signing = load_manifest(root, "preview-signing.json")
            signing["enabled"] = True
            for family in ("apt", "rpm"):
                signing[family]["primary_fingerprint"] = "A" * 40
                signing[family]["signing_subkeys"] = {
                    "current": "A" * 40,
                    "next": "A" * 40,
                    "historical": [],
                }
                (root / signing[family]["public_key"]).write_text(
                    f"{family} public key fixture\n",
                    encoding="utf-8",
                )
            write_manifest(root, "preview-signing.json", signing)

            self.assert_rejected(
                root,
                "signing.apt fingerprints must all be distinct",
            )

    def test_rejects_extra_binary_key_file_while_signing_is_disabled(self) -> None:
        with copied_control_root() as root:
            signing = load_manifest(root, "preview-signing.json")
            signing["enabled"] = False
            for family in ("apt", "rpm"):
                (root / signing[family]["public_key"]).unlink()
                signing[family]["primary_fingerprint"] = None
                signing[family]["signing_subkeys"] = {
                    "current": None,
                    "next": None,
                    "historical": [],
                }
            write_manifest(root, "preview-signing.json", signing)

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

    def test_rejects_non_rsa_rpm_public_certificate(self) -> None:
        with copied_control_root() as root:
            enable_signing(root, rpm_key_algorithm="ed25519")

            self.assert_rejected(root, "public-key algorithm 1 (RSA)")

    def test_rejects_rsa2048_rpm_public_certificate(self) -> None:
        with copied_control_root() as root:
            enable_signing(root, rpm_key_algorithm="rsa2048")

            self.assert_rejected(root, "RSA key must be exactly 3072 or 4096 bits")

    def test_accepts_ready_preview_after_signing_is_provisioned(self) -> None:
        with copied_control_root() as root:
            enable_signing(root, preview_ready=True)

            result = self.run_validator(root)

            self.assertEqual(0, result.returncode, result.stderr)

    def test_rejects_shared_or_renamed_signing_environment(self) -> None:
        cases = (
            ("apt", "native-package-preview-signing"),
            ("rpm", "native-package-preview-apt-signing"),
        )
        for family, environment in cases:
            with self.subTest(family=family), copied_control_root() as root:
                signing = load_manifest(root, "preview-signing.json")
                signing[family]["environment"] = environment
                write_manifest(root, "preview-signing.json", signing)

                self.assert_rejected(
                    root,
                    f"signing.{family}.environment must be native-package-preview-{family}-signing",
                )

    def test_rejects_bootstrap_reason_that_does_not_match_preview_state(self) -> None:
        with copied_control_root() as root:
            enable_signing(root)
            write_bootstrap_reason(root, "signing_not_provisioned")

            self.assert_rejected(
                root,
                "bootstrap status must match the reviewed preview status",
            )

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
                "must be sign-only",
            )

    def test_rejects_next_subkey_without_rotation_runway(self) -> None:
        with copied_control_root() as root:
            enable_signing(root, apt_next_expiration="100d")

            self.assert_rejected(
                root,
                "next signing subkey does not extend the rotation runway",
            )

    def test_accepts_still_valid_former_current_as_historical(self) -> None:
        with copied_control_root() as root:
            enable_signing(root, apt_historical_expiration="60d")

            result = self.run_validator(root)

            self.assertEqual(0, result.returncode, result.stderr)

    def test_rejects_historical_subkey_that_expires_after_current(self) -> None:
        with copied_control_root() as root:
            enable_signing(root, apt_historical_expiration="120d")

            self.assert_rejected(root, "historical signing subkey expires after the current")

    def test_rejects_distinct_fingerprints_with_colliding_key_ids(self) -> None:
        with copied_control_root() as root:
            enable_signing(root)
            signing = load_manifest(root, "preview-signing.json")
            apt_current = signing["apt"]["signing_subkeys"]["current"]
            signing["rpm"]["signing_subkeys"]["next"] = "0" * 24 + apt_current[-16:]
            write_manifest(root, "preview-signing.json", signing)

            self.assert_rejected(root, "globally distinct 16-hex key IDs")

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

    def test_accepts_each_reviewed_publication_operation_shape(self) -> None:
        removed_at = "2026-10-01T00:00:00Z"
        first = preview_release()
        second = preview_release(
            version="3.1.0-rc.2",
            source_sha="4" * 40,
            source_release_id=1002,
            package_release_id=2002,
            deb_sha256="5" * 64,
            rpm_sha256="6" * 64,
        )
        removed_first = {**first, "state": "index_removed", "not_before": removed_at}
        cases = (
            (
                "add_first_release",
                [first],
                publication(
                    "add_release",
                    audit_release_id=2001,
                    target_version="3.1.0-rc.1",
                ),
                None,
            ),
            (
                "add_later_release",
                [first, second],
                publication(
                    "add_release",
                    audit_release_id=2002,
                    base_audit_release_id=2001,
                    target_version="3.1.0-rc.2",
                ),
                None,
            ),
            (
                "remove_indexes",
                [removed_first, second],
                publication(
                    "remove_indexes",
                    audit_release_id=3001,
                    base_audit_release_id=2002,
                    target_version="3.1.0-rc.1",
                ),
                {
                    "phase": "indexes_removed",
                    "version": "3.1.0-rc.1",
                    "not_before": removed_at,
                },
            ),
            (
                "remove_payloads",
                [second],
                publication(
                    "remove_payloads",
                    audit_release_id=3002,
                    base_audit_release_id=3001,
                    target_version="3.1.0-rc.1",
                ),
                None,
            ),
        )
        with copied_control_root() as root:
            enable_signing(root)
            for name, releases, requested_publication, retirement in cases:
                with self.subTest(operation=name):
                    configure_ready_preview(
                        root,
                        releases,
                        requested_publication,
                        retirement=retirement,
                    )
                    result = self.run_validator(root)
                    self.assertEqual(0, result.returncode, result.stderr)

    def test_rejects_malformed_publication_operations(self) -> None:
        removed_at = "2026-10-01T00:00:00Z"
        first = preview_release()
        second = preview_release(
            version="3.1.0-rc.2",
            source_sha="4" * 40,
            source_release_id=1002,
            package_release_id=2002,
            deb_sha256="5" * 64,
            rpm_sha256="6" * 64,
        )
        removed_first = {**first, "state": "index_removed", "not_before": removed_at}
        indexed_retirement = {
            "phase": "indexes_removed",
            "version": "3.1.0-rc.1",
            "not_before": removed_at,
        }
        cases = (
            (
                "none_with_release",
                [first],
                publication(),
                None,
                "publication none requires no releases or retirement",
            ),
            (
                "none_with_id",
                [first],
                publication(audit_release_id=2001),
                None,
                "publication none requires null",
            ),
            (
                "first_add_with_base",
                [first],
                publication(
                    "add_release",
                    audit_release_id=2001,
                    base_audit_release_id=1999,
                    target_version="3.1.0-rc.1",
                ),
                None,
                "first add_release requires a null base_audit_release_id",
            ),
            (
                "add_with_wrong_audit",
                [first],
                publication(
                    "add_release",
                    audit_release_id=2999,
                    target_version="3.1.0-rc.1",
                ),
                None,
                "audit_release_id must match the target package_release_id",
            ),
            (
                "later_add_without_base",
                [first, second],
                publication(
                    "add_release",
                    audit_release_id=2002,
                    target_version="3.1.0-rc.2",
                ),
                None,
                "base_audit_release_id must be a positive integer",
            ),
            (
                "remove_indexes_wrong_target",
                [removed_first, second],
                publication(
                    "remove_indexes",
                    audit_release_id=3001,
                    base_audit_release_id=2002,
                    target_version="3.1.0-rc.2",
                ),
                indexed_retirement,
                "remove_indexes target must be exactly one index_removed preview release",
            ),
            (
                "remove_payloads_still_present",
                [first, second],
                publication(
                    "remove_payloads",
                    audit_release_id=3002,
                    base_audit_release_id=3001,
                    target_version="3.1.0-rc.1",
                ),
                None,
                "remove_payloads target must be absent from preview releases",
            ),
            (
                "reused_audit_id",
                [second],
                publication(
                    "remove_payloads",
                    audit_release_id=3001,
                    base_audit_release_id=3001,
                    target_version="3.1.0-rc.1",
                ),
                None,
                "publication audit and base audit Release IDs must differ",
            ),
            (
                "invalid_target_version",
                [first],
                publication(
                    "add_release",
                    audit_release_id=2001,
                    target_version="v3.1.0-rc.1",
                ),
                None,
                "target_version must be strict prerelease SemVer",
            ),
        )
        for name, releases, requested_publication, retirement, diagnostic in cases:
            with self.subTest(operation=name), copied_control_root() as root:
                configure_ready_preview(
                    root,
                    releases,
                    requested_publication,
                    retirement=retirement,
                )
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

    def test_accepts_digest_pinned_signing_toolchain(self) -> None:
        with copied_control_root() as root:
            toolchain = load_manifest(root, "signing-toolchain.json")
            toolchain.update({
                "enabled": True,
                "digest": "sha256:" + "a" * 64,
                "workflow_sha": "b" * 40,
            })
            write_manifest(root, "signing-toolchain.json", toolchain)

            result = self.run_validator(root)

            self.assertEqual(0, result.returncode, result.stderr)

    def test_rejects_unreviewed_signing_toolchain_controls(self) -> None:
        cases = (
            (
                "renamed_image",
                {"image": "ghcr.io/wukongim/other"},
                "signing toolchain.image must be ghcr.io/wukongim/native-package-signing-toolchain",
            ),
            (
                "disabled_with_digest",
                {"digest": "sha256:" + "a" * 64},
                "disabled signing toolchain requires null digest and workflow_sha",
            ),
            (
                "enabled_without_digest",
                {"enabled": True, "workflow_sha": "b" * 40},
                "enabled signing toolchain.digest must be sha256:<64 lowercase hex>",
            ),
            (
                "enabled_with_tag_like_digest",
                {"enabled": True, "digest": "latest", "workflow_sha": "b" * 40},
                "enabled signing toolchain.digest must be sha256:<64 lowercase hex>",
            ),
            (
                "enabled_without_workflow_sha",
                {"enabled": True, "digest": "sha256:" + "a" * 64},
                "enabled signing toolchain.workflow_sha must be a lowercase 40-hex commit",
            ),
        )
        for name, changes, diagnostic in cases:
            with self.subTest(case=name), copied_control_root() as root:
                toolchain = load_manifest(root, "signing-toolchain.json")
                toolchain.update({
                    "enabled": False,
                    "digest": None,
                    "workflow_sha": None,
                })
                toolchain.update(changes)
                write_manifest(root, "signing-toolchain.json", toolchain)

                self.assert_rejected(root, diagnostic)


if __name__ == "__main__":
    unittest.main()
