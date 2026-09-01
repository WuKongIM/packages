from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
import json
import os
import tarfile
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "package-audit-receipt.py"
SPEC = importlib.util.spec_from_file_location("package_audit_receipt", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
receipt_module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(receipt_module)

AUDIT_ID = 42
CONTROL_SHA = "1" * 40
VERSION = "3.1.0-rc.1"
APT_PRIMARY = "A" * 40
APT_SUBKEY = "B" * 40
APT_NEXT = "E" * 40
RPM_PRIMARY = "C" * 40
RPM_SUBKEY = "D" * 40
RPM_NEXT = "F" * 40
APT_HISTORICAL = "7" * 40


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"


def artifact(path: Path, relative: str) -> dict[str, object]:
    data = path.read_bytes()
    return {
        "path": relative,
        "sha256": hashlib.sha256(data).hexdigest(),
        "size": len(data),
    }


class PackageAuditReceiptTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.snapshot_root = self.root / "snapshot-root"
        self.site = self.snapshot_root / "site"
        self.audit = self.snapshot_root / "audit"
        self.audit.mkdir(parents=True)
        self.channels_path = self.root / "channels.json"
        self.signing_path = self.root / "preview-signing.json"
        self.signing_toolchain_path = self.root / "signing-toolchain.json"
        self.source_attestations_path = self.root / "source-attestations"
        self.source_attestations_path.mkdir()
        self.apt_public_cert_path = self.root / "apt-preview.asc"
        self.rpm_public_cert_path = self.root / "rpm-preview.asc"
        self.plan_path = self.root / "plan.json"
        self.apt_receipt_path = self.root / "apt-receipt.json"
        self.rpm_receipt_path = self.root / "rpm-receipt.json"
        self.archive_path = self.root / f"wukongim-preview-r{AUDIT_ID}-site.tar"
        self.receipt_path = self.root / f"wukongim-preview-r{AUDIT_ID}-receipt.json"

        self.deb_bytes = b"DEB payload\n"
        self.rpm_bytes = b"signed RPM payload\n"
        self.release = {
            "version": VERSION,
            "source_sha": "2" * 40,
            "source_release_id": 110,
            "package_release_id": AUDIT_ID,
            "deb_sha256": hashlib.sha256(self.deb_bytes).hexdigest(),
            "rpm_sha256": hashlib.sha256(b"unsigned RPM payload\n").hexdigest(),
            "state": "active",
            "not_before": None,
        }
        self.retirement = {"phase": "none", "version": None, "not_before": None}
        self.publication = {
            "audit_release_id": AUDIT_ID,
            "base_audit_release_id": None,
            "operation": "add_release",
            "target_version": VERSION,
        }
        self.channels = {
            "schema": receipt_module.CHANNELS_SCHEMA,
            "source_repository": receipt_module.SOURCE_REPOSITORY,
            "site_limit_bytes": receipt_module.SITE_LIMIT_BYTES,
            "site_warning_bytes": receipt_module.SITE_WARNING_BYTES,
            "max_online_versions": 4,
            "architectures": ["amd64"],
            "channels": {
                "preview": {
                    "enabled": True,
                    "status": "ready",
                    "releases": [self.release],
                    "retirement": self.retirement,
                    "publication": self.publication,
                },
                "stable": {
                    "enabled": False,
                    "status": "object_storage_required",
                    "releases": [],
                },
            },
        }
        self.signing = {
            "schema": receipt_module.SIGNING_SCHEMA,
            "enabled": True,
            "minimum_valid_days": 30,
            "rotation_begin_days": 45,
            "maximum_subkey_lifetime_days": 180,
            "apt": {
                "environment": "native-package-preview-apt-signing",
                "public_key": "keys/apt-preview.asc",
                "primary_fingerprint": APT_PRIMARY,
                "signing_subkeys": {
                    "current": APT_SUBKEY,
                    "next": APT_NEXT,
                    "historical": [],
                },
                "secret_subkey_env": "WK_APT_PREVIEW_SECRET_SUBKEY_B64",
                "passphrase_env": "WK_APT_PREVIEW_PASSPHRASE",
            },
            "rpm": {
                "environment": "native-package-preview-rpm-signing",
                "public_key": "keys/rpm-preview.asc",
                "primary_fingerprint": RPM_PRIMARY,
                "signing_subkeys": {
                    "current": RPM_SUBKEY,
                    "next": RPM_NEXT,
                    "historical": [],
                },
                "secret_subkey_env": "WK_RPM_PREVIEW_SECRET_SUBKEY_B64",
                "passphrase_env": "WK_RPM_PREVIEW_PASSPHRASE",
            },
        }
        self.signing_toolchain = {
            "schema": receipt_module.SIGNING_TOOLCHAIN_SCHEMA,
            "enabled": True,
            "image": receipt_module.SIGNING_TOOLCHAIN_IMAGE,
            "digest": "sha256:" + "8" * 64,
            "workflow_sha": "9" * 40,
        }
        self.plan = {
            "schema": receipt_module.PLAN_SCHEMA,
            "control_sha": CONTROL_SHA,
            "operation": "add_release",
            "audit_release_id": AUDIT_ID,
            "base_audit_release_id": None,
            "target_version": VERSION,
            "active_versions": [VERSION],
            "retained_versions": [],
            "new_versions": [VERSION],
            "removed_versions": [],
            "not_before": None,
        }
        self.apt_public_cert_bytes = (
            b"-----BEGIN PGP PUBLIC KEY BLOCK-----\nAPT reviewed certificate\n"
            b"-----END PGP PUBLIC KEY BLOCK-----\n"
        )
        self.rpm_public_cert_bytes = (
            b"-----BEGIN PGP PUBLIC KEY BLOCK-----\nRPM reviewed certificate\n"
            b"-----END PGP PUBLIC KEY BLOCK-----\n"
        )
        self.apt_public_cert_path.write_bytes(self.apt_public_cert_bytes)
        self.rpm_public_cert_path.write_bytes(self.rpm_public_cert_bytes)
        self.source_attestation_summary = self._source_attestation_summary()
        self._build_site()
        self.snapshot = {
            "schema": receipt_module.SNAPSHOT_SCHEMA,
            "audit_release_id": AUDIT_ID,
            "control_sha": CONTROL_SHA,
            "releases": [self.release],
            "retirement": self.retirement,
            "payloads": {
                "apt": [
                    {
                        "version": VERSION,
                        "path": "apt/pool/main/w/wukongim/wukongim.deb",
                        "source_sha256": self.release["deb_sha256"],
                        "published_sha256": self.release["deb_sha256"],
                        "indexed": True,
                    }
                ],
                "rpm": [
                    {
                        "version": VERSION,
                        "path": "rpm/preview/el/9/x86_64/Packages/wukongim.rpm",
                        "source_sha256": self.release["rpm_sha256"],
                        "published_sha256": hashlib.sha256(self.rpm_bytes).hexdigest(),
                        "indexed": True,
                    }
                ],
            },
            "public_keys": {
                "apt": self._public_key_snapshot(
                    "apt", APT_PRIMARY, APT_SUBKEY, APT_NEXT,
                    self.apt_public_cert_bytes,
                ),
                "rpm": self._public_key_snapshot(
                    "rpm", RPM_PRIMARY, RPM_SUBKEY, RPM_NEXT,
                    self.rpm_public_cert_bytes,
                ),
            },
            "source_attestations": self._source_attestation_snapshot(),
            "toolchain": {
                "image": self.signing_toolchain["image"],
                "digest": self.signing_toolchain["digest"],
                "workflow_sha": self.signing_toolchain["workflow_sha"],
                "manifest_sha256": hashlib.sha256(
                    (json.dumps(self.signing_toolchain, indent=2) + "\n").encode()
                ).hexdigest(),
                "manifest_size": len(
                    (json.dumps(self.signing_toolchain, indent=2) + "\n").encode()
                ),
            },
        }
        self.apt_receipt = self._family_receipt("apt", APT_PRIMARY, APT_SUBKEY)
        self.rpm_receipt = self._family_receipt("rpm", RPM_PRIMARY, RPM_SUBKEY)
        self.write_inputs()
        self.rebuild_archive()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _build_site(self) -> None:
        apt_release = self.site / "apt/dists/preview/Release"
        apt_release.parent.mkdir(parents=True)
        apt_release.write_bytes(b"Suite: preview\n")
        (apt_release.parent / "InRelease").write_bytes(b"signed inline Release\n")
        (apt_release.parent / "Release.gpg").write_bytes(b"detached signature\n")
        deb = self.site / "apt/pool/main/w/wukongim/wukongim.deb"
        deb.parent.mkdir(parents=True)
        deb.write_bytes(self.deb_bytes)

        rpm_root = self.site / "rpm/preview/el/9/x86_64"
        package = rpm_root / "Packages/wukongim.rpm"
        package.parent.mkdir(parents=True)
        package.write_bytes(self.rpm_bytes)
        repodata = rpm_root / "repodata"
        repodata.mkdir()
        (repodata / "repomd.xml").write_bytes(b"<repomd/>\n")
        (repodata / "repomd.xml.asc").write_bytes(b"signed repomd\n")
        (self.site / "index.html").write_bytes(b"package repository\n")
        keys = self.site / "keys"
        keys.mkdir()
        (keys / "apt-preview.asc").write_bytes(self.apt_public_cert_bytes)
        (keys / "rpm-preview.asc").write_bytes(self.rpm_public_cert_bytes)

    def _source_attestation_summary(self) -> dict[str, object]:
        names = sorted([
            f"wukongim_{VERSION}_checksums.txt",
            f"wukongim_{VERSION}_darwin_amd64.tar.gz",
            f"wukongim_{VERSION}_darwin_arm64.tar.gz",
            f"wukongim_{VERSION}_linux_amd64.deb",
            f"wukongim_{VERSION}_linux_amd64.rpm",
            f"wukongim_{VERSION}_linux_amd64.tar.gz",
            f"wukongim_{VERSION}_linux_arm64.tar.gz",
        ])
        assets = []
        for index, name in enumerate(names):
            evidence_file = f"{name}.attestation.json"
            evidence_raw = canonical({"asset": name, "verified": True})
            (self.source_attestations_path / evidence_file).write_bytes(evidence_raw)
            if name.endswith(".deb"):
                asset_sha256 = self.release["deb_sha256"]
            elif name.endswith(".rpm"):
                asset_sha256 = self.release["rpm_sha256"]
            else:
                asset_sha256 = f"{index + 1:x}" * 64
            assets.append({
                "asset": name,
                "asset_sha256": asset_sha256,
                "evidence_file": evidence_file,
                "evidence_sha256": hashlib.sha256(evidence_raw).hexdigest(),
            })
        return {
            "schema": receipt_module.SOURCE_ATTESTATION_SCHEMA,
            "repository": receipt_module.SOURCE_REPOSITORY,
            "release_id": self.release["source_release_id"],
            "tag": f"v{VERSION}",
            "version": VERSION,
            "source_sha": self.release["source_sha"],
            "source_ref": f"refs/tags/v{VERSION}",
            "signer_workflow": receipt_module.SOURCE_SIGNER_WORKFLOW,
            "deny_self_hosted_runners": True,
            "asset_count": 7,
            "assets": assets,
            "assets_revalidated_after_attestations": True,
        }

    def _source_attestation_snapshot(self) -> dict[str, object]:
        summary_raw = canonical(self.source_attestation_summary)
        (self.source_attestations_path / "source-attestations.json").write_bytes(summary_raw)
        files = []
        for path in sorted(self.source_attestations_path.iterdir(), key=lambda item: item.name):
            raw = path.read_bytes()
            files.append({
                "path": f"audit/source-attestations/{path.name}",
                "sha256": hashlib.sha256(raw).hexdigest(),
                "size": len(raw),
            })
        return {
            "summary_sha256": hashlib.sha256(summary_raw).hexdigest(),
            "files": files,
        }

    def _public_key_snapshot(
        self,
        family: str,
        primary: str,
        current: str,
        successor: str,
        certificate: bytes,
    ) -> dict[str, object]:
        return {
            "path": f"keys/{family}-preview.asc",
            "sha256": hashlib.sha256(certificate).hexdigest(),
            "size": len(certificate),
            "primary_fingerprint": primary,
            "current_signing_subkey_fingerprint": current,
            "next_signing_subkey_fingerprint": successor,
            "historical_signing_subkey_fingerprints": [],
        }

    def _key_receipt(self, family: str, primary: str, subkey: str) -> dict[str, object]:
        successor = APT_NEXT if family == "apt" else RPM_NEXT
        certificate = (
            self.apt_public_cert_bytes if family == "apt" else self.rpm_public_cert_bytes
        )
        return {
            "family": family,
            "historical_signing_subkey_fingerprints": [],
            "maximum_lifetime_days": 180,
            "minimum_valid_days": 30,
            "next_signing_subkey_fingerprint": successor,
            "primary_fingerprint": primary,
            "public_certificate_sha256": hashlib.sha256(certificate).hexdigest(),
            "public_certificate_size": len(certificate),
            "signing_subkey_created": "2026-09-01T00:00:00Z",
            "signing_subkey_expires": "2026-12-01T00:00:00Z",
            "signing_subkey_fingerprint": subkey,
            "validated": True,
        }

    def _family_receipt(self, family: str, primary: str, subkey: str) -> dict[str, object]:
        if family == "apt":
            apt_root = self.site / "apt"
            result: dict[str, object] = {
                "inrelease": artifact(
                    apt_root / "dists/preview/InRelease", "dists/preview/InRelease"
                ),
                "release": artifact(
                    apt_root / "dists/preview/Release", "dists/preview/Release"
                ),
                "release_gpg": artifact(
                    apt_root / "dists/preview/Release.gpg", "dists/preview/Release.gpg"
                ),
            }
        else:
            rpm_root = self.site / "rpm/preview/el/9/x86_64"
            signed = artifact(rpm_root / "Packages/wukongim.rpm", "Packages/wukongim.rpm")
            unsigned = {
                "path": "Packages/wukongim.rpm",
                "sha256": self.release["rpm_sha256"],
                "size": len(b"unsigned RPM payload\n"),
            }
            result = {
                "active": [signed],
                "new_unsigned_inputs": [unsigned],
                "newly_signed": [signed],
                "preserved_signed": [],
                "repodata": [
                    artifact(rpm_root / "repodata/repomd.xml", "repodata/repomd.xml"),
                    artifact(
                        rpm_root / "repodata/repomd.xml.asc",
                        "repodata/repomd.xml.asc",
                    ),
                ],
                "repository": "preview/el/9/x86_64",
                "retired": [],
            }
        return {
            "schema": receipt_module.FAMILY_RECEIPT_SCHEMA,
            "family": family,
            "key": self._key_receipt(family, primary, subkey),
            "result": result,
        }

    def write_inputs(self) -> None:
        self.channels_path.write_text(json.dumps(self.channels, indent=2) + "\n", encoding="utf-8")
        self.signing_path.write_text(json.dumps(self.signing, indent=2) + "\n", encoding="utf-8")
        self.signing_toolchain_path.write_text(
            json.dumps(self.signing_toolchain, indent=2) + "\n", encoding="utf-8"
        )
        (self.source_attestations_path / "source-attestations.json").write_bytes(
            canonical(self.source_attestation_summary)
        )
        self.plan_path.write_bytes(canonical(self.plan))
        self.apt_receipt_path.write_bytes(canonical(self.apt_receipt))
        self.rpm_receipt_path.write_bytes(canonical(self.rpm_receipt))
        (self.audit / "snapshot.json").write_bytes(canonical(self.snapshot))
        (self.audit / "plan.json").write_bytes(canonical(self.plan))
        (self.audit / "apt-signing.json").write_bytes(canonical(self.apt_receipt))
        (self.audit / "rpm-signing.json").write_bytes(canonical(self.rpm_receipt))
        (self.audit / "signing-toolchain.json").write_bytes(
            self.signing_toolchain_path.read_bytes()
        )
        archived_attestations = self.audit / "source-attestations"
        archived_attestations.mkdir(exist_ok=True)
        for source in self.source_attestations_path.iterdir():
            (archived_attestations / source.name).write_bytes(source.read_bytes())

    def rebuild_archive(self) -> None:
        (self.audit / "snapshot.json").write_bytes(canonical(self.snapshot))
        self.archive_current_tree()

    def archive_current_tree(self) -> None:
        self.archive_path.unlink(missing_ok=True)
        receipt_module.snapshot_archive.create_snapshot(
            source_dir=self.snapshot_root,
            archive_path=self.archive_path,
            max_total_size=receipt_module.ARCHIVE_MAX_TOTAL_BYTES,
        )

    def inputs(self) -> dict[str, Path]:
        return {
            "channels_path": self.channels_path,
            "signing_path": self.signing_path,
            "signing_toolchain_path": self.signing_toolchain_path,
            "apt_public_cert_path": self.apt_public_cert_path,
            "rpm_public_cert_path": self.rpm_public_cert_path,
            "source_attestations_path": self.source_attestations_path,
            "plan_path": self.plan_path,
            "apt_receipt_path": self.apt_receipt_path,
            "rpm_receipt_path": self.rpm_receipt_path,
            "archive_path": self.archive_path,
        }

    def create(self) -> dict[str, object]:
        return receipt_module.create_audit_receipt(
            output_path=self.receipt_path, **self.inputs()
        )

    def test_create_and_verify_bind_all_reviewed_evidence(self) -> None:
        receipt = self.create()
        self.assertEqual(receipt_module.RECEIPT_SCHEMA, receipt["schema"])
        self.assertEqual(AUDIT_ID, receipt["audit_release_id"])
        self.assertEqual(CONTROL_SHA, receipt["control_sha"])
        self.assertEqual("add_release", receipt["plan"]["operation"])
        self.assertEqual(
            hashlib.sha256(canonical(self.plan)).hexdigest(),
            receipt["plan"]["sha256"],
        )
        self.assertEqual(self.archive_path.name, receipt["archive"]["name"])
        self.assertEqual(
            hashlib.sha256(canonical(self.snapshot)).hexdigest(),
            receipt["archive"]["snapshot_sha256"],
        )
        self.assertEqual(
            hashlib.sha256(canonical(self.apt_receipt)).hexdigest(),
            receipt["signers"]["apt"]["receipt_sha256"],
        )
        self.assertEqual(self.signing_toolchain["digest"], receipt["toolchain"]["digest"])
        self.assertEqual(self.release["source_release_id"], receipt["source"]["release_id"])
        self.assertEqual(
            hashlib.sha256(canonical(self.source_attestation_summary)).hexdigest(),
            receipt["source"]["attestation_summary_sha256"],
        )
        expected_site_bytes = sum(
            path.stat().st_size for path in self.site.rglob("*") if path.is_file()
        )
        self.assertEqual(expected_site_bytes, receipt["site"]["total_bytes"])
        self.assertFalse(receipt["site"]["warning_exceeded"])
        self.assertEqual(canonical(receipt), self.receipt_path.read_bytes())
        self.assertEqual(
            receipt,
            receipt_module.verify_audit_receipt(
                receipt_path=self.receipt_path, **self.inputs()
            ),
        )

    def test_rejects_reviewed_fingerprints_with_colliding_key_ids(self) -> None:
        signing = json.loads(json.dumps(self.signing))
        signing["rpm"]["signing_subkeys"]["next"] = "0" * 24 + APT_SUBKEY[-16:]

        with self.assertRaisesRegex(
            receipt_module.AuditReceiptError, "distinct 16-hex key IDs"
        ):
            receipt_module.validate_signing(
                signing, self.apt_public_cert_path, self.rpm_public_cert_path
            )

    def test_receipt_closes_over_still_valid_former_current_identity(self) -> None:
        self.signing["apt"]["signing_subkeys"]["historical"] = [APT_HISTORICAL]
        self.apt_receipt["key"]["historical_signing_subkey_fingerprints"] = [
            APT_HISTORICAL
        ]
        self.snapshot["public_keys"]["apt"][
            "historical_signing_subkey_fingerprints"
        ] = [APT_HISTORICAL]
        self.write_inputs()
        self.rebuild_archive()

        receipt = self.create()

        self.assertEqual(
            [APT_HISTORICAL],
            receipt["signers"]["apt"]["historical_signing_subkey_fingerprints"],
        )

    def test_cli_create_and_verify_are_canonical(self) -> None:
        common = [
            "--channels", str(self.channels_path),
            "--signing", str(self.signing_path),
            "--signing-toolchain", str(self.signing_toolchain_path),
            "--apt-public-cert", str(self.apt_public_cert_path),
            "--rpm-public-cert", str(self.rpm_public_cert_path),
            "--source-attestations", str(self.source_attestations_path),
            "--plan", str(self.plan_path),
            "--apt-receipt", str(self.apt_receipt_path),
            "--rpm-receipt", str(self.rpm_receipt_path),
            "--archive", str(self.archive_path),
        ]
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            code = receipt_module.main(["create", *common, "--output", str(self.receipt_path)])
        self.assertEqual(0, code)
        self.assertEqual(self.receipt_path.read_bytes(), stdout.getvalue().encode())
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            code = receipt_module.main(["verify", *common, "--receipt", str(self.receipt_path)])
        self.assertEqual(0, code)
        self.assertEqual(self.receipt_path.read_bytes(), stdout.getvalue().encode())

    def test_fixed_archive_and_receipt_names_are_mandatory(self) -> None:
        wrong_archive = self.root / "site.tar"
        self.archive_path.rename(wrong_archive)
        inputs = self.inputs()
        inputs["archive_path"] = wrong_archive
        with self.assertRaisesRegex(receipt_module.AuditReceiptError, "archive name must be"):
            receipt_module.build_audit_receipt(**inputs)

        wrong_archive.rename(self.archive_path)
        with self.assertRaisesRegex(receipt_module.AuditReceiptError, "receipt name must be"):
            receipt_module.create_audit_receipt(
                output_path=self.root / "receipt.json", **self.inputs()
            )

    def test_duplicate_and_unknown_fields_fail_closed(self) -> None:
        self.channels_path.write_text(
            '{"schema":"x","schema":"y"}', encoding="utf-8"
        )
        with self.assertRaisesRegex(receipt_module.AuditReceiptError, "duplicate JSON key"):
            receipt_module.build_audit_receipt(**self.inputs())

        self.write_inputs()
        self.apt_receipt["unknown"] = True
        self.apt_receipt_path.write_bytes(canonical(self.apt_receipt))
        (self.audit / "apt-signing.json").write_bytes(canonical(self.apt_receipt))
        self.archive_current_tree()
        with self.assertRaisesRegex(receipt_module.AuditReceiptError, "fields must be exactly"):
            receipt_module.build_audit_receipt(**self.inputs())

        self.apt_receipt.pop("unknown")
        self.write_inputs()
        self.archive_current_tree()
        receipt = self.create()
        receipt["unknown"] = True
        self.receipt_path.write_bytes(canonical(receipt))
        with self.assertRaisesRegex(receipt_module.AuditReceiptError, "fields must be exactly"):
            receipt_module.verify_audit_receipt(
                receipt_path=self.receipt_path, **self.inputs()
            )

    def test_snapshot_must_match_current_channels_and_plan(self) -> None:
        mutations = (
            ("audit_release_id", AUDIT_ID + 1, "audit_release_id differs"),
            ("control_sha", "9" * 40, "control_sha differs"),
            ("releases", [], "releases differ"),
            (
                "retirement",
                {"phase": "index_removed", "version": VERSION, "not_before": "2026-09-02T00:00:00Z"},
                "retirement differs",
            ),
        )
        for field, value, pattern in mutations:
            with self.subTest(field=field):
                original = self.snapshot[field]
                self.snapshot[field] = value
                self.rebuild_archive()
                with self.assertRaisesRegex(receipt_module.AuditReceiptError, pattern):
                    receipt_module.build_audit_receipt(**self.inputs())
                self.snapshot[field] = original
        self.rebuild_archive()

    def test_snapshot_payloads_are_exact_and_bound_to_reviewed_release(self) -> None:
        self.snapshot["payloads"]["apt"][0]["source_sha256"] = "f" * 64
        self.rebuild_archive()
        with self.assertRaisesRegex(receipt_module.AuditReceiptError, "source digest differs"):
            receipt_module.build_audit_receipt(**self.inputs())

        self.snapshot["payloads"]["apt"][0]["source_sha256"] = self.release["deb_sha256"]
        self.snapshot["payloads"]["apt"][0]["unknown"] = True
        self.rebuild_archive()
        with self.assertRaisesRegex(receipt_module.AuditReceiptError, "fields must be exactly"):
            receipt_module.build_audit_receipt(**self.inputs())

    def test_snapshot_published_digest_must_match_the_archived_payload(self) -> None:
        package = self.site / "apt/pool/main/w/wukongim/wukongim.deb"
        package.write_bytes(b"different archived package\n")
        self.rebuild_archive()
        with self.assertRaisesRegex(receipt_module.AuditReceiptError, "differs from snapshot inventory"):
            receipt_module.build_audit_receipt(**self.inputs())

    def test_public_certificates_close_over_external_receipts_snapshot_and_archive(self) -> None:
        self.apt_public_cert_path.write_bytes(
            b"-----BEGIN PGP PUBLIC KEY BLOCK-----\nchanged external certificate\n"
            b"-----END PGP PUBLIC KEY BLOCK-----\n"
        )
        with self.assertRaisesRegex(receipt_module.AuditReceiptError,
                                    "public key differs from reviewed signing"):
            receipt_module.build_audit_receipt(**self.inputs())

        self.apt_public_cert_path.write_bytes(self.apt_public_cert_bytes)
        (self.site / "keys/apt-preview.asc").write_bytes(
            b"-----BEGIN PGP PUBLIC KEY BLOCK-----\nchanged archived certificate\n"
            b"-----END PGP PUBLIC KEY BLOCK-----\n"
        )
        self.rebuild_archive()
        with self.assertRaisesRegex(receipt_module.AuditReceiptError,
                                    "differs from snapshot inventory"):
            receipt_module.build_audit_receipt(**self.inputs())

    def test_source_attestation_and_toolchain_identity_are_fail_closed(self) -> None:
        self.source_attestation_summary["source_sha"] = "f" * 40
        (self.source_attestations_path / "source-attestations.json").write_bytes(
            canonical(self.source_attestation_summary)
        )
        with self.assertRaisesRegex(receipt_module.AuditReceiptError,
                                    "commit differs from reviewed release"):
            receipt_module.build_audit_receipt(**self.inputs())

        self.source_attestation_summary["source_sha"] = self.release["source_sha"]
        (self.source_attestations_path / "source-attestations.json").write_bytes(
            canonical(self.source_attestation_summary)
        )
        self.signing_toolchain["digest"] = "sha256:" + "z" * 64
        self.signing_toolchain_path.write_text(
            json.dumps(self.signing_toolchain), encoding="utf-8"
        )
        with self.assertRaisesRegex(receipt_module.AuditReceiptError,
                                    "immutable SHA-256 OCI digest"):
            receipt_module.build_audit_receipt(**self.inputs())

    def test_archive_rejects_trailing_bytes_links_and_unexpected_top_level_paths(self) -> None:
        with self.archive_path.open("ab") as output:
            output.write(b"trailing attacker bytes")
        with self.assertRaisesRegex(receipt_module.AuditReceiptError, "trailing bytes"):
            receipt_module.build_audit_receipt(**self.inputs())

        self.rebuild_archive()
        (self.snapshot_root / "unexpected").write_text("extra", encoding="utf-8")
        self.rebuild_archive()
        with self.assertRaisesRegex(receipt_module.AuditReceiptError, "unexpected path"):
            receipt_module.build_audit_receipt(**self.inputs())
        (self.snapshot_root / "unexpected").unlink()

        self.archive_path.unlink()
        with tarfile.open(self.archive_path, "w", format=tarfile.USTAR_FORMAT) as tar:
            info = tarfile.TarInfo("site/link")
            info.type = tarfile.SYMTYPE
            info.linkname = "../../escape"
            tar.addfile(info)
        with self.assertRaisesRegex(receipt_module.AuditReceiptError, "link, special"):
            receipt_module.build_audit_receipt(**self.inputs())

    def test_archive_requires_exact_audit_json_and_source_evidence_closure(self) -> None:
        required = {
            "snapshot.json": canonical(self.snapshot),
            "plan.json": canonical(self.plan),
            "apt-signing.json": canonical(self.apt_receipt),
            "rpm-signing.json": canonical(self.rpm_receipt),
            "signing-toolchain.json": self.signing_toolchain_path.read_bytes(),
        }
        for name, raw in required.items():
            with self.subTest(name=name):
                path = self.audit / name
                path.unlink()
                self.archive_current_tree()
                with self.assertRaisesRegex(
                    receipt_module.AuditReceiptError, "exact audit evidence closure"
                ):
                    receipt_module.build_audit_receipt(**self.inputs())
                path.write_bytes(raw)

        evidence = next(
            path for path in (self.audit / "source-attestations").iterdir()
            if path.name != "source-attestations.json"
        )
        evidence_raw = evidence.read_bytes()
        evidence.unlink()
        self.archive_current_tree()
        with self.assertRaisesRegex(receipt_module.AuditReceiptError,
                                    "exact audit evidence closure"):
            receipt_module.build_audit_receipt(**self.inputs())
        evidence.write_bytes(evidence_raw)

        extra = self.audit / "extra.json"
        extra.write_bytes(canonical({"unexpected": True}))
        self.archive_current_tree()
        with self.assertRaisesRegex(receipt_module.AuditReceiptError, "unexpected path"):
            receipt_module.build_audit_receipt(**self.inputs())

    def test_external_recovery_inputs_must_byte_match_the_archive(self) -> None:
        self.plan["control_sha"] = "9" * 40
        self.plan_path.write_bytes(canonical(self.plan))
        with self.assertRaisesRegex(receipt_module.AuditReceiptError, "publication plan bytes"):
            receipt_module.build_audit_receipt(**self.inputs())

        self.plan["control_sha"] = CONTROL_SHA
        self.plan_path.write_bytes(canonical(self.plan))
        self.apt_receipt["key"]["signing_subkey_created"] = "2026-08-31T00:00:00Z"
        self.apt_receipt_path.write_bytes(canonical(self.apt_receipt))
        with self.assertRaisesRegex(receipt_module.AuditReceiptError, "APT signing receipt bytes"):
            receipt_module.build_audit_receipt(**self.inputs())

    def test_archive_only_draft_can_recover_inputs_and_rebuild_the_receipt(self) -> None:
        original = self.create()
        extracted = self.root / "recovered-snapshot"
        receipt_module.snapshot_archive.extract_snapshot(
            archive_path=self.archive_path,
            output_dir=extracted,
            max_total_size=receipt_module.ARCHIVE_MAX_TOTAL_BYTES,
        )
        recovered_inputs = self.inputs()
        recovered_inputs.update(
            {
                "plan_path": extracted / "audit/plan.json",
                "apt_receipt_path": extracted / "audit/apt-signing.json",
                "rpm_receipt_path": extracted / "audit/rpm-signing.json",
                "apt_public_cert_path": extracted / "site/keys/apt-preview.asc",
                "rpm_public_cert_path": extracted / "site/keys/rpm-preview.asc",
                "source_attestations_path": extracted / "audit/source-attestations",
                "signing_toolchain_path": extracted / "audit/signing-toolchain.json",
            }
        )
        self.assertEqual(
            original,
            receipt_module.build_audit_receipt(**recovered_inputs),
        )
        recovery_output = self.root / "recovery-output"
        recovery_output.mkdir()
        recovered_receipt = recovery_output / self.receipt_path.name
        self.assertEqual(
            original,
            receipt_module.create_audit_receipt(
                output_path=recovered_receipt, **recovered_inputs
            ),
        )
        self.assertEqual(canonical(original), recovered_receipt.read_bytes())

    def test_signer_receipts_must_match_reviewed_keys_and_archived_artifacts(self) -> None:
        self.apt_receipt["key"]["primary_fingerprint"] = "E" * 40
        self.apt_receipt_path.write_bytes(canonical(self.apt_receipt))
        (self.audit / "apt-signing.json").write_bytes(canonical(self.apt_receipt))
        self.archive_current_tree()
        with self.assertRaisesRegex(receipt_module.AuditReceiptError, "differs from reviewed"):
            receipt_module.build_audit_receipt(**self.inputs())

        self.apt_receipt["key"]["primary_fingerprint"] = APT_PRIMARY
        self.apt_receipt["result"]["release"]["sha256"] = "f" * 64
        self.apt_receipt_path.write_bytes(canonical(self.apt_receipt))
        (self.audit / "apt-signing.json").write_bytes(canonical(self.apt_receipt))
        self.archive_current_tree()
        with self.assertRaisesRegex(receipt_module.AuditReceiptError, "differs from the signing receipt"):
            receipt_module.build_audit_receipt(**self.inputs())

    def test_verify_detects_a_valid_signer_receipt_change_by_sha256(self) -> None:
        self.create()
        self.apt_receipt["key"]["signing_subkey_created"] = "2026-08-31T00:00:00Z"
        self.apt_receipt_path.write_bytes(canonical(self.apt_receipt))
        (self.audit / "apt-signing.json").write_bytes(canonical(self.apt_receipt))
        self.archive_current_tree()
        with self.assertRaisesRegex(receipt_module.AuditReceiptError, "differs from the current"):
            receipt_module.verify_audit_receipt(
                receipt_path=self.receipt_path, **self.inputs()
            )

    def test_plan_must_match_channels_publication(self) -> None:
        self.plan["operation"] = "remove_indexes"
        self.plan_path.write_bytes(canonical(self.plan))
        with self.assertRaisesRegex(receipt_module.AuditReceiptError, "differs from reviewed channels"):
            receipt_module.build_audit_receipt(**self.inputs())

    def test_retirement_source_attestation_identity_is_explicitly_null(self) -> None:
        retirement_plan = {**self.plan, "operation": "remove_indexes"}
        source, evidence = receipt_module.validate_source_attestation(
            None, retirement_plan, {"releases": [self.release]}
        )
        self.assertIsNone(source)
        self.assertEqual({}, evidence)
        with self.assertRaisesRegex(receipt_module.AuditReceiptError, "forbidden"):
            receipt_module.validate_source_attestation(
                self.source_attestations_path,
                retirement_plan,
                {"releases": [self.release]},
            )

    def test_warning_and_hard_capacity_thresholds_are_enforced(self) -> None:
        with mock.patch.object(receipt_module, "SITE_WARNING_BYTES", 1):
            self.channels["site_warning_bytes"] = 1
            self.channels_path.write_text(json.dumps(self.channels), encoding="utf-8")
            built = receipt_module.build_audit_receipt(**self.inputs())
            self.assertTrue(built["site"]["warning_exceeded"])
            self.assertEqual(1, built["site"]["warning_bytes"])

        self.channels["site_warning_bytes"] = receipt_module.SITE_WARNING_BYTES
        with mock.patch.object(receipt_module, "SITE_LIMIT_BYTES", 1):
            self.channels["site_limit_bytes"] = 1
            self.channels_path.write_text(json.dumps(self.channels), encoding="utf-8")
            with self.assertRaisesRegex(receipt_module.AuditReceiptError, "hard limit"):
                receipt_module.build_audit_receipt(**self.inputs())

    def test_json_inputs_must_be_single_link_regular_files(self) -> None:
        hardlink = self.root / "channels-hardlink.json"
        os.link(self.channels_path, hardlink)
        with self.assertRaisesRegex(receipt_module.AuditReceiptError, "single-link regular"):
            receipt_module.build_audit_receipt(**self.inputs())


if __name__ == "__main__":
    unittest.main()
