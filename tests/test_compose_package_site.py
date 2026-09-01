from __future__ import annotations

import contextlib
import gzip
import hashlib
import importlib.util
import io
import json
import shutil
import unittest
from argparse import Namespace
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "compose-package-site.py"
SPEC = importlib.util.spec_from_file_location("compose_package_site", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
composer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(composer)

CONTROL_SHA = "1" * 40
APT_PRIMARY = "A" * 40
APT_SUBKEY = "B" * 40
RPM_PRIMARY = "C" * 40
RPM_SUBKEY = "D" * 40
APT_NEXT = "E" * 40
RPM_NEXT = "F" * 40
APT_HISTORICAL = "7" * 40
APT_CERT = b"-----BEGIN PGP PUBLIC KEY BLOCK-----\nAPT-TEST-ONLY\n-----END PGP PUBLIC KEY BLOCK-----\n"
RPM_CERT = b"-----BEGIN PGP PUBLIC KEY BLOCK-----\nRPM-TEST-ONLY\n-----END PGP PUBLIC KEY BLOCK-----\n"
V1 = "3.1.0-rc.1"
V2 = "3.1.0-rc.2"
REMOVED_AT = "2026-09-01T01:00:00Z"


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"


def artifact(path: Path, relative: str) -> dict[str, Any]:
    data = path.read_bytes()
    return {"path": relative, "sha256": digest(data), "size": len(data)}


def release(
    version: str,
    deb: bytes,
    unsigned_rpm: bytes,
    *,
    source_release_id: int,
    package_release_id: int,
    state: str = "active",
    not_before: str | None = None,
) -> dict[str, Any]:
    return {
        "version": version,
        "source_sha": f"{source_release_id % 10}" * 40,
        "source_release_id": source_release_id,
        "package_release_id": package_release_id,
        "deb_sha256": digest(deb),
        "rpm_sha256": digest(unsigned_rpm),
        "state": state,
        "not_before": not_before,
    }


def key_receipt(family: str) -> dict[str, Any]:
    apt = family == "apt"
    certificate = APT_CERT if apt else RPM_CERT
    return {
        "family": family,
        "historical_signing_subkey_fingerprints": [],
        "maximum_lifetime_days": 180,
        "minimum_valid_days": 30,
        "primary_fingerprint": APT_PRIMARY if apt else RPM_PRIMARY,
        "public_certificate_sha256": digest(certificate),
        "public_certificate_size": len(certificate),
        "next_signing_subkey_fingerprint": APT_NEXT if apt else RPM_NEXT,
        "signing_subkey_created": "2026-08-01T00:00:00Z",
        "signing_subkey_expires": "2026-11-01T00:00:00Z",
        "signing_subkey_fingerprint": APT_SUBKEY if apt else RPM_SUBKEY,
        "validated": True,
    }


class Fixture:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.channels = root / "channels.json"
        self.signing = root / "preview-signing.json"
        self.signing_toolchain = root / "signing-toolchain.json"
        self.source_attestations: Path | None = None
        self.apt_public_cert = root / "apt-preview.asc"
        self.rpm_public_cert = root / "rpm-preview.asc"
        self.plan = root / "plan.json"
        self.inventory = root / "inventory.json"
        self.apt_tree = root / "apt-tree"
        self.apt_receipt = root / "apt-receipt.json"
        self.rpm_tree = root / "rpm-tree"
        self.rpm_receipt = root / "rpm-receipt.json"
        self.output = root / "output"
        self.base: Path | None = None
        self.apt_public_cert.write_bytes(APT_CERT)
        self.rpm_public_cert.write_bytes(RPM_CERT)
        self.signing.write_text(json.dumps({
            "schema": composer.SIGNING_SCHEMA,
            "enabled": True,
            "minimum_valid_days": 30,
            "rotation_begin_days": 45,
            "maximum_subkey_lifetime_days": 180,
            "apt": {
                "environment": "native-package-preview-apt-signing",
                "public_key": "keys/apt-preview.asc",
                "primary_fingerprint": APT_PRIMARY,
                "signing_subkeys": {"current": APT_SUBKEY, "next": APT_NEXT, "historical": []},
                "secret_subkey_env": "WK_APT_PREVIEW_SECRET_SUBKEY_B64",
                "passphrase_env": "WK_APT_PREVIEW_PASSPHRASE",
            },
            "rpm": {
                "environment": "native-package-preview-rpm-signing",
                "public_key": "keys/rpm-preview.asc",
                "primary_fingerprint": RPM_PRIMARY,
                "signing_subkeys": {"current": RPM_SUBKEY, "next": RPM_NEXT, "historical": []},
                "secret_subkey_env": "WK_RPM_PREVIEW_SECRET_SUBKEY_B64",
                "passphrase_env": "WK_RPM_PREVIEW_PASSPHRASE",
            },
        }, indent=2) + "\n", encoding="utf-8")
        self.signing_toolchain.write_text(json.dumps({
            "schema": composer.SIGNING_TOOLCHAIN_SCHEMA,
            "enabled": True,
            "image": composer.SIGNING_TOOLCHAIN_IMAGE,
            "digest": "sha256:" + "8" * 64,
            "workflow_sha": "9" * 40,
        }, indent=2) + "\n", encoding="utf-8")

    def write_source_attestations(self, item: dict[str, Any]) -> None:
        self.source_attestations = self.root / "source-attestations"
        self.source_attestations.mkdir()
        version = item["version"]
        names = sorted([
            f"wukongim_{version}_checksums.txt",
            f"wukongim_{version}_darwin_amd64.tar.gz",
            f"wukongim_{version}_darwin_arm64.tar.gz",
            f"wukongim_{version}_linux_amd64.deb",
            f"wukongim_{version}_linux_amd64.rpm",
            f"wukongim_{version}_linux_amd64.tar.gz",
            f"wukongim_{version}_linux_arm64.tar.gz",
        ])
        assets = []
        for index, name in enumerate(names):
            evidence_name = f"{name}.attestation.json"
            evidence = canonical({"asset": name, "verified": True})
            (self.source_attestations / evidence_name).write_bytes(evidence)
            asset_sha = (
                item["deb_sha256"] if name.endswith(".deb") else
                item["rpm_sha256"] if name.endswith(".rpm") else
                f"{index + 1:x}" * 64
            )
            assets.append({
                "asset": name,
                "asset_sha256": asset_sha,
                "evidence_file": evidence_name,
                "evidence_sha256": digest(evidence),
            })
        summary = {
            "schema": composer.SOURCE_ATTESTATION_SCHEMA,
            "repository": composer.SOURCE_REPOSITORY,
            "release_id": item["source_release_id"],
            "tag": f"v{version}",
            "version": version,
            "source_sha": item["source_sha"],
            "source_ref": f"refs/tags/v{version}",
            "signer_workflow": composer.SOURCE_SIGNER_WORKFLOW,
            "deny_self_hosted_runners": True,
            "asset_count": 7,
            "assets": assets,
            "assets_revalidated_after_attestations": True,
        }
        (self.source_attestations / "source-attestations.json").write_bytes(canonical(summary))

    def write_control(
        self,
        releases: list[dict[str, Any]],
        *,
        operation: str,
        audit_id: int,
        base_id: int | None,
        target: str,
        active: list[str],
        retained: list[str],
        new: list[str],
        removed: list[str],
        not_before: str | None,
    ) -> None:
        retirement = (
            {"phase": "indexes_removed", "version": target, "not_before": not_before}
            if operation == "remove_indexes"
            else {"phase": "none", "version": None, "not_before": None}
        )
        channels = {
            "schema": composer.CHANNELS_SCHEMA,
            "source_repository": "WuKongIM/WuKongIM",
            "site_limit_bytes": composer.SITE_LIMIT_BYTES,
            "site_warning_bytes": composer.SITE_WARNING_BYTES,
            "max_online_versions": composer.MAX_ONLINE_VERSIONS,
            "architectures": ["amd64"],
            "channels": {
                "preview": {
                    "enabled": True,
                    "status": "ready",
                    "releases": releases,
                    "retirement": retirement,
                    "publication": {
                        "audit_release_id": audit_id,
                        "base_audit_release_id": base_id,
                        "operation": operation,
                        "target_version": target,
                    },
                },
                "stable": {
                    "enabled": False,
                    "status": "object_storage_required",
                    "releases": [],
                },
            },
        }
        self.channels.write_text(json.dumps(channels, indent=2) + "\n", encoding="utf-8")
        plan = {
            "schema": composer.PLAN_SCHEMA,
            "control_sha": CONTROL_SHA,
            "operation": operation,
            "audit_release_id": audit_id,
            "base_audit_release_id": base_id,
            "target_version": target,
            "active_versions": active,
            "retained_versions": retained,
            "new_versions": new,
            "removed_versions": removed,
            "not_before": not_before,
        }
        self.plan.write_bytes(canonical(plan))

    def write_inventory(
        self,
        releases: dict[str, dict[str, Any]],
        published: dict[str, dict[str, bytes]],
        *,
        audit_id: int,
        active: list[str],
        retained: list[str],
        new: list[str],
    ) -> None:
        payloads: dict[str, list[dict[str, Any]]] = {"apt": [], "rpm": []}
        for family, source_field in (("apt", "deb_sha256"), ("rpm", "rpm_sha256")):
            for version in sorted(set(active) | set(retained)):
                payloads[family].append({
                    "version": version,
                    "path": composer.expected_payload_path(family, version),
                    "source_sha256": releases[version][source_field],
                    "published_sha256": digest(published[family][version]),
                    "indexed": version in active,
                    "new": version in new,
                })
        self.inventory.write_bytes(canonical({
            "schema": composer.INVENTORY_SCHEMA,
            "audit_release_id": audit_id,
            "active_versions": active,
            "retained_versions": retained,
            "payloads": payloads,
        }))

    def write_apt(
        self,
        payloads: dict[str, bytes],
        active: list[str],
        *,
        indexed: list[str] | None = None,
    ) -> None:
        if self.apt_tree.exists():
            shutil.rmtree(self.apt_tree)
        indexed = active if indexed is None else indexed
        for version, data in payloads.items():
            path = self.apt_tree / composer.expected_payload_path("apt", version).removeprefix("apt/")
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        packages = b""
        for version in indexed:
            relative = composer.expected_payload_path("apt", version).removeprefix("apt/")
            payload = payloads[version]
            packages += (
                f"Package: wukongim\nVersion: {version}\nFilename: {relative}\n"
                f"Size: {len(payload)}\nSHA256: {digest(payload)}\n\n"
            ).encode()
        binary = self.apt_tree / "dists/preview/main/binary-amd64"
        binary.mkdir(parents=True, exist_ok=True)
        packages_path = binary / "Packages"
        packages_path.write_bytes(packages)
        compressed_path = binary / "Packages.gz"
        compressed_path.write_bytes(gzip.compress(packages, compresslevel=9, mtime=0))
        by_hash = binary / "by-hash/SHA256"
        by_hash.mkdir(parents=True)
        for path in (packages_path, compressed_path):
            (by_hash / digest(path.read_bytes())).write_bytes(path.read_bytes())
        release_path = self.apt_tree / "dists/preview/Release"
        release_path.write_text(
            "Suite: preview\nAcquire-By-Hash: yes\nSHA256:\n"
            f" {digest(packages)} {len(packages)} main/binary-amd64/Packages\n"
            f" {digest(compressed_path.read_bytes())} {compressed_path.stat().st_size} "
            "main/binary-amd64/Packages.gz\n",
            encoding="utf-8",
        )
        (release_path.parent / "InRelease").write_bytes(b"APT-INRELEASE\n")
        (release_path.parent / "Release.gpg").write_bytes(b"APT-SIGNATURE\n")
        result = {
            "inrelease": artifact(release_path.parent / "InRelease", "dists/preview/InRelease"),
            "release": artifact(release_path, "dists/preview/Release"),
            "release_gpg": artifact(release_path.parent / "Release.gpg", "dists/preview/Release.gpg"),
        }
        self.apt_receipt.write_bytes(canonical({
            "schema": composer.SIGNING_RECEIPT_SCHEMA,
            "family": "apt",
            "key": key_receipt("apt"),
            "result": result,
        }))

    def write_rpm(
        self,
        payloads: dict[str, bytes],
        active: list[str],
        new: list[str],
        *,
        indexed: list[str] | None = None,
        unsigned_payloads: dict[str, bytes] | None = None,
    ) -> None:
        if self.rpm_tree.exists():
            shutil.rmtree(self.rpm_tree)
        indexed = active if indexed is None else indexed
        repository = "preview/el/9/x86_64"
        repo = self.rpm_tree / repository
        package_artifacts: dict[str, dict[str, Any]] = {}
        for version, data in payloads.items():
            relative = Path(composer.expected_payload_path("rpm", version)).relative_to(
                Path("rpm") / repository
            ).as_posix()
            path = repo / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            package_artifacts[relative] = artifact(path, relative)
        primary = (
            '<metadata packages="{}">{}</metadata>\n'.format(
                len(indexed),
                "".join(
                    '<package type="rpm">'
                    f'<checksum type="sha256" pkgid="YES">{digest(payloads[version])}</checksum>'
                    f'<size package="{len(payloads[version])}"/>'
                    f'<location href="{Path(composer.expected_payload_path("rpm", version)).relative_to(Path("rpm") / repository).as_posix()}"/>'
                    '</package>'
                    for version in indexed
                ),
            )
        ).encode()
        repodata = repo / "repodata"
        repodata.mkdir(parents=True)
        metadata = {
            "primary": primary,
            "filelists": b'<filelists packages="0"></filelists>\n',
            "other": b'<otherdata packages="0"></otherdata>\n',
        }
        for data_type, data in metadata.items():
            (repodata / f"{data_type}.xml").write_bytes(data)
        repomd_path = repodata / "repomd.xml"
        repomd_path.write_text(
            '<repomd>'
            + "".join(
                f'<data type="{data_type}">'
                f'<checksum type="sha256">{digest(data)}</checksum>'
                f'<open-checksum type="sha256">{digest(data)}</open-checksum>'
                f'<size>{len(data)}</size><open-size>{len(data)}</open-size>'
                f'<location href="repodata/{data_type}.xml"/>'
                '</data>'
                for data_type, data in metadata.items()
            )
            + '</repomd>\n',
            encoding="utf-8",
        )
        (repodata / "repomd.xml.asc").write_bytes(b"RPM-REPOMD-SIGNATURE\n")
        repodata_artifacts = {
            path.name: artifact(path, f"repodata/{path.name}")
            for path in sorted(repodata.iterdir())
        }
        active_paths = {
            Path(composer.expected_payload_path("rpm", version)).relative_to(
                Path("rpm") / repository
            ).as_posix()
            for version in active
        }
        new_paths = {
            Path(composer.expected_payload_path("rpm", version)).relative_to(
                Path("rpm") / repository
            ).as_posix()
            for version in new
        }
        unsigned_payloads = unsigned_payloads or {}
        unsigned_artifacts = {
            Path(composer.expected_payload_path("rpm", version)).relative_to(
                Path("rpm") / repository
            ).as_posix(): {
                "path": Path(composer.expected_payload_path("rpm", version)).relative_to(
                    Path("rpm") / repository
                ).as_posix(),
                "sha256": digest(unsigned_payloads[version]),
                "size": len(unsigned_payloads[version]),
            }
            for version in new
        }
        result = {
            "active": [package_artifacts[path] for path in sorted(active_paths)],
            "new_unsigned_inputs": [
                unsigned_artifacts[path] for path in sorted(unsigned_artifacts)
            ],
            "newly_signed": [package_artifacts[path] for path in sorted(new_paths)],
            "preserved_signed": [
                package_artifacts[path] for path in sorted(set(package_artifacts) - new_paths)
            ],
            "repodata": [repodata_artifacts[name] for name in sorted(repodata_artifacts)],
            "repository": repository,
            "retired": [
                package_artifacts[path]
                for path in sorted(set(package_artifacts) - active_paths)
            ],
        }
        self.rpm_receipt.write_bytes(canonical({
            "schema": composer.SIGNING_RECEIPT_SCHEMA,
            "family": "rpm",
            "key": key_receipt("rpm"),
            "result": result,
        }))

    def write_base(
        self,
        audit_id: int,
        releases: list[dict[str, Any]],
        payloads: dict[str, dict[str, bytes]],
        indexed: dict[str, bool],
        retirement: dict[str, Any],
    ) -> None:
        self.base = self.root / f"base-{audit_id}"
        site = self.base / "site"
        snapshot_payloads: dict[str, list[dict[str, Any]]] = {"apt": [], "rpm": []}
        release_map = {item["version"]: item for item in releases}
        for family, source_field in (("apt", "deb_sha256"), ("rpm", "rpm_sha256")):
            for version in sorted(payloads[family]):
                path_value = composer.expected_payload_path(family, version)
                path = site / path_value
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(payloads[family][version])
                snapshot_payloads[family].append({
                    "version": version,
                    "path": path_value,
                    "source_sha256": release_map[version][source_field],
                    "published_sha256": digest(payloads[family][version]),
                    "indexed": indexed[version],
                })
        snapshot = {
            "schema": composer.SNAPSHOT_SCHEMA,
            "audit_release_id": audit_id,
            "control_sha": "2" * 40,
            "releases": releases,
            "retirement": retirement,
            "payloads": snapshot_payloads,
            "public_keys": {
                "apt": {
                    "path": "keys/apt-preview.asc", "sha256": digest(APT_CERT),
                    "size": len(APT_CERT), "primary_fingerprint": APT_PRIMARY,
                    "current_signing_subkey_fingerprint": APT_SUBKEY,
                    "next_signing_subkey_fingerprint": APT_NEXT,
                    "historical_signing_subkey_fingerprints": [],
                },
                "rpm": {
                    "path": "keys/rpm-preview.asc", "sha256": digest(RPM_CERT),
                    "size": len(RPM_CERT), "primary_fingerprint": RPM_PRIMARY,
                    "current_signing_subkey_fingerprint": RPM_SUBKEY,
                    "next_signing_subkey_fingerprint": RPM_NEXT,
                    "historical_signing_subkey_fingerprints": [],
                },
            },
            "source_attestations": None,
            "toolchain": {
                "image": composer.SIGNING_TOOLCHAIN_IMAGE,
                "digest": "sha256:" + "8" * 64,
                "workflow_sha": "9" * 40,
                "manifest_sha256": digest(self.signing_toolchain.read_bytes()),
                "manifest_size": self.signing_toolchain.stat().st_size,
            },
        }
        (site / "keys").mkdir(parents=True, exist_ok=True)
        (site / "keys/apt-preview.asc").write_bytes(APT_CERT)
        (site / "keys/rpm-preview.asc").write_bytes(RPM_CERT)
        path = self.base / "audit/snapshot.json"
        path.parent.mkdir(parents=True)
        (self.base / "audit/signing-toolchain.json").write_bytes(
            self.signing_toolchain.read_bytes()
        )
        path.write_bytes(canonical(snapshot))

    def args(self) -> Namespace:
        return Namespace(
            channels=self.channels,
            signing=self.signing,
            signing_toolchain=self.signing_toolchain,
            source_attestations=self.source_attestations,
            plan=self.plan,
            inventory=self.inventory,
            apt_tree=self.apt_tree,
            apt_receipt=self.apt_receipt,
            apt_public_cert=self.apt_public_cert,
            rpm_tree=self.rpm_tree,
            rpm_receipt=self.rpm_receipt,
            rpm_public_cert=self.rpm_public_cert,
            base_root=self.base,
            output_root=self.output,
        )


class ComposePackageSiteTest(unittest.TestCase):
    def fixture(self) -> tuple[Fixture, TemporaryDirectory[str]]:
        temporary = TemporaryDirectory()
        return Fixture(Path(temporary.name)), temporary

    def first_release(self) -> tuple[Fixture, TemporaryDirectory[str]]:
        fixture, temporary = self.fixture()
        deb = b"deb-v1"
        unsigned_rpm = b"unsigned-rpm-v1"
        signed_rpm = b"signed-rpm-v1"
        item = release(V1, deb, unsigned_rpm, source_release_id=101, package_release_id=10)
        releases = {V1: item}
        fixture.write_control(
            [item], operation="add_release", audit_id=10, base_id=None, target=V1,
            active=[V1], retained=[], new=[V1], removed=[], not_before=None,
        )
        fixture.write_source_attestations(item)
        fixture.write_inventory(
            releases, {"apt": {V1: deb}, "rpm": {V1: unsigned_rpm}},
            audit_id=10, active=[V1], retained=[], new=[V1],
        )
        fixture.write_apt({V1: deb}, [V1])
        fixture.write_rpm(
            {V1: signed_rpm}, [V1], [V1], unsigned_payloads={V1: unsigned_rpm}
        )
        return fixture, temporary

    def phase_one(self) -> tuple[Fixture, TemporaryDirectory[str]]:
        fixture, temporary = self.fixture()
        deb = {V1: b"deb-v1", V2: b"deb-v2"}
        unsigned = {V1: b"unsigned-rpm-v1", V2: b"unsigned-rpm-v2"}
        signed = {V1: b"signed-rpm-v1", V2: b"signed-rpm-v2"}
        old_v1 = release(V1, deb[V1], unsigned[V1], source_release_id=101, package_release_id=10)
        v2 = release(V2, deb[V2], unsigned[V2], source_release_id=102, package_release_id=20)
        retired_v1 = {**old_v1, "state": "index_removed", "not_before": REMOVED_AT}
        releases = {V1: retired_v1, V2: v2}
        fixture.write_control(
            [retired_v1, v2], operation="remove_indexes", audit_id=30, base_id=20,
            target=V1, active=[V2], retained=[V1], new=[], removed=[],
            not_before=REMOVED_AT,
        )
        fixture.write_inventory(
            releases, {"apt": deb, "rpm": signed}, audit_id=30,
            active=[V2], retained=[V1], new=[],
        )
        fixture.write_base(
            20, [old_v1, v2], {"apt": deb, "rpm": signed},
            {V1: True, V2: True},
            {"phase": "none", "version": None, "not_before": None},
        )
        fixture.write_apt(deb, [V2])
        fixture.write_rpm(signed, [V2], [])
        return fixture, temporary

    def phase_two(self) -> tuple[Fixture, TemporaryDirectory[str]]:
        fixture, temporary = self.fixture()
        deb = {V1: b"deb-v1", V2: b"deb-v2"}
        unsigned = {V1: b"unsigned-rpm-v1", V2: b"unsigned-rpm-v2"}
        signed = {V1: b"signed-rpm-v1", V2: b"signed-rpm-v2"}
        retired_v1 = release(
            V1, deb[V1], unsigned[V1], source_release_id=101, package_release_id=10,
            state="index_removed", not_before=REMOVED_AT,
        )
        v2 = release(V2, deb[V2], unsigned[V2], source_release_id=102, package_release_id=20)
        releases = {V2: v2}
        fixture.write_control(
            [v2], operation="remove_payloads", audit_id=40, base_id=30, target=V1,
            active=[V2], retained=[], new=[], removed=[V1], not_before=REMOVED_AT,
        )
        fixture.write_inventory(
            releases, {"apt": {V2: deb[V2]}, "rpm": {V2: signed[V2]}},
            audit_id=40, active=[V2], retained=[], new=[],
        )
        fixture.write_base(
            30, [retired_v1, v2], {"apt": deb, "rpm": signed},
            {V1: False, V2: True},
            {"phase": "indexes_removed", "version": V1, "not_before": REMOVED_AT},
        )
        fixture.write_apt({V2: deb[V2]}, [V2])
        fixture.write_rpm({V2: signed[V2]}, [V2], [])
        return fixture, temporary

    def test_first_release_composes_exact_signed_families_and_snapshot(self) -> None:
        fixture, temporary = self.first_release()
        self.addCleanup(temporary.cleanup)

        receipt = composer.compose(fixture.args())

        self.assertEqual(10, receipt["audit_release_id"])
        self.assertFalse(receipt["capacity_warning"])
        status = json.loads((fixture.output / "site/status.json").read_text())
        self.assertEqual({
            "schema": composer.STATUS_SCHEMA,
            "apt": True,
            "rpm": True,
            "reason": "ready",
            "audit_release_id": 10,
            "control_sha": "1" * 40,
            "snapshot_sha256": receipt["snapshot_sha256"],
            "operation": "add_release",
            "target_version": V1,
        }, status)
        manifest = (fixture.output / "site/signing-manifest.txt").read_text()
        for line in (
            "TEST_ONLY=false",
            f"APT_PRIMARY_FINGERPRINT={APT_PRIMARY}",
            f"APT_SIGNING_FINGERPRINT={APT_SUBKEY}",
            f"APT_NEXT_SIGNING_FINGERPRINT={APT_NEXT}",
            f"RPM_PRIMARY_FINGERPRINT={RPM_PRIMARY}",
            f"RPM_SIGNING_FINGERPRINT={RPM_SUBKEY}",
            f"RPM_NEXT_SIGNING_FINGERPRINT={RPM_NEXT}",
            "APT_RELEASE=apt/dists/preview/Release",
            "RPM_REPOSITORY=rpm/preview/el/9/x86_64",
        ):
            self.assertIn(line, manifest.splitlines())
        snapshot = json.loads((fixture.output / "audit/snapshot.json").read_text())
        self.assertEqual(APT_CERT, (fixture.output / "site/keys/apt-preview.asc").read_bytes())
        self.assertEqual(RPM_CERT, (fixture.output / "site/keys/rpm-preview.asc").read_bytes())
        self.assertEqual(APT_NEXT,
                         snapshot["public_keys"]["apt"]["next_signing_subkey_fingerprint"])
        self.assertEqual(RPM_NEXT,
                         snapshot["public_keys"]["rpm"]["next_signing_subkey_fingerprint"])
        self.assertEqual(8, len(snapshot["source_attestations"]["files"]))
        self.assertEqual("sha256:" + "8" * 64, snapshot["toolchain"]["digest"])
        self.assertTrue((
            fixture.output / "audit/source-attestations/source-attestations.json"
        ).is_file())
        rpm_entry = snapshot["payloads"]["rpm"][0]
        self.assertEqual(digest(b"signed-rpm-v1"), rpm_entry["published_sha256"])
        self.assertEqual(b"signed-rpm-v1", (
            fixture.output / "site" / composer.expected_payload_path("rpm", V1)
        ).read_bytes())

    def test_rejects_reviewed_fingerprints_with_colliding_key_ids(self) -> None:
        fixture, temporary = self.first_release()
        self.addCleanup(temporary.cleanup)
        signing = json.loads(fixture.signing.read_text())
        signing["rpm"]["signing_subkeys"]["next"] = "0" * 24 + APT_SUBKEY[-16:]

        with self.assertRaisesRegex(composer.CompositionError, "distinct 16-hex key IDs"):
            composer.validate_signing_manifest(
                signing, fixture.apt_public_cert, fixture.rpm_public_cert
            )

    def test_carries_still_valid_former_current_through_snapshot_identity(self) -> None:
        fixture, temporary = self.first_release()
        self.addCleanup(temporary.cleanup)
        signing = json.loads(fixture.signing.read_text())
        signing["apt"]["signing_subkeys"]["historical"] = [APT_HISTORICAL]
        fixture.signing.write_text(json.dumps(signing, indent=2) + "\n")
        receipt = json.loads(fixture.apt_receipt.read_text())
        receipt["key"]["historical_signing_subkey_fingerprints"] = [APT_HISTORICAL]
        fixture.apt_receipt.write_bytes(canonical(receipt))

        composer.compose(fixture.args())

        snapshot = json.loads((fixture.output / "audit/snapshot.json").read_text())
        self.assertEqual(
            [APT_HISTORICAL],
            snapshot["public_keys"]["apt"]["historical_signing_subkey_fingerprints"],
        )

    def test_cli_emits_canonical_composition_receipt(self) -> None:
        fixture, temporary = self.first_release()
        self.addCleanup(temporary.cleanup)
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            code = composer.main([
                "--channels", str(fixture.channels),
                "--signing", str(fixture.signing),
                "--signing-toolchain", str(fixture.signing_toolchain),
                "--source-attestations", str(fixture.source_attestations),
                "--plan", str(fixture.plan),
                "--inventory", str(fixture.inventory),
                "--apt-tree", str(fixture.apt_tree),
                "--apt-receipt", str(fixture.apt_receipt),
                "--apt-public-cert", str(fixture.apt_public_cert),
                "--rpm-tree", str(fixture.rpm_tree),
                "--rpm-receipt", str(fixture.rpm_receipt),
                "--rpm-public-cert", str(fixture.rpm_public_cert),
                "--output-root", str(fixture.output),
            ])
        self.assertEqual(0, code)
        receipt = json.loads(stdout.getvalue())
        self.assertEqual(canonical(receipt), stdout.getvalue().encode())

    def test_remove_indexes_retains_payload_but_excludes_both_indexes(self) -> None:
        fixture, temporary = self.phase_one()
        self.addCleanup(temporary.cleanup)

        composer.compose(fixture.args())

        self.assertTrue((
            fixture.output / "site" / composer.expected_payload_path("apt", V1)
        ).is_file())
        packages = (
            fixture.output / "site/apt/dists/preview/main/binary-amd64/Packages"
        ).read_text()
        primary = (
            fixture.output / "site/rpm/preview/el/9/x86_64/repodata/primary.xml"
        ).read_text()
        self.assertNotIn(V1, packages)
        self.assertNotIn(V1, primary)
        snapshot = json.loads((fixture.output / "audit/snapshot.json").read_text())
        self.assertFalse(snapshot["payloads"]["apt"][0]["indexed"])
        self.assertIsNone(snapshot["source_attestations"])
        self.assertFalse((fixture.output / "audit/source-attestations").exists())

    def test_remove_payloads_drops_only_previously_retained_bytes(self) -> None:
        fixture, temporary = self.phase_two()
        self.addCleanup(temporary.cleanup)
        phase_one, phase_one_temporary = self.phase_one()
        self.addCleanup(phase_one_temporary.cleanup)
        composer.compose(phase_one.args())
        fixture.base = phase_one.output

        composer.compose(fixture.args())

        self.assertFalse((
            fixture.output / "site" / composer.expected_payload_path("apt", V1)
        ).exists())
        self.assertFalse((
            fixture.output / "site" / composer.expected_payload_path("rpm", V1)
        ).exists())
        snapshot = json.loads((fixture.output / "audit/snapshot.json").read_text())
        self.assertEqual([V2], [item["version"] for item in snapshot["payloads"]["apt"]])

    def test_rejects_extra_or_missing_family_tree_file(self) -> None:
        for mutation, pattern in (
            ("extra", "file closure"),
            ("missing", "missing Packages metadata"),
        ):
            with self.subTest(mutation=mutation):
                fixture, temporary = self.first_release()
                with temporary:
                    if mutation == "extra":
                        (fixture.apt_tree / "unexpected").write_bytes(b"extra")
                    else:
                        (fixture.apt_tree / "dists/preview/main/binary-amd64/Packages").unlink()
                    with self.assertRaisesRegex(composer.CompositionError, pattern):
                        composer.compose(fixture.args())
                    self.assertFalse(fixture.output.exists())

    def test_rejects_retained_payload_in_apt_or_rpm_index(self) -> None:
        for family, pattern in (
            ("apt", "APT Packages index"),
            ("rpm", "RPM primary"),
        ):
            with self.subTest(family=family):
                fixture, temporary = self.phase_one()
                with temporary:
                    if family == "apt":
                        fixture.write_apt({V1: b"deb-v1", V2: b"deb-v2"}, [V2], indexed=[V1, V2])
                    else:
                        fixture.write_rpm(
                            {V1: b"signed-rpm-v1", V2: b"signed-rpm-v2"},
                            [V2], [], indexed=[V1, V2],
                        )
                    with self.assertRaisesRegex(composer.CompositionError, pattern):
                        composer.compose(fixture.args())

    def test_rejects_receipt_size_or_digest_mismatch(self) -> None:
        fixture, temporary = self.first_release()
        self.addCleanup(temporary.cleanup)
        receipt = json.loads(fixture.rpm_receipt.read_text())
        receipt["result"]["repodata"][0]["size"] += 1
        fixture.rpm_receipt.write_bytes(canonical(receipt))

        with self.assertRaisesRegex(composer.CompositionError, "identity differs"):
            composer.compose(fixture.args())

    def test_rejects_public_certificate_that_differs_from_signer_receipt(self) -> None:
        fixture, temporary = self.first_release()
        self.addCleanup(temporary.cleanup)
        fixture.apt_public_cert.write_bytes(
            b"-----BEGIN PGP PUBLIC KEY BLOCK-----\nchanged certificate\n"
            b"-----END PGP PUBLIC KEY BLOCK-----\n"
        )

        with self.assertRaisesRegex(
            composer.CompositionError, "differs from the reviewed public certificate"
        ):
            composer.compose(fixture.args())

    def test_rejects_base_payload_identity_change(self) -> None:
        fixture, temporary = self.phase_one()
        self.addCleanup(temporary.cleanup)
        assert fixture.base is not None
        (fixture.base / "site" / composer.expected_payload_path("apt", V1)).write_bytes(b"tampered")

        with self.assertRaisesRegex(composer.CompositionError, "base apt payload digest"):
            composer.compose(fixture.args())

    def test_capacity_warning_and_hard_limit_boundaries(self) -> None:
        self.assertFalse(composer.capacity_status(9, 10, 20))
        self.assertTrue(composer.capacity_status(10, 10, 20))
        self.assertTrue(composer.capacity_status(20, 10, 20))
        with self.assertRaisesRegex(composer.CompositionError, "hard Pages limit"):
            composer.capacity_status(21, 10, 20)

    def test_rejects_noncanonical_or_unsafe_inventory_path(self) -> None:
        fixture, temporary = self.first_release()
        self.addCleanup(temporary.cleanup)
        inventory = json.loads(fixture.inventory.read_text())
        inventory["payloads"]["apt"][0]["path"] = "apt/../escape.deb"
        fixture.inventory.write_bytes(canonical(inventory))

        with self.assertRaisesRegex(composer.CompositionError, "path is not canonical"):
            composer.compose(fixture.args())


if __name__ == "__main__":
    unittest.main()
