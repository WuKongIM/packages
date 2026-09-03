from __future__ import annotations

import hashlib
import gzip
import importlib.util
import json
import subprocess
import unittest
from argparse import Namespace
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any
from unittest import mock

from tests import test_compose_package_site as fixtures


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/verify-production-package-site.py"
SPEC = importlib.util.spec_from_file_location("verify_production_package_site", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
verifier = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(verifier)

RPM_HISTORICAL = "7" * 40
RPM_UNKNOWN = "6" * 40


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"


def sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def md5(value: bytes) -> str:
    return hashlib.md5(value, usedforsecurity=False).hexdigest()


def sha1(value: bytes) -> str:
    return hashlib.sha1(value, usedforsecurity=False).hexdigest()


def sha512(value: bytes) -> str:
    return hashlib.sha512(value).hexdigest()


class VerifyProductionPackageSiteTest(unittest.TestCase):
    def compose(self, phase: str = "first") -> tuple[fixtures.Fixture, TemporaryDirectory[str]]:
        factory = fixtures.ComposePackageSiteTest()
        if phase == "first":
            fixture, temporary = factory.first_release()
        elif phase == "indexes_removed":
            fixture, temporary = factory.phase_one()
        else:  # pragma: no cover - test programming error
            raise AssertionError(phase)
        fixtures.composer.compose(fixture.args())
        self._add_apt_sha512(fixture)
        self._close_secondary_rpm_metadata(fixture)
        return fixture, temporary

    def args(self, fixture: fixtures.Fixture) -> Namespace:
        return Namespace(
            site_root=fixture.output / "site",
            snapshot=fixture.output / "audit/snapshot.json",
            channels=fixture.channels,
            signing=fixture.signing,
            apt_public_cert=fixture.apt_public_cert,
            rpm_public_cert=fixture.rpm_public_cert,
        )

    def _add_apt_sha512(self, fixture: fixtures.Fixture) -> None:
        binary = fixture.output / "site/apt/dists/preview/main/binary-amd64"
        release = fixture.output / "site/apt/dists/preview/Release"
        snapshot = json.loads((fixture.output / "audit/snapshot.json").read_text())
        packages_text = (binary / "Packages").read_text()
        for item in snapshot["payloads"]["apt"]:
            if item["indexed"]:
                packages_text = packages_text.replace(
                    f"Version: {item['version']}\n",
                    f"Version: {verifier.apt_package_version(item['version'])}\n"
                    "Architecture: amd64\n",
                )
        bootstrap_path = fixture.output / "site/bootstrap/manifest.json"
        if bootstrap_path.is_file():
            bootstrap = json.loads(bootstrap_path.read_text())["packages"]["apt"]
            packages_text = packages_text.replace(
                f"Package: {bootstrap['name']}\nVersion: {bootstrap['version']}\n",
                f"Package: {bootstrap['name']}\nVersion: {bootstrap['version']}\n"
                f"Architecture: {bootstrap['architecture']}\n",
            )
        packages = packages_text.encode()
        (binary / "Packages").write_bytes(packages)
        self._rewrite_apt_hashes(fixture)

    def _rewrite_apt_hashes(self, fixture: fixtures.Fixture) -> None:
        binary = fixture.output / "site/apt/dists/preview/main/binary-amd64"
        release = fixture.output / "site/apt/dists/preview/Release"
        packages = (binary / "Packages").read_bytes()
        compressed = gzip.compress(packages, compresslevel=9, mtime=0)
        (binary / "Packages.gz").write_bytes(compressed)
        by_hash = binary / "by-hash/SHA256"
        for existing in by_hash.iterdir():
            existing.unlink()
        (by_hash / sha256(packages)).write_bytes(packages)
        (by_hash / sha256(compressed)).write_bytes(compressed)
        release.write_bytes((
            "Origin: WuKongIM\n"
            "Label: WuKongIM\n"
            "Suite: preview\n"
            "Codename: preview\n"
            "Architectures: amd64\n"
            "Components: main\n"
            "Acquire-By-Hash: yes\n"
            "Date: Tue, 01 Sep 2026 00:00:00 +0000\n"
            "MD5Sum:\n"
            f" {md5(packages)} {len(packages)} main/binary-amd64/Packages\n"
            f" {md5(compressed)} {len(compressed)} main/binary-amd64/Packages.gz\n"
            "SHA1:\n"
            f" {sha1(packages)} {len(packages)} main/binary-amd64/Packages\n"
            f" {sha1(compressed)} {len(compressed)} main/binary-amd64/Packages.gz\n"
            "SHA256:\n"
            f" {sha256(packages)} {len(packages)} main/binary-amd64/Packages\n"
            f" {sha256(compressed)} {len(compressed)} main/binary-amd64/Packages.gz\n"
            "SHA512:\n"
            f" {sha512(packages)} {len(packages)} main/binary-amd64/Packages\n"
            f" {sha512(compressed)} {len(compressed)} main/binary-amd64/Packages.gz\n"
        ).encode())

    def _close_secondary_rpm_metadata(
        self, fixture: fixtures.Fixture, *, include_bootstrap: bool = True
    ) -> None:
        site = fixture.output / "site"
        snapshot = json.loads((fixture.output / "audit/snapshot.json").read_text())
        repository = site / "rpm/preview/el/9/x86_64"
        active = [item for item in snapshot["payloads"]["rpm"] if item["indexed"]]
        entries = [
            {
                "name": "wukongim",
                "architecture": "x86_64",
                "version": verifier.rpm_package_version(item["version"]),
                "release": "1",
                "path": item["path"],
                "sha256": item["published_sha256"],
            }
            for item in active
        ]
        bootstrap_path = site / "bootstrap/manifest.json"
        if include_bootstrap and bootstrap_path.is_file():
            bootstrap = json.loads(bootstrap_path.read_text())["packages"]["rpm"]
            entries.append({
                "name": bootstrap["name"],
                "architecture": bootstrap["architecture"],
                "version": bootstrap["version"],
                "release": "1",
                "path": bootstrap["repository_path"],
                "sha256": bootstrap["published_sha256"],
            })
        secondary_packages = "".join(
            f'<package pkgid="{item["sha256"]}" name="{item["name"]}" '
            f'arch="{item["architecture"]}">'
            f'<version epoch="0" ver="{item["version"]}" rel="{item["release"]}"/>'
            "</package>"
            for item in entries
        )
        primary_packages = "".join(
            f'<package type="rpm"><name>{item["name"]}</name>'
            f'<arch>{item["architecture"]}</arch>'
            f'<version epoch="0" ver="{item["version"]}" rel="{item["release"]}"/>'
            f'<checksum type="sha256" pkgid="YES">{item["sha256"]}</checksum>'
            f'<size package="{(site / item["path"]).stat().st_size}"/>'
            f'<location href="{Path(item["path"]).relative_to("rpm/preview/el/9/x86_64").as_posix()}"/>'
            "</package>"
            for item in entries
        )
        metadata = {
            "primary": f'<metadata packages="{len(entries)}">{primary_packages}</metadata>\n'.encode(),
            "filelists": f'<filelists packages="{len(entries)}">{secondary_packages}</filelists>\n'.encode(),
            "other": f'<otherdata packages="{len(entries)}">{secondary_packages}</otherdata>\n'.encode(),
        }
        for data_type, contents in metadata.items():
            (repository / f"repodata/{data_type}.xml").write_bytes(contents)
        self._rewrite_repomd(fixture)

    def _rewrite_repomd(self, fixture: fixtures.Fixture) -> None:
        repository = fixture.output / "site/rpm/preview/el/9/x86_64"
        metadata = {
            data_type: (repository / f"repodata/{data_type}.xml").read_bytes()
            for data_type in ("primary", "filelists", "other")
        }
        repomd = (
            "<repomd>" + "".join(
                f'<data type="{data_type}">'
                f'<checksum type="sha256">{sha256(contents)}</checksum>'
                f'<open-checksum type="sha256">{sha256(contents)}</open-checksum>'
                f'<size>{len(contents)}</size><open-size>{len(contents)}</open-size>'
                f'<location href="repodata/{data_type}.xml"/>'
                "</data>"
                for data_type, contents in metadata.items()
            ) + "</repomd>\n"
        ).encode()
        (repository / "repodata/repomd.xml").write_bytes(repomd)

    def _deb_query(self, fixture: fixtures.Fixture):
        snapshot = json.loads((fixture.output / "audit/snapshot.json").read_text())
        identities = {
            str(fixture.output / "site" / item["path"]): {
                "name": "wukongim",
                "version": verifier.apt_package_version(item["version"]),
                "architecture": "amd64",
            }
            for item in snapshot["payloads"]["apt"]
        }
        bootstrap_path = fixture.output / "site/bootstrap/manifest.json"
        if bootstrap_path.is_file():
            bootstrap = json.loads(bootstrap_path.read_text())["packages"]["apt"]
            identities[str(fixture.output / "site" / bootstrap["repository_path"])] = {
                "name": bootstrap["name"],
                "version": bootstrap["version"],
                "architecture": bootstrap["architecture"],
            }
        return lambda path: identities[str(path)]

    def _rpm_query(self, fixture: fixtures.Fixture):
        snapshot = json.loads((fixture.output / "audit/snapshot.json").read_text())
        identities = {
            str(fixture.output / "site" / item["path"]): {
                "name": "wukongim", "epoch": "0",
                "version": verifier.rpm_package_version(item["version"]),
                "release": "1", "architecture": "x86_64",
            }
            for item in snapshot["payloads"]["rpm"]
        }
        bootstrap_path = fixture.output / "site/bootstrap/manifest.json"
        if bootstrap_path.is_file():
            bootstrap = json.loads(bootstrap_path.read_text())["packages"]["rpm"]
            identities[str(fixture.output / "site" / bootstrap["repository_path"])] = {
                "name": bootstrap["name"], "epoch": "0",
                "version": bootstrap["version"], "release": "1",
                "architecture": bootstrap["architecture"],
            }
        return lambda path: identities[str(path)]

    def _topology(self, fixture: fixtures.Fixture):
        signing = json.loads(fixture.signing.read_text())

        def inspect(path: Path) -> dict[str, Any]:
            family = "apt" if "apt" in path.name else "rpm"
            values = signing[family]
            subkeys = values["signing_subkeys"]
            return {
                "primary": {
                    "kind": "pub", "fingerprint": values["primary_fingerprint"],
                    "capabilities": ["c"], "validity": "u", "disabled": False,
                    "key_bits": 3072 if family == "rpm" else 255,
                    "public_key_algorithm": 1 if family == "rpm" else 22,
                    "created": 1, "expires": None,
                },
                "subkeys": [
                    {"kind": "sub", "fingerprint": fingerprint,
                     "capabilities": ["s"], "validity": "u", "disabled": False,
                     "key_bits": 3072 if family == "rpm" else 255,
                     "public_key_algorithm": 1 if family == "rpm" else 22,
                     "created": 1, "expires": 4_102_444_800}
                    for fingerprint in [subkeys["current"], subkeys["next"], *subkeys["historical"]]
                ],
            }
        return inspect

    def _openpgp(self, fixture: fixtures.Fixture, *, apt_issuer: str | None = None,
                 rpm_issuer: str | None = None):
        def verify(certificate: Path, signature: Path, data: Path | None) -> dict[str, Any]:
            apt = "apt" in certificate.name
            issuer = (apt_issuer or fixtures.APT_SUBKEY) if apt else (rpm_issuer or fixtures.RPM_SUBKEY)
            cleartext = None
            if data is None:
                cleartext = (fixture.output / "site/apt/dists/preview/Release").read_bytes()
            return {"fingerprint": issuer, "digest_algorithm": 8, "cleartext": cleartext}
        return verify

    def verify(self, fixture: fixtures.Fixture, *, rpm_issuers=None,
               apt_issuer: str | None = None, rpm_metadata_issuer: str | None = None,
               topology_inspector=None, deb_query=None, rpm_query=None,
               apt_bootstrap_inspector=None, rpm_bootstrap_inspector=None):
        rpm_issuers = rpm_issuers or (
            lambda _path, _cert, _allowed: fixtures.RPM_SUBKEY
        )
        topology_inspector = topology_inspector or self._topology(fixture)
        deb_query = deb_query or self._deb_query(fixture)
        rpm_query = rpm_query or self._rpm_query(fixture)
        apt_bootstrap_inspector = apt_bootstrap_inspector or mock.Mock()
        rpm_bootstrap_inspector = rpm_bootstrap_inspector or mock.Mock()
        with mock.patch.object(verifier, "inspect_public_certificate",
                               side_effect=topology_inspector), \
             mock.patch.object(verifier, "verify_openpgp_signature",
                               side_effect=self._openpgp(
                                   fixture, apt_issuer=apt_issuer,
                                   rpm_issuer=rpm_metadata_issuer,
                               )), \
             mock.patch.object(verifier, "verify_rpm_package_signature",
                               side_effect=rpm_issuers), \
             mock.patch.object(verifier, "query_deb_identity", side_effect=deb_query), \
             mock.patch.object(verifier, "query_rpm_identity", side_effect=rpm_query), \
             mock.patch.object(verifier, "inspect_apt_bootstrap_package",
                               side_effect=apt_bootstrap_inspector), \
             mock.patch.object(verifier, "inspect_rpm_bootstrap_package",
                               side_effect=rpm_bootstrap_inspector):
            return verifier.verify(self.args(fixture))

    def _add_historical_control(self, fixture: fixtures.Fixture) -> None:
        signing = json.loads(fixture.signing.read_text())
        signing["rpm"]["signing_subkeys"]["historical"] = [RPM_HISTORICAL]
        fixture.signing.write_text(json.dumps(signing, indent=2) + "\n")
        snapshot_path = fixture.output / "audit/snapshot.json"
        snapshot = json.loads(snapshot_path.read_text())
        snapshot["public_keys"]["rpm"]["historical_signing_subkey_fingerprints"] = [RPM_HISTORICAL]
        snapshot_path.write_bytes(canonical(snapshot))
        status_path = fixture.output / "site/status.json"
        status = json.loads(status_path.read_text())
        status["snapshot_sha256"] = sha256(snapshot_path.read_bytes())
        status_path.write_bytes(canonical(status))

    def _remove_bootstrap_from_apt_index(self, fixture: fixtures.Fixture) -> None:
        packages_path = (
            fixture.output / "site/apt/dists/preview/main/binary-amd64/Packages"
        )
        paragraphs = [
            paragraph for paragraph in packages_path.read_text().strip().split("\n\n")
            if not paragraph.startswith("Package: wukongim-archive-keyring\n")
        ]
        packages_path.write_text("\n\n".join(paragraphs) + "\n\n")
        self._rewrite_apt_hashes(fixture)

    def _make_legacy_bootstrap_free_site(self, fixture: fixtures.Fixture) -> None:
        site = fixture.output / "site"
        manifest_path = site / verifier.BOOTSTRAP_MANIFEST_PATH
        manifest = json.loads(manifest_path.read_text())
        self._remove_bootstrap_from_apt_index(fixture)
        self._close_secondary_rpm_metadata(fixture, include_bootstrap=False)
        for item in manifest["packages"].values():
            (site / item["repository_path"]).unlink()
            (site / item["download_path"]).unlink()
        (site / verifier.C.REPOSITORY_ENTRYPOINT_PATH).unlink()
        manifest_path.unlink()
        (site / "bootstrap").rmdir()
        (site / "index.html").write_bytes(
            b'<!doctype html>\n<meta charset="utf-8">\n'
            b"<title>WuKongIM Linux packages</title>\n"
            b"<h1>WuKongIM Linux packages</h1>\n"
            b"<p>The signed preview APT and RPM repositories are ready.</p>\n"
        )

        audit_id, control_sha = next(iter(verifier.LEGACY_BOOTSTRAP_FREE_SNAPSHOTS))
        channels = json.loads(fixture.channels.read_text())
        channels["channels"]["preview"]["publication"]["audit_release_id"] = audit_id
        channels["channels"]["preview"]["releases"][0]["package_release_id"] = audit_id
        fixture.channels.write_text(json.dumps(channels, indent=2) + "\n")
        snapshot_path = fixture.output / "audit/snapshot.json"
        snapshot = json.loads(snapshot_path.read_text())
        snapshot["audit_release_id"] = audit_id
        snapshot["control_sha"] = control_sha
        snapshot["releases"][0]["package_release_id"] = audit_id
        snapshot_path.write_bytes(canonical(snapshot))
        status_path = site / "status.json"
        status = json.loads(status_path.read_text())
        status["audit_release_id"] = audit_id
        status["control_sha"] = control_sha
        status["snapshot_sha256"] = sha256(snapshot_path.read_bytes())
        status_path.write_bytes(canonical(status))

    def test_valid_add_release_site_is_fully_closed(self) -> None:
        fixture, temporary = self.compose()
        self.addCleanup(temporary.cleanup)
        apt_inspector = mock.Mock()
        rpm_inspector = mock.Mock()
        result = self.verify(
            fixture,
            apt_bootstrap_inspector=apt_inspector,
            rpm_bootstrap_inspector=rpm_inspector,
        )
        self.assertEqual(10, result["audit_release_id"])
        self.assertEqual("add_release", result["operation"])
        manifest = json.loads((
            fixture.output / "site" / verifier.BOOTSTRAP_MANIFEST_PATH
        ).read_text())
        for item in manifest["packages"].values():
            self.assertEqual(
                (fixture.output / "site" / item["repository_path"]).read_bytes(),
                (fixture.output / "site" / item["download_path"]).read_bytes(),
            )
        apt_inspector.assert_called_once()
        rpm_inspector.assert_called_once()

    def test_bootstrap_static_content_inspection_is_mandatory(self) -> None:
        for family in ("apt", "rpm"):
            with self.subTest(family=family):
                fixture, temporary = self.compose()
                with temporary:
                    def reject(*_args) -> None:
                        raise verifier.VerificationError(
                            f"{family.upper()} bootstrap package content is invalid"
                        )

                    arguments = {
                        f"{family}_bootstrap_inspector": reject,
                    }
                    with self.assertRaisesRegex(
                        verifier.VerificationError,
                        f"{family.upper()} bootstrap package content is invalid",
                    ):
                        self.verify(fixture, **arguments)

    def test_apt_bootstrap_content_inspector_enforces_exact_repository_files(self) -> None:
        certificate = ROOT / "keys/apt-preview.asc"
        keyring = verifier.B.dearmor_public_certificate(
            certificate.read_bytes(), "APT public certificate"
        )
        with TemporaryDirectory() as temporary:
            package = Path(temporary) / "wukongim-archive-keyring_1.0.0_all.deb"
            verifier.B.build_deb(package, "1.0.0", keyring)
            verifier.inspect_apt_bootstrap_package(package, "1.0.0", certificate)

            wrong_keyring = verifier.B.dearmor_public_certificate(
                (ROOT / "keys/rpm-preview.asc").read_bytes(), "RPM public certificate"
            )
            verifier.B.build_deb(package, "1.0.0", wrong_keyring)
            with self.assertRaisesRegex(
                verifier.VerificationError, "keyring payload differs"
            ):
                verifier.inspect_apt_bootstrap_package(package, "1.0.0", certificate)

    def test_rpm_bootstrap_content_inspector_is_bounded_and_data_only(self) -> None:
        certificate = ROOT / "keys/rpm-preview.asc"
        certificate_sha = sha256(certificate.read_bytes())
        repository_sha = sha256(verifier.B.RPM_REPOSITORY)

        def result(stdout: bytes = b"", returncode: int = 0):
            return subprocess.CompletedProcess([], returncode, stdout, b"")

        valid_results = [
            result(
                b"/etc/pki/rpm-gpg/RPM-GPG-KEY-wukongim-preview\n"
                b"/etc/yum.repos.d/wukongim-preview.repo\n"
            ),
            result(),
            result(b"8\n"),
            result(
                f"/etc/pki/rpm-gpg/RPM-GPG-KEY-wukongim-preview\t{certificate_sha}"
                "\t0\t-rw-r--r--\n"
                f"/etc/yum.repos.d/wukongim-preview.repo\t{repository_sha}"
                "\t17\t-rw-r--r--\n".encode()
            ),
            result(),
        ]
        with mock.patch.object(verifier, "_tool", return_value="rpm"), \
             mock.patch.object(verifier, "run_command", side_effect=valid_results) as run:
            verifier.inspect_rpm_bootstrap_package(
                Path("bootstrap.rpm"), "1.0.0", certificate
            )
        self.assertEqual(5, run.call_count)

        with mock.patch.object(verifier, "_tool", return_value="rpm"), \
             mock.patch.object(
                 verifier,
                 "run_command",
                 side_effect=[valid_results[0], result(b"postinstall scriptlet\n")],
             ):
            with self.assertRaisesRegex(verifier.VerificationError, "contains scriptlets"):
                verifier.inspect_rpm_bootstrap_package(
                    Path("bootstrap.rpm"), "1.0.0", certificate
                )

    def test_bootstrap_manifest_and_direct_downloads_fail_closed(self) -> None:
        for mutation, pattern in (
            ("manifest", "fields must be exactly"),
            ("direct", "direct APT bootstrap download differs"),
            ("missing", "omits the required bootstrap package manifest"),
        ):
            with self.subTest(mutation=mutation):
                fixture, temporary = self.compose()
                with temporary:
                    manifest_path = fixture.output / "site" / verifier.BOOTSTRAP_MANIFEST_PATH
                    manifest = json.loads(manifest_path.read_text())
                    if mutation == "manifest":
                        manifest["unknown"] = True
                        manifest_path.write_bytes(canonical(manifest))
                    elif mutation == "direct":
                        direct = fixture.output / "site" / manifest["packages"]["apt"]["download_path"]
                        direct.write_bytes(direct.read_bytes() + b"tampered")
                    else:
                        manifest_path.unlink()
                    with self.assertRaisesRegex(verifier.VerificationError, pattern):
                        self.verify(fixture)

    def test_repository_setup_entrypoint_is_exact_and_in_the_site_closure(self) -> None:
        for mutation, pattern in (
            ("missing", "omits the required repository setup entrypoint"),
            ("tampered", "differs from reviewed bootstrap identities"),
        ):
            with self.subTest(mutation=mutation):
                fixture, temporary = self.compose()
                with temporary:
                    entrypoint = (
                        fixture.output / "site" / verifier.C.REPOSITORY_ENTRYPOINT_PATH
                    )
                    if mutation == "missing":
                        entrypoint.unlink()
                    else:
                        entrypoint.write_bytes(entrypoint.read_bytes() + b"# tampered\n")
                    with self.assertRaisesRegex(verifier.VerificationError, pattern):
                        self.verify(fixture)

    def test_only_the_exact_first_bootstrap_audit_may_omit_repo_entrypoint(self) -> None:
        fixture, temporary = self.compose()
        self.addCleanup(temporary.cleanup)
        site = fixture.output / "site"
        (site / verifier.C.REPOSITORY_ENTRYPOINT_PATH).unlink()
        audit_id, control_sha = next(
            iter(verifier.LEGACY_REPOSITORY_ENTRYPOINT_FREE_SNAPSHOTS)
        )
        channels = json.loads(fixture.channels.read_text())
        channels["channels"]["preview"]["publication"]["audit_release_id"] = audit_id
        channels["channels"]["preview"]["releases"][0]["package_release_id"] = audit_id
        fixture.channels.write_text(json.dumps(channels, indent=2) + "\n")
        snapshot_path = fixture.output / "audit/snapshot.json"
        snapshot = json.loads(snapshot_path.read_text())
        snapshot["audit_release_id"] = audit_id
        snapshot["control_sha"] = control_sha
        snapshot["releases"][0]["package_release_id"] = audit_id
        snapshot_path.write_bytes(canonical(snapshot))
        status_path = site / "status.json"
        status = json.loads(status_path.read_text())
        status["audit_release_id"] = audit_id
        status["control_sha"] = control_sha
        status["snapshot_sha256"] = sha256(snapshot_path.read_bytes())
        status_path.write_bytes(canonical(status))

        self.verify(fixture)

        snapshot["control_sha"] = "0" * 40
        snapshot_path.write_bytes(canonical(snapshot))
        status["control_sha"] = "0" * 40
        status["snapshot_sha256"] = sha256(snapshot_path.read_bytes())
        status_path.write_bytes(canonical(status))
        with self.assertRaisesRegex(
            verifier.VerificationError, "omits the required repository setup entrypoint"
        ):
            self.verify(fixture)

    def test_bootstrap_packages_are_mandatory_members_of_both_indexes(self) -> None:
        for family in ("apt", "rpm"):
            with self.subTest(family=family):
                fixture, temporary = self.compose()
                with temporary:
                    if family == "apt":
                        self._remove_bootstrap_from_apt_index(fixture)
                    else:
                        self._close_secondary_rpm_metadata(
                            fixture, include_bootstrap=False
                        )
                    with self.assertRaisesRegex(
                        verifier.VerificationError,
                        "active reviewed and bootstrap",
                    ):
                        self.verify(fixture)

    def test_bootstrap_package_headers_are_bound_to_manifest_identity(self) -> None:
        for family in ("apt", "rpm"):
            with self.subTest(family=family):
                fixture, temporary = self.compose()
                with temporary:
                    if family == "apt":
                        ordinary = self._deb_query(fixture)

                        def wrong(path: Path) -> dict[str, str]:
                            result = dict(ordinary(path))
                            if result["name"] == "wukongim-archive-keyring":
                                result["architecture"] = "amd64"
                            return result

                        arguments = {"deb_query": wrong}
                    else:
                        ordinary = self._rpm_query(fixture)

                        def wrong(path: Path) -> dict[str, str]:
                            result = dict(ordinary(path))
                            if result["name"] == "wukongim-release":
                                result["architecture"] = "x86_64"
                            return result

                        arguments = {"rpm_query": wrong}
                    with self.assertRaisesRegex(
                        verifier.VerificationError,
                        f"{family.upper()} bootstrap package header identity differs",
                    ):
                        self.verify(fixture, **arguments)

    def test_only_the_exact_prebootstrap_audit_may_omit_bootstrap_packages(self) -> None:
        fixture, temporary = self.compose()
        self.addCleanup(temporary.cleanup)
        self._make_legacy_bootstrap_free_site(fixture)

        result = self.verify(fixture)

        self.assertEqual(381152722, result["audit_release_id"])

    def test_update_bootstrap_requires_new_packages_and_no_source_evidence(self) -> None:
        fixture, temporary = self.compose()
        self.addCleanup(temporary.cleanup)
        channels = json.loads(fixture.channels.read_text())
        publication = channels["channels"]["preview"]["publication"]
        publication.update({"base_audit_release_id": 9, "operation": "update_bootstrap"})
        fixture.channels.write_text(json.dumps(channels, indent=2) + "\n")
        snapshot_path = fixture.output / "audit/snapshot.json"
        snapshot = json.loads(snapshot_path.read_text())
        snapshot["source_attestations"] = None
        snapshot_path.write_bytes(canonical(snapshot))
        for path in (fixture.output / "audit/source-attestations").iterdir():
            path.unlink()
        (fixture.output / "audit/source-attestations").rmdir()
        status_path = fixture.output / "site/status.json"
        status = json.loads(status_path.read_text())
        status["operation"] = "update_bootstrap"
        status["snapshot_sha256"] = sha256(snapshot_path.read_bytes())
        status_path.write_bytes(canonical(status))

        result = self.verify(fixture)
        self.assertEqual("update_bootstrap", result["operation"])

        manifest_path = fixture.output / "site" / verifier.BOOTSTRAP_MANIFEST_PATH
        manifest = json.loads(manifest_path.read_text())
        manifest["packages"]["apt"]["new"] = False
        manifest["packages"]["rpm"]["new"] = False
        manifest_path.write_bytes(canonical(manifest))
        with self.assertRaisesRegex(verifier.VerificationError, "must publish new"):
            self.verify(fixture)

    def test_new_rpm_requires_current_and_rejects_next_or_historical(self) -> None:
        for issuer in (fixtures.RPM_NEXT, RPM_HISTORICAL, RPM_UNKNOWN):
            with self.subTest(issuer=issuer):
                fixture, temporary = self.compose()
                with temporary:
                    if issuer == RPM_HISTORICAL:
                        self._add_historical_control(fixture)
                    with self.assertRaisesRegex(verifier.VerificationError, "rotation allowlist|next subkey"):
                        self.verify(
                            fixture,
                            rpm_issuers=lambda _path, _cert, _allowed, value=issuer: value,
                        )

    def test_preserved_rpm_accepts_current_or_historical_but_never_next(self) -> None:
        for issuer, accepted in (
            (fixtures.RPM_SUBKEY, True), (RPM_HISTORICAL, True),
            (fixtures.RPM_NEXT, False), (RPM_UNKNOWN, False),
        ):
            with self.subTest(issuer=issuer):
                fixture, temporary = self.compose("indexes_removed")
                with temporary:
                    self._add_historical_control(fixture)
                    if accepted:
                        self.verify(
                            fixture,
                            rpm_issuers=lambda _path, _cert, _allowed, value=issuer: value,
                        )
                    else:
                        with self.assertRaisesRegex(verifier.VerificationError,
                                                    "rotation allowlist|next subkey"):
                            self.verify(
                                fixture,
                                rpm_issuers=lambda _path, _cert, _allowed, value=issuer: value,
                            )

    def test_preserved_rpm_rejects_revoked_or_expired_historical_issuer(self) -> None:
        for validity in ("r", "e"):
            with self.subTest(validity=validity):
                fixture, temporary = self.compose("indexes_removed")
                with temporary:
                    self._add_historical_control(fixture)
                    ordinary = self._topology(fixture)

                    def unusable(path: Path) -> dict[str, Any]:
                        result = ordinary(path)
                        if "rpm" in path.name:
                            for record in result["subkeys"]:
                                if record["fingerprint"] == RPM_HISTORICAL:
                                    record["validity"] = validity
                        return result

                    with self.assertRaisesRegex(verifier.VerificationError,
                                                "unusable historical"):
                        self.verify(
                            fixture,
                            rpm_issuers=lambda _path, _cert, _allowed: RPM_HISTORICAL,
                            topology_inspector=unusable,
                        )

    def test_apt_and_repomd_require_exact_current_fingerprint(self) -> None:
        fixture, temporary = self.compose()
        self.addCleanup(temporary.cleanup)
        with self.assertRaisesRegex(verifier.VerificationError, "APT .*current"):
            self.verify(fixture, apt_issuer=fixtures.APT_NEXT)
        with self.assertRaisesRegex(verifier.VerificationError, "RPM repomd.*current"):
            self.verify(fixture, rpm_metadata_issuer=fixtures.RPM_NEXT)

    def test_rejects_wrong_or_duplicate_apt_release_policy_header(self) -> None:
        for kind in ("wrong", "duplicate", "malformed"):
            with self.subTest(kind=kind):
                fixture, temporary = self.compose()
                with temporary:
                    release = fixture.output / "site/apt/dists/preview/Release"
                    contents = release.read_bytes()
                    if kind == "wrong":
                        contents = contents.replace(b"Suite: preview\n", b"Suite: stable\n")
                    elif kind == "duplicate":
                        contents = b"Origin: WuKongIM\n" + contents
                    else:
                        contents = contents.replace(b"Label: WuKongIM\n", b"malformed\n")
                    release.write_bytes(contents)
                    with self.assertRaisesRegex(
                        verifier.VerificationError,
                        "must be exactly|duplicate Origin|malformed header",
                    ):
                        self.verify(fixture)

    def test_rejects_extra_apt_policy_headers_and_future_date(self) -> None:
        for name, value in (
            ("NotAutomatic", "yes"),
            ("ButAutomaticUpgrades", "yes"),
            ("Valid-Until", "Tue, 08 Sep 2026 00:00:00 +0000"),
            ("Signed-By", fixtures.APT_SUBKEY),
        ):
            with self.subTest(name=name):
                fixture, temporary = self.compose()
                with temporary:
                    release = fixture.output / "site/apt/dists/preview/Release"
                    release.write_bytes(f"{name}: {value}\n".encode() + release.read_bytes())
                    with self.assertRaisesRegex(verifier.VerificationError,
                                                "exactly.*builder allowlist"):
                        self.verify(fixture)

        fixture, temporary = self.compose()
        with temporary:
            release = fixture.output / "site/apt/dists/preview/Release"
            release.write_bytes(release.read_bytes().replace(
                b"Date: Tue, 01 Sep 2026 00:00:00 +0000\n",
                b"Date: Fri, 01 Jan 2100 00:00:00 +0000\n",
            ))
            with self.assertRaisesRegex(verifier.VerificationError, "future clock skew"):
                self.verify(fixture)

    def test_rejects_tampered_payload_or_metadata(self) -> None:
        for kind in ("payload", "metadata"):
            with self.subTest(kind=kind):
                fixture, temporary = self.compose()
                with temporary:
                    if kind == "payload":
                        path = fixture.output / "site" / fixtures.composer.expected_payload_path(
                            "apt", fixtures.V1
                        )
                    else:
                        path = fixture.output / "site/rpm/preview/el/9/x86_64/repodata/primary.xml"
                    path.write_bytes(path.read_bytes() + b"tampered")
                    with self.assertRaisesRegex(verifier.VerificationError, "digest differs|identity differs"):
                        self.verify(fixture)

    def test_rejects_inconsistent_weak_apt_checksum_section(self) -> None:
        fixture, temporary = self.compose()
        self.addCleanup(temporary.cleanup)
        release = fixture.output / "site/apt/dists/preview/Release"
        release.write_bytes(release.read_bytes().replace(
            md5((fixture.output / "site/apt/dists/preview/main/binary-amd64/Packages").read_bytes()).encode(),
            b"0" * 32,
            1,
        ))
        with self.assertRaisesRegex(verifier.VerificationError, "MD5Sum identity differs"):
            self.verify(fixture)

    def test_rejects_signed_but_semantically_wrong_rpm_metadata(self) -> None:
        fixture, temporary = self.compose()
        self.addCleanup(temporary.cleanup)
        primary = fixture.output / "site/rpm/preview/el/9/x86_64/repodata/primary.xml"
        expected = verifier.rpm_package_version(fixtures.V1).encode()
        primary.write_bytes(primary.read_bytes().replace(expected, b"9.9.9~forged"))
        self._rewrite_repomd(fixture)
        with self.assertRaisesRegex(verifier.VerificationError, "version identity differs"):
            self.verify(fixture)

    def test_rejects_signed_but_semantically_wrong_apt_metadata(self) -> None:
        fixture, temporary = self.compose()
        self.addCleanup(temporary.cleanup)
        packages = fixture.output / "site/apt/dists/preview/main/binary-amd64/Packages"
        expected = verifier.apt_package_version(fixtures.V1).encode()
        packages.write_bytes(packages.read_bytes().replace(expected, b"9.9.9~forged"))
        self._rewrite_apt_hashes(fixture)
        with self.assertRaisesRegex(verifier.VerificationError, "semantic identity differs"):
            self.verify(fixture)

    def test_rejects_actual_deb_or_rpm_header_identity_mismatch(self) -> None:
        for family in ("apt", "rpm"):
            with self.subTest(family=family):
                fixture, temporary = self.compose()
                with temporary:
                    deb_query = self._deb_query(fixture)
                    rpm_query = self._rpm_query(fixture)
                    if family == "apt":
                        def wrong_deb(path: Path) -> dict[str, str]:
                            result = dict(deb_query(path))
                            result["version"] = "9.9.9~forged"
                            return result
                        kwargs = {"deb_query": wrong_deb}
                    else:
                        def wrong_rpm(path: Path) -> dict[str, str]:
                            result = dict(rpm_query(path))
                            result["architecture"] = "aarch64"
                            return result
                        kwargs = {"rpm_query": wrong_rpm}
                    with self.assertRaisesRegex(verifier.VerificationError,
                                                "payload header identity differs"):
                        self.verify(fixture, **kwargs)

    def test_rejects_extra_file_symlink_and_unsafe_path(self) -> None:
        for kind in ("extra", "symlink", "unsafe"):
            with self.subTest(kind=kind):
                fixture, temporary = self.compose()
                with temporary:
                    site = fixture.output / "site"
                    if kind == "extra":
                        (site / "unreviewed.js").write_bytes(b"unexpected")
                    elif kind == "symlink":
                        (site / "linked").symlink_to("status.json")
                    else:
                        (site / "bad\\path").write_bytes(b"unexpected")
                    with self.assertRaisesRegex(verifier.VerificationError,
                                                "file closure|regular file|unsafe path|canonical relative"):
                        self.verify(fixture)

    def test_rejects_site_key_substitution(self) -> None:
        fixture, temporary = self.compose()
        self.addCleanup(temporary.cleanup)
        (fixture.output / "site/keys/rpm-preview.asc").write_bytes(fixtures.APT_CERT)
        with self.assertRaisesRegex(verifier.VerificationError, "public certificate differs"):
            self.verify(fixture)

    def test_read_only_gpg_checks_always_use_an_explicit_home(self) -> None:
        fingerprint = "A" * 40
        shown = (
            "pub:u:3072:1:0000000000000000:1:2:::::c:\n"
            f"fpr:::::::::{fingerprint}:\n"
        ).encode()
        commands: list[list[str]] = []
        results = iter([
            subprocess.CompletedProcess([], 0, b":public key packet:\n", b""),
            subprocess.CompletedProcess([], 0, shown, b""),
        ])

        def run(command, _label, **_kwargs):
            commands.append(command)
            return next(results)

        with TemporaryDirectory() as temporary, \
             mock.patch.object(verifier, "_tool", side_effect=lambda value: value), \
             mock.patch.object(verifier, "run_command", side_effect=run):
            certificate = Path(temporary) / "certificate.asc"
            certificate.write_bytes(b"public-only test certificate")
            topology = verifier.inspect_public_certificate(certificate)

        self.assertEqual(fingerprint, topology["primary"]["fingerprint"])
        self.assertEqual(2, len(commands))
        self.assertTrue(all("--homedir" in command for command in commands))

    def test_rpm_candidate_export_is_armored_for_rpm_import(self) -> None:
        candidate = fixtures.RPM_SUBKEY
        armor = (
            b"-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n"
            b"integration\n-----END PGP PUBLIC KEY BLOCK-----\n"
        )
        commands: list[list[str]] = []

        def run(command, _label, **_kwargs):
            commands.append(command)
            if "--export" in command:
                return subprocess.CompletedProcess([], 0, armor, b"")
            return subprocess.CompletedProcess([], 0, b"", b"")

        topology = {
            "primary": {"fingerprint": "A" * 40},
            "subkeys": [{"fingerprint": candidate}],
        }
        with mock.patch.object(verifier, "_tool", side_effect=lambda value: value), \
             mock.patch.object(verifier, "run_command", side_effect=run), \
             mock.patch.object(verifier, "inspect_public_certificate", return_value=topology):
            exported = verifier.export_rpm_candidate_certificates(
                Path("certificate.asc"), [candidate]
            )

        self.assertEqual(armor, exported[candidate])
        export_command = next(command for command in commands if "--export" in command)
        self.assertIn("--armor", export_command)
        filter_index = export_command.index("--export-filter")
        self.assertEqual(
            f"drop-subkey=fpr <> {candidate}", export_command[filter_index + 1]
        )

    def test_rpm_candidate_export_isolates_real_rotation_subkeys(self) -> None:
        signing = json.loads((ROOT / "manifests/preview-signing.json").read_text())
        rpm_signing = signing["rpm"]["signing_subkeys"]
        candidates = [rpm_signing["current"], rpm_signing["next"]]

        exported = verifier.export_rpm_candidate_certificates(
            ROOT / "keys/rpm-preview.asc", candidates
        )

        self.assertEqual(set(candidates), set(exported))
        self.assertTrue(all(value.startswith(b"-----BEGIN PGP PUBLIC KEY BLOCK-----")
                            for value in exported.values()))

    def test_rpm_packet_requires_full_issuer_and_sha256_not_sha512(self) -> None:
        signature = (
            b"-----BEGIN PGP SIGNATURE-----\nTEST\n-----END PGP SIGNATURE-----\n"
        )

        def process(returncode: int = 0, stdout: bytes = b"", stderr: bytes = b""):
            return subprocess.CompletedProcess([], returncode, stdout, stderr)

        sha256_packet = (
            f":signature packet: algo 1, keyid 00000000\n"
            f"\tdigest algo 8, begin of digest 00 00\n"
            f"\thashed subpkt 33 len 21 (issuer fpr v4 {fixtures.RPM_SUBKEY})\n"
        ).encode()

        def inspect(packet: bytes) -> str:
            with mock.patch.object(verifier, "_tool", side_effect=lambda value: value), \
                 mock.patch.object(
                     verifier, "run_command",
                     side_effect=[process(stdout=signature), process(stdout=packet)],
                 ):
                return verifier.rpm_signature_packet_issuer(Path("package.rpm"))

        self.assertEqual(fixtures.RPM_SUBKEY, inspect(sha256_packet))

        sha512_packet = sha256_packet.replace(b"digest algo 8,", b"digest algo 10,")
        with self.assertRaisesRegex(verifier.VerificationError, "SHA-256"):
            inspect(sha512_packet)

        duplicate_digest = sha256_packet.replace(
            b"\tdigest algo 8,", b"\tdigest algo 8, duplicate\n\tdigest algo 8,"
        )
        with self.assertRaisesRegex(verifier.VerificationError, "exactly.*SHA-256"):
            inspect(duplicate_digest)

        unhashed_only = sha256_packet.replace(b"\thashed subpkt", b"\tunhashed subpkt")
        with self.assertRaisesRegex(verifier.VerificationError, "hashed full issuer"):
            inspect(unhashed_only)

        mixed_claims = (
            sha256_packet.replace(fixtures.RPM_SUBKEY.encode(), RPM_HISTORICAL.encode())
            + f"\tunhashed subpkt 33 len 21 (issuer fpr v4 {fixtures.RPM_SUBKEY})\n".encode()
        )
        with self.assertRaisesRegex(verifier.VerificationError, "hashed full issuer"):
            inspect(mixed_claims)

        v5_unhashed_claim = (
            sha256_packet
            + f"\tunhashed subpkt 33 len 33 (issuer fpr v5 {fixtures.RPM_SUBKEY})\n".encode()
        )
        with self.assertRaisesRegex(verifier.VerificationError, "hashed full issuer"):
            inspect(v5_unhashed_claim)

    def test_rpm_hashed_claim_must_equal_candidate_only_crypto_success(self) -> None:
        candidates = {fixtures.RPM_SUBKEY, RPM_HISTORICAL}
        exports = {value: value.encode() for value in candidates}
        with mock.patch.object(
            verifier, "rpm_signature_packet_issuer", return_value=fixtures.RPM_SUBKEY
        ), mock.patch.object(
            verifier, "export_rpm_candidate_certificates", return_value=exports
        ), mock.patch.object(
            verifier, "rpm_candidate_signature_verifies",
            side_effect=lambda _package, _cert, candidate: candidate == RPM_HISTORICAL,
        ):
            with self.assertRaisesRegex(verifier.VerificationError,
                                        "claim differs.*cryptographic signer"):
                verifier.verify_rpm_package_signature(
                    Path("package.rpm"), Path("key.asc"), candidates
                )


if __name__ == "__main__":
    unittest.main()
