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

    def _close_secondary_rpm_metadata(self, fixture: fixtures.Fixture) -> None:
        site = fixture.output / "site"
        snapshot = json.loads((fixture.output / "audit/snapshot.json").read_text())
        repository = site / "rpm/preview/el/9/x86_64"
        active = [item for item in snapshot["payloads"]["rpm"] if item["indexed"]]
        secondary_packages = "".join(
            f'<package pkgid="{item["published_sha256"]}" name="wukongim" arch="x86_64">'
            f'<version epoch="0" ver="{verifier.rpm_package_version(item["version"])}" rel="1"/>'
            "</package>"
            for item in active
        )
        primary_packages = "".join(
            '<package type="rpm"><name>wukongim</name><arch>x86_64</arch>'
            f'<version epoch="0" ver="{verifier.rpm_package_version(item["version"])}" rel="1"/>'
            f'<checksum type="sha256" pkgid="YES">{item["published_sha256"]}</checksum>'
            f'<size package="{(site / item["path"]).stat().st_size}"/>'
            f'<location href="{Path(item["path"]).relative_to("rpm/preview/el/9/x86_64").as_posix()}"/>'
            "</package>"
            for item in active
        )
        metadata = {
            "primary": f'<metadata packages="{len(active)}">{primary_packages}</metadata>\n'.encode(),
            "filelists": f'<filelists packages="{len(active)}">{secondary_packages}</filelists>\n'.encode(),
            "other": f'<otherdata packages="{len(active)}">{secondary_packages}</otherdata>\n'.encode(),
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
               topology_inspector=None, deb_query=None, rpm_query=None):
        rpm_issuers = rpm_issuers or (
            lambda _path, _cert, _allowed: fixtures.RPM_SUBKEY
        )
        topology_inspector = topology_inspector or self._topology(fixture)
        deb_query = deb_query or self._deb_query(fixture)
        rpm_query = rpm_query or self._rpm_query(fixture)
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
             mock.patch.object(verifier, "query_rpm_identity", side_effect=rpm_query):
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

    def test_valid_add_release_site_is_fully_closed(self) -> None:
        fixture, temporary = self.compose()
        self.addCleanup(temporary.cleanup)
        result = self.verify(fixture)
        self.assertEqual(10, result["audit_release_id"])
        self.assertEqual("add_release", result["operation"])

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
