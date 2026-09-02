from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "sign-package-family.py"
SIGNER_SPEC = importlib.util.spec_from_file_location("package_family_signer", SCRIPT)
assert SIGNER_SPEC is not None and SIGNER_SPEC.loader is not None
signer = importlib.util.module_from_spec(SIGNER_SPEC)
SIGNER_SPEC.loader.exec_module(signer)
VALIDATOR_TEST = ROOT / "tests" / "test_validate_signing_material.py"
FACTORY_SPEC = importlib.util.spec_from_file_location("signer_test_key_factory", VALIDATOR_TEST)
assert FACTORY_SPEC is not None and FACTORY_SPEC.loader is not None
factory_module = importlib.util.module_from_spec(FACTORY_SPEC)
sys.modules[FACTORY_SPEC.name] = factory_module
FACTORY_SPEC.loader.exec_module(factory_module)
PASSPHRASE = factory_module.PASSPHRASE


def canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"


def identity(path: Path, relative: str) -> dict[str, object]:
    contents = path.read_bytes()
    return {"path": relative, "sha256": hashlib.sha256(contents).hexdigest(), "size": len(contents)}


class PackageFamilySigningTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if shutil.which("gpg") is None or shutil.which("gpgconf") is None:
            raise unittest.SkipTest("gpg and gpgconf are required")
        cls.temporary = TemporaryDirectory(prefix="wk-family-signer-TEST-ONLY-", dir="/tmp")
        cls.root = Path(cls.temporary.name)
        cls.factory = factory_module.TestKeyFactory(cls.root / "keys")
        cls.key = cls.factory.generate(
            "FAMILY-SIGNER", signing_expiration="60d", add_encryption_subkey=False,
            algorithm="rsa3072",
        )
        signature_payload = cls.root / "rpm-header-signature-payload"
        signature_path = cls.root / "rpm-header-signature.asc"
        signature_payload.write_bytes(b"TEST ONLY RPM header signature packet\n")
        cls.factory._gpg(
            cls.key.home,
            [
                "--pinentry-mode", "loopback", "--passphrase-fd", "0",
                "--local-user", f"{cls.key.signing_subkey_fingerprint}!",
                "--digest-algo", "SHA256",
                "--armor", "--output", str(signature_path), "--detach-sign",
                str(signature_payload),
            ],
            input_bytes=PASSPHRASE + b"\n",
        )
        cls.rpm_header_signature = signature_path.read_text(encoding="ascii")
        cls.fake_bin = cls.root / "fake-bin"
        cls.fake_bin.mkdir()
        cls._write_fake_tools()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.factory.close()
        cls.temporary.cleanup()

    @classmethod
    def _write_tool(cls, name: str, body: str) -> None:
        path = cls.fake_bin / name
        path.write_text("#!/usr/bin/env python3\n" + body, encoding="utf-8")
        path.chmod(0o755)

    @classmethod
    def _write_fake_tools(cls) -> None:
        signature_literal = repr(cls.rpm_header_signature)
        cls._write_tool(
            "rpm",
            f"""import sys
if "-qp" in sys.argv:
    sys.stdout.write({signature_literal})
raise SystemExit(0)
""",
        )
        cls._write_tool(
            "rpmkeys",
            """import pathlib, re, sys
package = pathlib.Path(sys.argv[-1])
match = re.search(br"WK-RPM-SIGNATURE:([0-9A-F]{40})\\n", package.read_bytes())
if match:
    fingerprint = match.group(1).decode()
    print(f"{package}: Header V4 RSA/SHA256 Signature, key ID {fingerprint[-16:]}: OK")
else:
    print(f"{package}: digests OK")
raise SystemExit(0)
""",
        )
        cls._write_tool(
            "rpmsign",
            """import pathlib, sys
package = pathlib.Path(sys.argv[-1])
if package.name.startswith("fail-"):
    raise SystemExit(42)
fingerprint = None
for index, value in enumerate(sys.argv[:-1]):
    if value == "--define" and sys.argv[index + 1].startswith("_gpg_name "):
        fingerprint = sys.argv[index + 1].split()[1].removesuffix("!")
if fingerprint is None:
    raise SystemExit(43)
package.write_bytes(package.read_bytes() + f"WK-RPM-SIGNATURE:{fingerprint}\\n".encode())
""",
        )
        cls._write_tool(
            "createrepo_c",
            """import pathlib, sys
root = pathlib.Path(sys.argv[-1])
packages = sorted(path.relative_to(root).as_posix() for path in root.glob("Packages/**/*.rpm"))
repodata = root / "repodata"
repodata.mkdir()
(repodata / "repomd.xml").write_text("<repomd>" + "".join(f"<package>{path}</package>" for path in packages) + "</repomd>\\n")
(repodata / "primary.xml.gz").write_bytes(("\\n".join(packages) + "\\n").encode())
""",
        )

    def setUp(self) -> None:
        self.case = self.root / self.id().rsplit(".", 1)[-1]
        self.case.mkdir()

    def environment(self) -> dict[str, str]:
        environment = os.environ.copy()
        environment["PATH"] = f"{self.fake_bin}{os.pathsep}{environment.get('PATH', '')}"
        environment["WK_TEST_SECRET_SUBKEY"] = self.key.selected_secret_base64.read_text(
            encoding="ascii"
        )
        environment["WK_TEST_PASSPHRASE"] = PASSPHRASE.decode()
        return environment

    def base_command(self, family: str, source: Path, output: Path) -> list[str]:
        return [
            sys.executable,
            str(SCRIPT),
            "--family",
            family,
            "--input-root",
            str(source),
            "--output-root",
            str(output),
            "--public-cert",
            str(self.key.public_cert),
            "--secret-subkey-base64-env",
            "WK_TEST_SECRET_SUBKEY",
            "--passphrase-env",
            "WK_TEST_PASSPHRASE",
            "--primary-fingerprint",
            self.key.primary_fingerprint,
            "--signing-subkey-fingerprint",
            self.key.signing_subkey_fingerprint,
        ]

    def run_apt(self, source: Path, output: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [*self.base_command("apt", source, output), "--apt-release", "dists/preview/Release"],
            text=True,
            capture_output=True,
            env=self.environment(),
            check=False,
        )

    def write_rpm_allowlists(
        self,
        source: Path,
        *,
        new: list[str],
        signed: list[str],
        active: list[str],
    ) -> tuple[Path, Path, Path]:
        paths: list[Path] = []
        for name, values in (("new", new), ("signed", signed)):
            path = self.case / f"{name}.json"
            path.write_bytes(
                canonical_json(
                    {
                        "packages": [identity(source / value, value) for value in sorted(values)],
                        "schema": "wukongim/rpm-package-allowlist/v1",
                    }
                )
            )
            paths.append(path)
        active_path = self.case / "active.json"
        active_path.write_bytes(
            canonical_json(
                {"paths": sorted(active), "schema": "wukongim/rpm-active-allowlist/v1"}
            )
        )
        paths.append(active_path)
        return paths[0], paths[1], paths[2]

    def run_rpm(
        self,
        source: Path,
        output: Path,
        allowlists: tuple[Path, Path, Path],
    ) -> subprocess.CompletedProcess[str]:
        new, signed, active = allowlists
        return subprocess.run(
            [
                *self.base_command("rpm", source, output),
                "--rpm-repository",
                "preview/el/9/x86_64",
                "--new-rpm-allowlist",
                str(new),
                "--signed-rpm-allowlist",
                str(signed),
                "--active-rpm-allowlist",
                str(active),
            ],
            text=True,
            capture_output=True,
            env=self.environment(),
            check=False,
        )

    @staticmethod
    def create_apt_source(root: Path) -> Path:
        release = root / "dists" / "preview" / "Release"
        release.parent.mkdir(parents=True)
        release.write_bytes(b"Suite: preview\nSHA256:\n")
        return release

    def create_rpm_source(self, names: list[str]) -> tuple[Path, dict[str, bytes]]:
        source = self.case / "rpm-input"
        packages = source / "preview" / "el" / "9" / "x86_64" / "Packages"
        packages.mkdir(parents=True)
        contents: dict[str, bytes] = {}
        for name in names:
            relative = f"Packages/{name}"
            payload = f"RPM-TEST-ONLY:{name}\n".encode()
            if name.startswith(("old-", "retired-")):
                payload += f"WK-RPM-SIGNATURE:{self.key.signing_subkey_fingerprint}\n".encode()
            (packages / name).write_bytes(payload)
            contents[relative] = payload
        return source, contents

    def assert_safe_failure(self, result: subprocess.CompletedProcess[str], expected: str) -> None:
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn(expected, result.stderr)
        self.assertNotIn(PASSPHRASE.decode(), result.stdout + result.stderr)
        self.assertNotIn(self.key.selected_secret_base64.read_text(), result.stdout + result.stderr)

    def test_apt_signs_only_the_exact_release_and_emits_canonical_receipt(self) -> None:
        source = self.case / "apt-input"
        release = self.create_apt_source(source)
        output = self.case / "apt-output"
        result = self.run_apt(source, output)
        self.assertEqual(result.returncode, 0, result.stderr)
        receipt = json.loads(result.stdout)
        self.assertEqual(result.stdout.encode(), canonical_json(receipt))
        self.assertEqual(receipt["family"], "apt")
        self.assertEqual(receipt["key"]["family"], "apt")
        self.assertEqual((output / "dists/preview/Release").read_bytes(), release.read_bytes())
        self.assertTrue((output / "dists/preview/InRelease").is_file())
        self.assertTrue((output / "dists/preview/Release.gpg").is_file())
        self.assertFalse(any(path.name.endswith(".rpm") for path in output.rglob("*")))

    def test_apt_rejects_preexisting_signature_without_publishing_output(self) -> None:
        source = self.case / "apt-input"
        release = self.create_apt_source(source)
        (release.parent / "InRelease").write_bytes(b"unreviewed signature")
        output = self.case / "apt-output"
        result = self.run_apt(source, output)
        self.assert_safe_failure(result, "pre-existing Release signatures")
        self.assertFalse(os.path.lexists(output))

    def test_input_tree_rejects_symbolic_and_hard_links_before_reading_secrets(self) -> None:
        for kind in ("symbolic", "hard"):
            with self.subTest(kind=kind):
                source = self.case / f"apt-input-{kind}"
                release = self.create_apt_source(source)
                target = release.parent / "linked"
                if kind == "symbolic":
                    target.symlink_to(release)
                    expected = "linked or special file"
                else:
                    os.link(release, target)
                    expected = "hard-linked file"
                output = self.case / f"apt-output-{kind}"
                environment = self.environment()
                environment.pop("WK_TEST_SECRET_SUBKEY")
                environment.pop("WK_TEST_PASSPHRASE")
                result = subprocess.run(
                    [*self.base_command("apt", source, output),
                     "--apt-release", "dists/preview/Release"],
                    text=True,
                    capture_output=True,
                    env=environment,
                    check=False,
                )
                self.assert_safe_failure(result, expected)
                self.assertNotIn("environment variable is not set", result.stderr)
                self.assertFalse(os.path.lexists(output))

    def test_rpm_signs_only_new_preserves_existing_and_excludes_retired_from_metadata(self) -> None:
        source, original = self.create_rpm_source(
            ["new-wukongim.rpm", "old-wukongim.rpm", "retired-wukongim.rpm"]
        )
        repo = source / "preview/el/9/x86_64"
        allowlists = self.write_rpm_allowlists(
            repo,
            new=["Packages/new-wukongim.rpm"],
            signed=["Packages/old-wukongim.rpm", "Packages/retired-wukongim.rpm"],
            active=["Packages/new-wukongim.rpm", "Packages/old-wukongim.rpm"],
        )
        output = self.case / "rpm-output"
        result = self.run_rpm(source, output, allowlists)
        self.assertEqual(result.returncode, 0, result.stderr)
        receipt = json.loads(result.stdout)
        self.assertEqual(result.stdout.encode(), canonical_json(receipt))
        output_repo = output / "preview/el/9/x86_64"
        self.assertEqual(
            (output_repo / "Packages/old-wukongim.rpm").read_bytes(),
            original["Packages/old-wukongim.rpm"],
        )
        self.assertEqual(
            (output_repo / "Packages/retired-wukongim.rpm").read_bytes(),
            original["Packages/retired-wukongim.rpm"],
        )
        self.assertNotEqual(
            (output_repo / "Packages/new-wukongim.rpm").read_bytes(),
            original["Packages/new-wukongim.rpm"],
        )
        repomd = (output_repo / "repodata/repomd.xml").read_text()
        self.assertIn("new-wukongim.rpm", repomd)
        self.assertIn("old-wukongim.rpm", repomd)
        self.assertNotIn("retired-wukongim.rpm", repomd)
        self.assertTrue((output_repo / "repodata/repomd.xml.asc").is_file())
        self.assertEqual(
            [item["path"] for item in receipt["result"]["retired"]],
            ["Packages/retired-wukongim.rpm"],
        )

    def test_rpm_rotation_accepts_historical_preserved_signature_but_rejects_next(self) -> None:
        historical = "1" * 40
        successor = "2" * 40
        rpm_database = self.case / "rpmdb"
        rpm_database.mkdir()
        package = self.case / "preserved.rpm"
        package.write_bytes(
            b"RPM-TEST-ONLY:preserved\n"
            + f"WK-RPM-SIGNATURE:{historical}\n".encode()
        )
        with mock.patch.object(
            signer, "rpm_signature_issuer_fingerprint", return_value=historical
        ), mock.patch.object(
            signer, "rpm_verifying_fingerprints", return_value=(historical,)
        ):
            signer.rpm_signature_check(
                str(self.fake_bin / "rpm"),
                str(self.fake_bin / "rpmkeys"),
                mock.Mock(),
                rpm_database,
                package,
                (self.key.signing_subkey_fingerprint, historical),
                expect_signed=True,
                environment=self.environment(),
            )

        package.write_bytes(
            b"RPM-TEST-ONLY:preserved\n"
            + f"WK-RPM-SIGNATURE:{successor}\n".encode()
        )
        with self.assertRaisesRegex(
            signer.FamilySigningError, "reviewed current or historical"
        ), mock.patch.object(
            signer, "rpm_signature_issuer_fingerprint", return_value=successor
        ), mock.patch.object(
            signer, "rpm_verifying_fingerprints", return_value=()
        ):
            signer.rpm_signature_check(
                str(self.fake_bin / "rpm"),
                str(self.fake_bin / "rpmkeys"),
                mock.Mock(),
                rpm_database,
                package,
                (self.key.signing_subkey_fingerprint, historical),
                expect_signed=True,
                environment=self.environment(),
            )

    def test_rpm_verification_isolates_each_real_rotation_subkey(self) -> None:
        signing = json.loads((ROOT / "manifests/preview-signing.json").read_text())
        rpm_signing = signing["rpm"]["signing_subkeys"]
        candidates = (rpm_signing["current"], rpm_signing["next"])
        package = self.case / "rotating-wukongim.rpm"
        package.write_bytes(
            b"RPM-TEST-ONLY:rotating\n"
            + f"WK-RPM-SIGNATURE:{candidates[0]}\n".encode()
        )

        with TemporaryDirectory(prefix="wk-rpm-rotation-TEST-ONLY-", dir="/tmp") as name:
            home = Path(name)
            home.chmod(0o700)
            gpg = signer.validator.IsolatedGPG(
                home,
                shutil.which("gpg"),
                shutil.which("gpgconf"),
            )
            try:
                gpg.run(
                    ["--import", str(ROOT / "keys/rpm-preview.asc")],
                    stage="TEST ONLY RPM rotation-certificate import",
                )
                with mock.patch.object(signer.time, "time", return_value=1_788_279_420):
                    verified = signer.rpm_verifying_fingerprints(
                        str(self.fake_bin / "rpm"),
                        str(self.fake_bin / "rpmkeys"),
                        gpg,
                        package,
                        candidates,
                        environment=self.environment(),
                    )
            finally:
                gpg.kill_agent()

        self.assertEqual(candidates, verified)

    def test_rpm_rejects_ambiguous_allowed_key_ids_before_verification(self) -> None:
        current = "1" * 40
        collision = "2" * 24 + current[-16:]
        rpm_database = self.case / "rpmdb"
        rpm_database.mkdir()
        package = self.case / "preserved.rpm"
        package.write_bytes(b"RPM-TEST-ONLY:preserved\n")

        with self.assertRaisesRegex(
            signer.FamilySigningError, "unambiguous reviewed key IDs"
        ):
            signer.rpm_signature_check(
                str(self.fake_bin / "rpm"),
                str(self.fake_bin / "rpmkeys"),
                mock.Mock(),
                rpm_database,
                package,
                (current, collision),
                expect_signed=True,
                environment=self.environment(),
            )

    def test_rpm_rejects_non_sha256_header_signature_packet(self) -> None:
        rpm_database = self.case / "rpmdb"
        rpm_database.mkdir()
        package = self.case / "preserved.rpm"
        package.write_bytes(b"RPM-TEST-ONLY:preserved\n")
        gpg = mock.Mock()
        gpg.home = self.case
        gpg.run.return_value = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout=(
                b":signature packet: algo 1, keyid 0123456789ABCDEF\n"
                b"\tdigest algo 10, begin of digest 00 00\n"
                + f"\thashed subpkt 33 len 21 (issuer fpr v4 {self.key.signing_subkey_fingerprint})\n".encode()
            ),
            stderr=b"",
        )
        extracted = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=b"TEST ONLY signature packet\n", stderr=b""
        )
        with mock.patch.object(signer, "run_tool", return_value=extracted), self.assertRaisesRegex(
            signer.FamilySigningError, "must use SHA-256"
        ):
            signer.rpm_signature_issuer_fingerprint(
                str(self.fake_bin / "rpm"),
                gpg,
                rpm_database,
                package,
                environment=self.environment(),
            )

    def test_rpm_rejects_unhashed_current_issuer_fingerprint(self) -> None:
        rpm_database = self.case / "rpmdb"
        rpm_database.mkdir()
        package = self.case / "preserved.rpm"
        package.write_bytes(b"RPM-TEST-ONLY:preserved\n")
        gpg = mock.Mock()
        gpg.home = self.case
        gpg.run.return_value = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout=(
                b":signature packet: algo 1, keyid 0123456789ABCDEF\n"
                b"\tdigest algo 8, begin of digest 00 00\n"
                + f"\tsubpkt 33 len 21 (issuer fpr v4 {self.key.signing_subkey_fingerprint})\n".encode()
            ),
            stderr=b"",
        )
        extracted = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=b"TEST ONLY signature packet\n", stderr=b""
        )
        with mock.patch.object(signer, "run_tool", return_value=extracted), self.assertRaisesRegex(
            signer.FamilySigningError, "hashed subpacket"
        ):
            signer.rpm_signature_issuer_fingerprint(
                str(self.fake_bin / "rpm"),
                gpg,
                rpm_database,
                package,
                environment=self.environment(),
            )

    def test_rpm_rejects_hashed_historical_plus_unhashed_current_issuer(self) -> None:
        historical = "A" * 40
        rpm_database = self.case / "rpmdb"
        rpm_database.mkdir()
        package = self.case / "preserved.rpm"
        package.write_bytes(b"RPM-TEST-ONLY:preserved\n")
        gpg = mock.Mock()
        gpg.home = self.case
        gpg.run.return_value = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout=(
                b":signature packet: algo 1, keyid 0123456789ABCDEF\n"
                b"\tdigest algo 8, begin of digest 00 00\n"
                + f"\thashed subpkt 33 len 21 (issuer fpr v4 {historical})\n".encode()
                + f"\tsubpkt 33 len 21 (issuer fpr v4 {self.key.signing_subkey_fingerprint})\n".encode()
            ),
            stderr=b"",
        )
        extracted = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=b"TEST ONLY signature packet\n", stderr=b""
        )
        with mock.patch.object(signer, "run_tool", return_value=extracted), self.assertRaisesRegex(
            signer.FamilySigningError, "exactly one hashed issuer fingerprint"
        ):
            signer.rpm_signature_issuer_fingerprint(
                str(self.fake_bin / "rpm"),
                gpg,
                rpm_database,
                package,
                environment=self.environment(),
            )

    def test_openpgp_verification_rejects_non_sha256_validsig(self) -> None:
        status = (
            "[GNUPG:] VALIDSIG "
            f"{self.key.signing_subkey_fingerprint} 2026-09-01 1788220800 "
            "0 4 0 1 10 00 "
            f"{self.key.primary_fingerprint}\n"
        ).encode()
        with self.assertRaisesRegex(
            signer.FamilySigningError, "did not use SHA-256"
        ):
            signer.exact_signature_status(
                status,
                self.key.signing_subkey_fingerprint,
                "TEST ONLY signature verification",
            )

    def test_rpm_rejects_full_issuer_fingerprint_that_only_spoofs_key_id(self) -> None:
        current = "1" * 40
        collision = "2" * 24 + current[-16:]
        rpm_database = self.case / "rpmdb"
        rpm_database.mkdir()
        package = self.case / "preserved.rpm"
        package.write_bytes(
            b"RPM-TEST-ONLY:preserved\n"
            + f"WK-RPM-SIGNATURE:{collision}\n".encode()
        )

        with self.assertRaisesRegex(
            signer.FamilySigningError, "reviewed current or historical"
        ), mock.patch.object(
            signer, "rpm_signature_issuer_fingerprint", return_value=collision
        ), mock.patch.object(
            signer, "rpm_verifying_fingerprints", return_value=()
        ):
            signer.rpm_signature_check(
                str(self.fake_bin / "rpm"),
                str(self.fake_bin / "rpmkeys"),
                mock.Mock(),
                rpm_database,
                package,
                (current,),
                expect_signed=True,
                environment=self.environment(),
            )

    def test_rpm_rejects_hashed_current_claim_signed_by_historical_key(self) -> None:
        current = self.key.signing_subkey_fingerprint
        historical = "A" * 40
        rpm_database = self.case / "rpmdb"
        rpm_database.mkdir()
        package = self.case / "preserved.rpm"
        package.write_bytes(
            b"RPM-TEST-ONLY:preserved\n"
            + f"WK-RPM-SIGNATURE:{historical}\n".encode()
        )

        with self.assertRaisesRegex(
            signer.FamilySigningError, "differs from the cryptographically verified subkey"
        ), mock.patch.object(
            signer, "rpm_signature_issuer_fingerprint", return_value=current
        ), mock.patch.object(
            signer, "rpm_verifying_fingerprints", return_value=(historical,)
        ):
            signer.rpm_signature_check(
                str(self.fake_bin / "rpm"),
                str(self.fake_bin / "rpmkeys"),
                mock.Mock(),
                rpm_database,
                package,
                (current, historical),
                expect_signed=True,
                environment=self.environment(),
            )

    def test_rpm_rejects_incomplete_allowlist_atomically(self) -> None:
        source, _ = self.create_rpm_source(["new-one.rpm", "new-unlisted.rpm"])
        repo = source / "preview/el/9/x86_64"
        allowlists = self.write_rpm_allowlists(
            repo,
            new=["Packages/new-one.rpm"],
            signed=[],
            active=["Packages/new-one.rpm"],
        )
        output = self.case / "rpm-output"
        result = self.run_rpm(source, output, allowlists)
        self.assert_safe_failure(result, "do not close over the exact Packages payload set")
        self.assertFalse(os.path.lexists(output))

    def test_rpm_rejects_presigned_package_on_new_unsigned_allowlist(self) -> None:
        source, _ = self.create_rpm_source(["old-wukongim.rpm"])
        repo = source / "preview/el/9/x86_64"
        allowlists = self.write_rpm_allowlists(
            repo,
            new=["Packages/old-wukongim.rpm"],
            signed=[],
            active=["Packages/old-wukongim.rpm"],
        )
        output = self.case / "rpm-output"
        result = self.run_rpm(source, output, allowlists)
        self.assert_safe_failure(result, "already-signed or invalid package")
        self.assertFalse(os.path.lexists(output))

    def test_rpm_tool_failure_never_exposes_partial_output(self) -> None:
        source, _ = self.create_rpm_source(["fail-wukongim.rpm"])
        repo = source / "preview/el/9/x86_64"
        allowlists = self.write_rpm_allowlists(
            repo,
            new=["Packages/fail-wukongim.rpm"],
            signed=[],
            active=["Packages/fail-wukongim.rpm"],
        )
        output = self.case / "rpm-output"
        result = self.run_rpm(source, output, allowlists)
        self.assert_safe_failure(result, "repository tool failed during RPM payload signing")
        self.assertFalse(os.path.lexists(output))

    def test_environment_reader_removes_secret_name_immediately(self) -> None:
        validator = factory_module.validator
        name = "WK_TEST_POPPED_SECRET"
        os.environ[name] = "TEST-ONLY-value"
        try:
            self.assertEqual(validator.read_environment(name, "TEST ONLY"), b"TEST-ONLY-value")
            self.assertNotIn(name, os.environ)
        finally:
            os.environ.pop(name, None)


if __name__ == "__main__":
    unittest.main()
