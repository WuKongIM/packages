from __future__ import annotations

import base64
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import time
import unittest
from argparse import Namespace
from dataclasses import dataclass, replace
from pathlib import Path
from tempfile import TemporaryDirectory


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "validate-signing-material.py"
PASSPHRASE = b"WuKongIM-TEST-ONLY-signing-passphrase-42"
VALIDATOR_SPEC = importlib.util.spec_from_file_location("validate_signing_material", SCRIPT)
assert VALIDATOR_SPEC is not None and VALIDATOR_SPEC.loader is not None
validator = importlib.util.module_from_spec(VALIDATOR_SPEC)
sys.modules[VALIDATOR_SPEC.name] = validator
VALIDATOR_SPEC.loader.exec_module(validator)


@dataclass(frozen=True)
class GeneratedKey:
    home: Path
    public_cert: Path
    public_cert_with_extra_subkeys: Path
    selected_secret_base64: Path
    full_secret_base64: Path
    all_subkeys_secret_base64: Path
    passphrase_file: Path
    primary_fingerprint: str
    signing_subkey_fingerprint: str


class TestKeyFactory:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.counter = 0

    def _gpg(
        self,
        home: Path,
        arguments: list[str],
        *,
        input_bytes: bytes | None = None,
        fake_time: int | None = None,
    ) -> bytes:
        command = [
            "gpg",
            "--no-options",
            "--homedir",
            str(home),
            "--batch",
            "--no-tty",
        ]
        if fake_time is not None:
            command.extend(("--faked-system-time", str(fake_time)))
        command.extend(arguments)
        result = subprocess.run(
            command,
            input=input_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={
                "GNUPGHOME": str(home),
                "HOME": str(home),
                "LANG": "C",
                "LC_ALL": "C",
                "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            },
            check=False,
        )
        if result.returncode != 0:
            self.fail_command(command, result)
        return result.stdout

    @staticmethod
    def fail_command(command: list[str], result: subprocess.CompletedProcess[bytes]) -> None:
        safe_command = [item for item in command if item != PASSPHRASE.decode()]
        raise AssertionError(
            f"TEST ONLY gpg command failed ({result.returncode}): {safe_command}; "
            f"stderr={result.stderr.decode(errors='replace')}"
        )

    def _fingerprints(self, home: Path) -> tuple[str, list[str]]:
        output = self._gpg(
            home,
            [
                "--with-colons",
                "--fixed-list-mode",
                "--with-fingerprint",
                "--with-subkey-fingerprint",
                "--list-keys",
            ],
        ).decode()
        primary = ""
        subkeys: list[str] = []
        pending = ""
        for line in output.splitlines():
            record = line.split(":")
            if record[0] in {"pub", "sub"}:
                pending = record[0]
            elif record[0] == "fpr" and pending:
                if pending == "pub":
                    primary = record[9]
                else:
                    subkeys.append(record[9])
                pending = ""
        if len(primary) != 40:
            raise AssertionError("TEST ONLY key generation did not produce expected fingerprints")
        return primary, subkeys

    def _export(
        self,
        home: Path,
        arguments: list[str],
        *,
        passphrase: bytes = PASSPHRASE,
        fake_time: int | None = None,
    ) -> bytes:
        return self._gpg(
            home,
            ["--pinentry-mode", "loopback", "--passphrase-fd", "0", *arguments],
            input_bytes=passphrase + b"\n",
            fake_time=fake_time,
        )

    def generate(
        self,
        name: str,
        *,
        signing_expiration: str,
        add_encryption_subkey: bool,
        algorithm: str = "ed25519",
        fake_time: int | None = None,
        key_passphrase: bytes = PASSPHRASE,
        primary_usage: str = "cert",
        signing_usage: str = "sign",
    ) -> GeneratedKey:
        self.counter += 1
        key_root = self.root / f"{self.counter:02d}-{name}"
        home = key_root / "gnupg"
        home.mkdir(parents=True, mode=0o700)
        uid = f"WuKongIM {name} TEST ONLY <{self.counter}@test.invalid>"
        loopback = ["--pinentry-mode", "loopback", "--passphrase-fd", "0"]
        self._gpg(
            home,
            [*loopback, "--quick-gen-key", uid, algorithm, primary_usage, "365d"],
            input_bytes=key_passphrase + b"\n",
            fake_time=fake_time,
        )
        primary, _ = self._fingerprints(home)
        self._gpg(
            home,
            [*loopback, "--quick-add-key", primary, algorithm, signing_usage, signing_expiration],
            input_bytes=key_passphrase + b"\n",
            fake_time=fake_time,
        )
        _, subkeys = self._fingerprints(home)
        signing_subkey = subkeys[0]
        reviewed_public_material = self._gpg(home, ["--armor", "--export", primary])
        if add_encryption_subkey:
            self._gpg(
                home,
                [*loopback, "--quick-add-key", primary, "cv25519", "encr", "60d"],
                input_bytes=key_passphrase + b"\n",
                fake_time=fake_time,
            )

        public_cert = key_root / "public-cert.asc"
        public_cert.write_bytes(reviewed_public_material)
        public_cert.chmod(0o644)
        public_cert_with_extra_subkeys = key_root / "public-cert-with-extra-subkeys.asc"
        public_cert_with_extra_subkeys.write_bytes(
            self._gpg(home, ["--armor", "--export", primary])
        )
        public_cert_with_extra_subkeys.chmod(0o644)

        export_time = None if fake_time is None else fake_time + 3600
        selected_secret = self._export(
            home,
            ["--export-secret-subkeys", f"{signing_subkey}!"],
            passphrase=key_passphrase,
            fake_time=export_time,
        )
        full_secret = self._export(
            home,
            ["--export-secret-keys", primary],
            passphrase=key_passphrase,
            fake_time=export_time,
        )
        all_subkeys_secret = self._export(
            home,
            ["--export-secret-subkeys", primary],
            passphrase=key_passphrase,
            fake_time=export_time,
        )

        selected_secret_base64 = key_root / "selected-secret-subkey.b64"
        full_secret_base64 = key_root / "full-secret-key.b64"
        all_subkeys_secret_base64 = key_root / "all-secret-subkeys.b64"
        for path, material in (
            (selected_secret_base64, selected_secret),
            (full_secret_base64, full_secret),
            (all_subkeys_secret_base64, all_subkeys_secret),
        ):
            path.write_bytes(base64.b64encode(material))
            path.chmod(0o600)
        passphrase_file = key_root / "passphrase"
        passphrase_file.write_bytes(PASSPHRASE)
        passphrase_file.chmod(0o600)
        return GeneratedKey(
            home=home,
            public_cert=public_cert,
            public_cert_with_extra_subkeys=public_cert_with_extra_subkeys,
            selected_secret_base64=selected_secret_base64,
            full_secret_base64=full_secret_base64,
            all_subkeys_secret_base64=all_subkeys_secret_base64,
            passphrase_file=passphrase_file,
            primary_fingerprint=primary,
            signing_subkey_fingerprint=signing_subkey,
        )

    def close(self) -> None:
        for home in self.root.glob("*/gnupg"):
            subprocess.run(
                ["gpgconf", "--homedir", str(home), "--kill", "all"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )


class SigningMaterialValidationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if shutil.which("gpg") is None or shutil.which("gpgconf") is None:
            raise unittest.SkipTest("gpg and gpgconf are required")
        cls.temporary = TemporaryDirectory(prefix="wk-signer-TEST-ONLY-", dir="/tmp")
        cls.factory = TestKeyFactory(Path(cls.temporary.name))
        cls.good = cls.factory.generate(
            "GOOD", signing_expiration="60d", add_encryption_subkey=True
        )
        cls.rpm_good = cls.factory.generate(
            "RPM-GOOD",
            signing_expiration="60d",
            add_encryption_subkey=True,
            algorithm="rsa3072",
        )
        cls.rpm_weak = cls.factory.generate(
            "RPM-RSA2048",
            signing_expiration="60d",
            add_encryption_subkey=False,
            algorithm="rsa2048",
        )
        old_time = int(time.time()) - 10 * 86400
        cls.expired = cls.factory.generate(
            "EXPIRED", signing_expiration="1d", add_encryption_subkey=False, fake_time=old_time
        )
        cls.overlong = cls.factory.generate(
            "OVERLONG", signing_expiration="181d", add_encryption_subkey=False
        )
        cls.mixed = cls.factory.generate(
            "MIXED",
            signing_expiration="60d",
            add_encryption_subkey=False,
            signing_usage="sign,auth",
        )
        cls.mixed_primary = cls.factory.generate(
            "MIXED-PRIMARY",
            signing_expiration="60d",
            add_encryption_subkey=False,
            primary_usage="cert,sign",
        )
        cls.unprotected = cls.factory.generate(
            "UNPROTECTED",
            signing_expiration="60d",
            add_encryption_subkey=False,
            key_passphrase=b"",
        )

    @classmethod
    def tearDownClass(cls) -> None:
        cls.factory.close()
        cls.temporary.cleanup()

    def run_validator(
        self,
        key: GeneratedKey,
        *,
        secret: Path | None = None,
        primary_fingerprint: str | None = None,
        signing_subkey_fingerprint: str | None = None,
        passphrase_file: Path | None = None,
        public_cert: Path | None = None,
        family: str = "apt",
    ) -> subprocess.CompletedProcess[str]:
        command = [
            sys.executable,
            str(SCRIPT),
            "--family",
            family,
            "--public-cert",
            str(public_cert or key.public_cert),
            "--secret-subkey-base64-file",
            str(secret or key.selected_secret_base64),
            "--passphrase-file",
            str(passphrase_file or key.passphrase_file),
            "--primary-fingerprint",
            primary_fingerprint or key.primary_fingerprint,
            "--signing-subkey-fingerprint",
            signing_subkey_fingerprint or key.signing_subkey_fingerprint,
            "--minimum-valid-days",
            "30",
            "--maximum-lifetime-days",
            "180",
        ]
        return subprocess.run(command, text=True, capture_output=True, check=False)

    def run_validator_with_secret_inputs(
        self, *, secret_from_stdin: bool
    ) -> subprocess.CompletedProcess[str]:
        secret_option = (
            ["--secret-subkey-base64-stdin"]
            if secret_from_stdin
            else ["--secret-subkey-base64-env", "WK_TEST_ONLY_SECRET_SUBKEY_B64"]
        )
        command = [
            sys.executable,
            str(SCRIPT),
            "--family",
            "apt",
            "--public-cert",
            str(self.good.public_cert),
            *secret_option,
            "--passphrase-env",
            "WK_TEST_ONLY_PASSPHRASE",
            "--primary-fingerprint",
            self.good.primary_fingerprint,
            "--signing-subkey-fingerprint",
            self.good.signing_subkey_fingerprint,
        ]
        environment = os.environ.copy()
        environment["WK_TEST_ONLY_PASSPHRASE"] = PASSPHRASE.decode()
        encoded = self.good.selected_secret_base64.read_text(encoding="ascii")
        if not secret_from_stdin:
            environment["WK_TEST_ONLY_SECRET_SUBKEY_B64"] = encoded
        return subprocess.run(
            command,
            input=encoded if secret_from_stdin else None,
            text=True,
            capture_output=True,
            env=environment,
            check=False,
        )

    def assert_safe_failure(self, result: subprocess.CompletedProcess[str], expected: str) -> None:
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn(expected, result.stderr)
        self.assertNotIn(PASSPHRASE.decode(), result.stdout)
        self.assertNotIn(PASSPHRASE.decode(), result.stderr)
        self.assertNotIn("BEGIN PGP PRIVATE KEY BLOCK", result.stdout + result.stderr)

    def test_accepts_only_reviewed_encrypted_signing_subkey_for_both_families(self) -> None:
        for family, key in (("apt", self.good), ("rpm", self.rpm_good)):
            with self.subTest(family=family):
                result = self.run_validator(key, family=family)
                self.assertEqual(result.returncode, 0, result.stderr)
                receipt = json.loads(result.stdout)
                self.assertEqual(receipt["family"], family)
                self.assertEqual(receipt["primary_fingerprint"], key.primary_fingerprint)
                self.assertEqual(
                    receipt["signing_subkey_fingerprint"], key.signing_subkey_fingerprint
                )
                self.assertTrue(receipt["validated"])

    def test_rejects_non_rsa_rpm_signing_material(self) -> None:
        result = self.run_validator(self.good, family="rpm")
        self.assert_safe_failure(result, "public-key algorithm 1 (RSA)")

    def test_rejects_rsa2048_rpm_signing_material(self) -> None:
        result = self.run_validator(self.rpm_weak, family="rpm")
        self.assert_safe_failure(result, "RSA key must be exactly 3072 or 4096 bits")

    def test_rejects_non_rsa_rpm_secret_record_after_import(self) -> None:
        primary = "1" * 40
        current = "2" * 40
        records = [
            validator.KeyRecord(
                "sec", "u", 3072, 1, 1, None, "c", "#", primary
            ),
            validator.KeyRecord(
                "ssb", "u", 255, 22, 1, None, "s", "+", current
            ),
        ]

        with self.assertRaisesRegex(
            validator.SigningMaterialError, r"public-key algorithm 1 \(RSA\)"
        ):
            validator.validate_secret_key(records, primary, current, "rpm")

    def test_rejects_non_rsa_key_in_every_reviewed_rpm_role(self) -> None:
        now = int(time.time())
        fingerprints = [character * 40 for character in "1234"]
        records = [
            validator.KeyRecord(
                "pub", "u", 3072, 1, now - 86400, now + 365 * 86400,
                "c", "", fingerprints[0],
            ),
            validator.KeyRecord(
                "sub", "u", 3072, 1, now - 86400, now + 60 * 86400,
                "s", "", fingerprints[1],
            ),
            validator.KeyRecord(
                "sub", "u", 3072, 1, now - 86400, now + 120 * 86400,
                "s", "", fingerprints[2],
            ),
            validator.KeyRecord(
                "sub", "u", 3072, 1, now - 10 * 86400, now + 30 * 86400,
                "s", "", fingerprints[3],
            ),
        ]
        for index, role in enumerate(("primary", "current", "next", "historical")):
            with self.subTest(role=role), self.assertRaisesRegex(
                validator.SigningMaterialError, r"public-key algorithm 1 \(RSA\)"
            ):
                candidate = list(records)
                candidate[index] = replace(
                    candidate[index], key_bits=255, public_key_algorithm=22
                )
                validator.validate_public_key(
                    candidate,
                    fingerprints[0],
                    fingerprints[1],
                    fingerprints[2],
                    [fingerprints[3]],
                    30,
                    45,
                    180,
                    now,
                    "rpm",
                )

    def test_accepts_rsa4096_for_every_reviewed_rpm_role(self) -> None:
        now = int(time.time())
        fingerprints = [character * 40 for character in "1234"]
        records = [
            validator.KeyRecord(
                "pub", "u", 4096, 1, now - 86400, now + 365 * 86400,
                "c", "", fingerprints[0],
            ),
            validator.KeyRecord(
                "sub", "u", 4096, 1, now - 86400, now + 60 * 86400,
                "s", "", fingerprints[1],
            ),
            validator.KeyRecord(
                "sub", "u", 4096, 1, now - 86400, now + 120 * 86400,
                "s", "", fingerprints[2],
            ),
            validator.KeyRecord(
                "sub", "u", 4096, 1, now - 10 * 86400, now + 30 * 86400,
                "s", "", fingerprints[3],
            ),
        ]

        selected = validator.validate_public_key(
            records,
            fingerprints[0],
            fingerprints[1],
            fingerprints[2],
            [fingerprints[3]],
            30,
            45,
            180,
            now,
            "rpm",
        )

        self.assertEqual(fingerprints[1], selected.fingerprint)

    def test_accepts_future_next_and_still_valid_former_current(self) -> None:
        now = int(time.time())
        primary = "1" * 40
        current = "2" * 40
        successor = "3" * 40
        historical = "4" * 40
        records = [
            validator.KeyRecord("pub", "u", 255, 22, now - 86400, now + 365 * 86400,
                                "c", "", primary),
            validator.KeyRecord("sub", "u", 255, 22, now - 86400, now + 60 * 86400,
                                "s", "", current),
            validator.KeyRecord("sub", "i", 255, 22, now + 2 * 86400, now + 120 * 86400,
                                "s", "", successor),
            validator.KeyRecord("sub", "u", 255, 22, now - 10 * 86400, now + 30 * 86400,
                                "s", "", historical),
        ]

        selected = validator.validate_public_key(
            records,
            primary,
            current,
            successor,
            [historical],
            30,
            45,
            180,
            now,
        )

        self.assertEqual(current, selected.fingerprint)

    def test_rejects_historical_subkey_that_expires_after_current(self) -> None:
        now = int(time.time())
        primary = "1" * 40
        current = "2" * 40
        successor = "3" * 40
        historical = "4" * 40
        records = [
            validator.KeyRecord("pub", "u", 255, 22, now - 86400, now + 365 * 86400,
                                "c", "", primary),
            validator.KeyRecord("sub", "u", 255, 22, now - 86400, now + 60 * 86400,
                                "s", "", current),
            validator.KeyRecord("sub", "u", 255, 22, now - 86400, now + 120 * 86400,
                                "s", "", successor),
            validator.KeyRecord("sub", "u", 255, 22, now - 10 * 86400, now + 90 * 86400,
                                "s", "", historical),
        ]

        with self.assertRaisesRegex(
            validator.SigningMaterialError, "expires after the current"
        ):
            validator.validate_public_key(
                records, primary, current, successor, [historical], 30, 45, 180, now
            )

    def test_rejects_full_fingerprints_with_colliding_rpm_key_ids(self) -> None:
        current = "1" * 40
        args = Namespace(
            primary_fingerprint="2" * 40,
            signing_subkey_fingerprint=current,
            next_signing_subkey_fingerprint="3" * 24 + current[-16:],
            historical_signing_subkey_fingerprint=[],
            minimum_valid_days=30,
            rotation_begin_days=45,
            maximum_lifetime_days=180,
        )

        with self.assertRaisesRegex(
            validator.SigningMaterialError, "distinct 16-hex key IDs"
        ):
            validator.validate_arguments(args)

    def test_accepts_ci_secrets_from_environment_without_disclosure(self) -> None:
        result = self.run_validator_with_secret_inputs(secret_from_stdin=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn(PASSPHRASE.decode(), result.stdout + result.stderr)
        self.assertNotIn(
            self.good.selected_secret_base64.read_text(encoding="ascii"),
            result.stdout + result.stderr,
        )

    def test_accepts_base64_secret_subkey_from_stdin(self) -> None:
        result = self.run_validator_with_secret_inputs(secret_from_stdin=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn(PASSPHRASE.decode(), result.stdout + result.stderr)

    def test_rejects_wrong_reviewed_fingerprint(self) -> None:
        result = self.run_validator(self.good, primary_fingerprint="A" * 40)
        self.assert_safe_failure(result, "primary fingerprint")

    def test_rejects_secret_file_with_broad_permissions(self) -> None:
        exposed = Path(self.temporary.name) / "exposed-secret-subkey.b64"
        exposed.write_bytes(self.good.selected_secret_base64.read_bytes())
        exposed.chmod(0o644)
        result = self.run_validator(self.good, secret=exposed)
        self.assert_safe_failure(result, "permissions")

    def test_rejects_secret_file_symlink(self) -> None:
        linked = Path(self.temporary.name) / "linked-secret-subkey.b64"
        linked.symlink_to(self.good.selected_secret_base64)
        result = self.run_validator(self.good, secret=linked)
        self.assert_safe_failure(result, "regular file")

    def test_rejects_file_replaced_between_lstat_and_open(self) -> None:
        with TemporaryDirectory(prefix="wk-signer-race-TEST-ONLY-", dir="/tmp") as directory:
            root = Path(directory)
            candidate = root / "candidate"
            replacement = root / "replacement"
            displaced = root / "displaced"
            candidate.write_bytes(b"reviewed-public-material")
            replacement.write_bytes(b"replacement-key-material")

            def replace_after_lstat() -> None:
                candidate.rename(displaced)
                replacement.rename(candidate)

            with self.assertRaisesRegex(
                validator.SigningMaterialError, "changed while it was opened"
            ):
                validator.checked_regular_file(
                    candidate,
                    "TEST ONLY replacement seam",
                    1024,
                    secret=False,
                    _after_lstat=replace_after_lstat,
                )

    def test_rejects_private_primary_key(self) -> None:
        result = self.run_validator(self.good, secret=self.good.full_secret_base64)
        self.assert_safe_failure(result, "must not contain a private primary key")

    def test_rejects_any_extra_private_subkey(self) -> None:
        result = self.run_validator(self.good, secret=self.good.all_subkeys_secret_base64)
        self.assert_safe_failure(result, "exactly one private subkey")

    def test_rejects_extra_public_subkey(self) -> None:
        result = self.run_validator(
            self.good, public_cert=self.good.public_cert_with_extra_subkeys
        )
        self.assert_safe_failure(result, "do not exactly match reviewed fingerprints")

    def test_rejects_mixed_capability_signing_subkey(self) -> None:
        result = self.run_validator(self.mixed)
        self.assert_safe_failure(result, "must be sign-only")

    def test_rejects_mixed_capability_primary(self) -> None:
        result = self.run_validator(self.mixed_primary)
        self.assert_safe_failure(result, "certify-only")

    def test_rejects_expired_signing_subkey(self) -> None:
        result = self.run_validator(self.expired)
        self.assert_safe_failure(result, "expired")

    def test_rejects_signing_subkey_lifetime_over_180_days(self) -> None:
        result = self.run_validator(self.overlong)
        self.assert_safe_failure(result, "lifetime exceeds")

    def test_rejects_wrong_passphrase_without_disclosure(self) -> None:
        wrong = Path(self.temporary.name) / "wrong-passphrase"
        wrong.write_bytes(b"wrong-TEST-ONLY-passphrase")
        wrong.chmod(0o600)
        result = self.run_validator(self.good, passphrase_file=wrong)
        self.assert_safe_failure(result, "unlock proof")

    def test_rejects_unprotected_secret_subkey(self) -> None:
        result = self.run_validator(self.unprotected)
        self.assert_safe_failure(result, "not protected")


if __name__ == "__main__":
    unittest.main()
