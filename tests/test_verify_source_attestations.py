from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import json
import os
import shutil
import stat
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures" / "source-release"
SCRIPT = ROOT / "scripts" / "verify-source-attestations.py"
SPEC = importlib.util.spec_from_file_location("verify_source_attestations", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
verifier = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(verifier)

RELEASE_ID = 4242
TAG = "v3.1.0-rc.1"
VERSION = TAG[1:]
SOURCE_SHA = "1" * 40
INITIAL_MAIN_SHA = "2" * 40
FINAL_MAIN_SHA = "5" * 40


MOCK_GH = r'''#!/usr/bin/env python3
import json
import os
import pathlib
import sys

log = pathlib.Path(os.environ["MOCK_GH_LOG"])
with log.open("a", encoding="utf-8") as stream:
    stream.write(json.dumps(sys.argv[1:]) + "\n")
calls = len(log.read_text(encoding="utf-8").splitlines())
mode = os.environ.get("MOCK_GH_MODE", "success")
if mode == "fail":
    print("mock attestation failure", file=sys.stderr)
    raise SystemExit(7)
if mode == "empty":
    raise SystemExit(0)
if mode == "invalid":
    print("not-json")
    raise SystemExit(0)
if mode == "empty-json":
    print("[]")
    raise SystemExit(0)
if mode == "duplicate-json":
    print('{"verified":true,"verified":false}')
    raise SystemExit(0)
expected_source_digest = os.environ.get("MOCK_EXPECT_SOURCE_DIGEST")
if expected_source_digest:
    digest_index = sys.argv.index("--source-digest") + 1
    if sys.argv[digest_index] != expected_source_digest:
        print("source digest did not match trusted attestation", file=sys.stderr)
        raise SystemExit(9)
mutate_path = os.environ.get("MOCK_MUTATE_PATH")
mutate_on_call = int(os.environ.get("MOCK_MUTATE_ON_CALL", "0"))
if mutate_path and calls == mutate_on_call:
    pathlib.Path(mutate_path).write_bytes(b"changed after attestation verification\n")
print(json.dumps({"verified": True, "asset": pathlib.Path(sys.argv[3]).name}))
'''


def source_receipt(asset_dir: Path) -> dict[str, object]:
    names = sorted(path.name for path in asset_dir.iterdir())
    assets = []
    facts: dict[str, str] = {}
    for offset, name in enumerate(names, start=1):
        data = (asset_dir / name).read_bytes()
        sha256 = hashlib.sha256(data).hexdigest()
        facts[name] = sha256
        assets.append(
            {
                "id": 1000 + offset,
                "name": name,
                "size": len(data),
                "sha256": sha256,
                "downloaded_file": name,
            }
        )
    checksum_name = f"wukongim_{VERSION}_checksums.txt"
    payload_names = [name for name in names if name != checksum_name]
    return {
        "schema": verifier.SOURCE_RECEIPT_SCHEMA,
        "repository": verifier.SOURCE_REPOSITORY,
        "release_id": RELEASE_ID,
        "tag": TAG,
        "version": VERSION,
        "prerelease": True,
        "published_at": "2026-09-01T00:00:00Z",
        "source_sha": SOURCE_SHA,
        "initial_main_sha": INITIAL_MAIN_SHA,
        "final_main_sha": FINAL_MAIN_SHA,
        "main_sha": FINAL_MAIN_SHA,
        "asset_count": 7,
        "total_size": sum(asset["size"] for asset in assets),
        "assets": assets,
        "checksum_asset": checksum_name,
        "checksum_entries": [
            {"name": name, "sha256": facts[name]} for name in payload_names
        ],
        "release_revalidated": True,
        "tag_revalidated": True,
        "main_ancestry_revalidated": True,
    }


class VerifySourceAttestationsTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.asset_dir = self.root / "assets"
        self.asset_dir.mkdir()
        for fixture in FIXTURES.iterdir():
            shutil.copyfile(fixture, self.asset_dir / fixture.name)
        self.receipt_path = self.root / "source-receipt.json"
        self.receipt = source_receipt(self.asset_dir)
        self.write_receipt()
        self.evidence_dir = self.root / "evidence"
        self.mock_bin = self.root / "bin"
        self.mock_bin.mkdir()
        self.mock_gh = self.mock_bin / "gh"
        self.mock_gh.write_text(MOCK_GH, encoding="utf-8")
        self.mock_gh.chmod(0o755)
        self.mock_log = self.root / "gh-commands.jsonl"

    def write_receipt(self) -> None:
        self.receipt_path.write_text(
            json.dumps(self.receipt, sort_keys=True), encoding="utf-8"
        )

    @contextlib.contextmanager
    def mock_gh_environment(self, mode: str = "success", **extra: str):
        environment = {
            "PATH": f"{self.mock_bin}{os.pathsep}{os.environ.get('PATH', '')}",
            "MOCK_GH_LOG": str(self.mock_log),
            "MOCK_GH_MODE": mode,
            **extra,
        }
        with mock.patch.dict(os.environ, environment, clear=False):
            yield

    def verify(self, mode: str = "success", **extra: str):
        with self.mock_gh_environment(mode, **extra):
            return verifier.verify_source_attestations(
                receipt_path=self.receipt_path,
                asset_dir=self.asset_dir,
                evidence_dir=self.evidence_dir,
            )

    def commands(self) -> list[list[str]]:
        if not self.mock_log.exists():
            return []
        return [json.loads(line) for line in self.mock_log.read_text().splitlines()]

    def test_verifies_exact_seven_assets_with_fixed_gh_identity_arguments(self) -> None:
        summary = self.verify()
        self.assertEqual(verifier.EVIDENCE_RECEIPT_SCHEMA, summary["schema"])
        self.assertEqual(7, summary["asset_count"])
        self.assertEqual(SOURCE_SHA, summary["source_sha"])
        self.assertTrue(summary["deny_self_hosted_runners"])
        self.assertTrue(summary["assets_revalidated_after_attestations"])

        expected_tail = [
            "--repo",
            verifier.SOURCE_REPOSITORY,
            "--signer-workflow",
            verifier.SIGNER_WORKFLOW,
            "--source-ref",
            f"refs/tags/{TAG}",
            "--source-digest",
            SOURCE_SHA,
            "--deny-self-hosted-runners",
            "--format=json",
        ]
        commands = self.commands()
        self.assertEqual(7, len(commands))
        expected_names = sorted(path.name for path in self.asset_dir.iterdir())
        for command, name in zip(commands, expected_names, strict=True):
            self.assertEqual(["attestation", "verify"], command[:2])
            self.assertEqual((self.asset_dir / name).resolve(), Path(command[2]))
            self.assertEqual(expected_tail, command[3:])

        evidence_names = sorted(path.name for path in self.evidence_dir.iterdir())
        self.assertEqual(8, len(evidence_names))
        self.assertIn("source-attestations.json", evidence_names)
        for name in expected_names:
            evidence_path = self.evidence_dir / f"{name}.attestation.json"
            self.assertTrue(evidence_path.is_file())
            self.assertEqual(1, evidence_path.stat().st_nlink)
            self.assertEqual(name, json.loads(evidence_path.read_text())["asset"])
        stored_summary = json.loads(
            (self.evidence_dir / "source-attestations.json").read_text()
        )
        self.assertEqual(summary, stored_summary)

    def test_rejects_asset_digest_tampering_before_calling_gh(self) -> None:
        target = next(path for path in self.asset_dir.iterdir() if path.suffix == ".deb")
        target.write_bytes(b"tampered package\n")
        with self.assertRaisesRegex(verifier.VerificationError, "size conflicts|digest conflicts"):
            self.verify()
        self.assertEqual([], self.commands())
        self.assertFalse(self.evidence_dir.exists())

        self.receipt = source_receipt(self.asset_dir)
        self.receipt["assets"][0]["sha256"] = "0" * 64
        self.write_receipt()
        with self.assertRaisesRegex(
            verifier.VerificationError, "checksum digest conflicts|digest conflicts"
        ):
            self.verify()
        self.assertEqual([], self.commands())

    def test_binds_valid_shaped_source_digest_to_gh_verification(self) -> None:
        self.receipt["source_sha"] = "3" * 40
        self.write_receipt()
        with self.assertRaisesRegex(verifier.VerificationError, "exit code 9"):
            self.verify(MOCK_EXPECT_SOURCE_DIGEST=SOURCE_SHA)
        self.assertEqual(1, len(self.commands()))
        self.assertFalse(self.evidence_dir.exists())

    def test_rejects_tampered_receipt_identity_and_revalidation(self) -> None:
        mutations = (
            ("repository", "attacker/repository", "repository is not trusted"),
            ("source_sha", "0" * 39, "invalid digest"),
            ("tag", "v3.1.0", "strict pre-release"),
            ("prerelease", False, "must describe a pre-release"),
            ("release_revalidated", False, "must be true"),
            ("tag_revalidated", False, "must be true"),
            ("main_ancestry_revalidated", False, "must be true"),
        )
        original = dict(self.receipt)
        for field, value, pattern in mutations:
            with self.subTest(field=field):
                self.receipt = dict(original)
                self.receipt[field] = value
                self.write_receipt()
                with self.assertRaisesRegex(verifier.VerificationError, pattern):
                    self.verify()
                self.assertEqual([], self.commands())

    def test_rejects_duplicate_receipt_and_gh_json_keys(self) -> None:
        self.receipt_path.write_text(
            '{"schema":"one","schema":"two"}', encoding="utf-8"
        )
        with self.assertRaisesRegex(verifier.VerificationError, "duplicate key"):
            self.verify()
        self.assertEqual([], self.commands())

        self.receipt = source_receipt(self.asset_dir)
        self.write_receipt()
        with self.assertRaisesRegex(verifier.VerificationError, "duplicate key"):
            self.verify("duplicate-json")
        self.assertEqual(1, len(self.commands()))
        self.assertFalse(self.evidence_dir.exists())

    def test_rejects_gh_failure_empty_non_json_and_empty_json_results(self) -> None:
        for mode, pattern in (
            ("fail", "exit code 7"),
            ("empty", "is empty"),
            ("invalid", "not valid JSON"),
            ("empty-json", "empty JSON"),
        ):
            with self.subTest(mode=mode):
                self.mock_log.unlink(missing_ok=True)
                with self.assertRaisesRegex(verifier.VerificationError, pattern):
                    self.verify(mode)
                self.assertEqual(1, len(self.commands()))
                self.assertFalse(self.evidence_dir.exists())

    def test_rejects_asset_change_after_external_attestation_verification(self) -> None:
        target = sorted(self.asset_dir.iterdir())[0]
        with self.assertRaisesRegex(verifier.VerificationError, "size conflicts|digest conflicts"):
            self.verify(
                MOCK_MUTATE_PATH=str(target),
                MOCK_MUTATE_ON_CALL="7",
            )
        self.assertEqual(7, len(self.commands()))
        self.assertFalse(self.evidence_dir.exists())

    def test_rejects_non_exact_or_non_single_link_asset_directory(self) -> None:
        extra = self.asset_dir / "unexpected"
        extra.write_text("unexpected", encoding="utf-8")
        with self.assertRaisesRegex(verifier.VerificationError, "exact seven"):
            self.verify()
        extra.unlink()

        target = sorted(self.asset_dir.iterdir())[0]
        hardlink = self.root / "hardlink"
        os.link(target, hardlink)
        with self.assertRaisesRegex(verifier.VerificationError, "regular single-link"):
            self.verify()

    def test_rejects_unsafe_or_nonempty_evidence_directory(self) -> None:
        self.evidence_dir.mkdir()
        (self.evidence_dir / "stale").write_text("stale", encoding="utf-8")
        with self.assertRaisesRegex(verifier.VerificationError, "must be empty"):
            self.verify()

        shutil.rmtree(self.evidence_dir)
        target = self.root / "evidence-target"
        target.mkdir()
        self.evidence_dir.symlink_to(target, target_is_directory=True)
        with self.assertRaisesRegex(verifier.VerificationError, "real directory"):
            self.verify()

        self.evidence_dir.unlink()
        self.evidence_dir = self.asset_dir / "evidence"
        with self.assertRaisesRegex(verifier.VerificationError, "must not be inside"):
            self.verify()

    def test_rejects_non_single_link_receipt(self) -> None:
        receipt_hardlink = self.root / "receipt-hardlink.json"
        os.link(self.receipt_path, receipt_hardlink)
        with self.assertRaisesRegex(verifier.VerificationError, "regular single-link"):
            self.verify()

    def test_verifier_invokes_only_gh_and_never_executes_an_asset(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertNotIn("shell=True", source)
        self.assertNotIn("tarfile", source)
        self.assertNotIn("zipfile", source)
        self.assertIn('"gh",', source)


if __name__ == "__main__":
    unittest.main()
