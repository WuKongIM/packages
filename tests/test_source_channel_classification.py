from __future__ import annotations

import json
import os
import subprocess
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from test_resolve_source_release import FixtureState, RELEASE_ID, SOURCE_SHA, serve
from test_verify_source_attestations import MOCK_GH


ROOT = Path(__file__).resolve().parents[1]
RESOLVER = ROOT / "scripts" / "resolve-source-release.py"
VERIFIER = ROOT / "scripts" / "verify-source-attestations.py"


class SourceChannelClassificationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.assets = self.root / "assets"

    def resolve(self, state: FixtureState, channel: str | None = None):
        with serve(state) as (api_base, download_base):
            command = [
                sys.executable, str(RESOLVER),
                "--release-id", str(RELEASE_ID),
                "--output-dir", str(self.assets),
                "--api-base-url", api_base,
                "--download-base-url", download_base,
                "--token-env", "",
            ]
            if channel is not None:
                command.extend(["--channel", channel])
            return subprocess.run(command, capture_output=True, text=True, timeout=10)

    def test_explicit_stable_resolves_immutable_release_and_seven_assets(self) -> None:
        result = self.resolve(FixtureState("v3.1.0", False), "stable")
        self.assertEqual(0, result.returncode, result.stderr)
        receipt = json.loads(result.stdout)
        self.assertEqual("v3.1.0", receipt["tag"])
        self.assertEqual("3.1.0", receipt["version"])
        self.assertIs(False, receipt["prerelease"])
        self.assertEqual(SOURCE_SHA, receipt["source_sha"])
        self.assertEqual(7, receipt["asset_count"])
        self.assertEqual(6, len(receipt["checksum_entries"]))
        self.assertTrue(receipt["release_revalidated"])
        self.assertTrue(receipt["tag_revalidated"])
        self.assertTrue(receipt["main_ancestry_revalidated"])
        self.assertEqual(7, len(list(self.assets.iterdir())))

    def test_default_preview_rejects_stable_without_downloads(self) -> None:
        state = FixtureState("v3.1.0", False)
        result = self.resolve(state)
        self.assertNotEqual(0, result.returncode)
        self.assertIn("preview source tag must be a SemVer pre-release", result.stderr)
        self.assertFalse(self.assets.exists())
        self.assertFalse(any("/assets/" in path for _, path in state.requests))

    def test_stable_rejects_prerelease_without_downloads(self) -> None:
        state = FixtureState()
        result = self.resolve(state, "stable")
        self.assertNotEqual(0, result.returncode)
        self.assertIn("stable source tag must not be a SemVer pre-release", result.stderr)
        self.assertFalse(self.assets.exists())
        self.assertFalse(any("/assets/" in path for _, path in state.requests))

    def test_stable_rejects_inconsistent_or_non_boolean_release_classification(self) -> None:
        for classification in (True, "false", 0):
            with self.subTest(classification=classification):
                result = self.resolve(FixtureState("v3.1.0", classification), "stable")
                self.assertNotEqual(0, result.returncode)
                self.assertRegex(result.stderr, "classification conflicts|must be a boolean")
                self.assertFalse(self.assets.exists())

    def test_unknown_channel_is_rejected_before_network_or_output(self) -> None:
        state = FixtureState("v3.1.0", False)
        result = self.resolve(state, "production")
        self.assertEqual(2, result.returncode)
        self.assertIn("invalid choice", result.stderr)
        self.assertEqual([], state.requests)
        self.assertFalse(self.assets.exists())

    def prepare_receipt(self, *, stable: bool = True):
        state = FixtureState("v3.1.0", False) if stable else FixtureState()
        result = self.resolve(state, "stable" if stable else "preview")
        self.assertEqual(0, result.returncode, result.stderr)
        receipt = json.loads(result.stdout)
        (self.root / "receipt.json").write_text(result.stdout)
        return receipt

    def verify(self, channel: str | None = None, mode: str = "success"):
        mock_bin = self.root / "bin"
        mock_bin.mkdir(exist_ok=True)
        mock_gh = mock_bin / "gh"
        mock_gh.write_text(MOCK_GH)
        mock_gh.chmod(0o755)
        command = [
            sys.executable, str(VERIFIER),
            "--receipt", str(self.root / "receipt.json"),
            "--asset-dir", str(self.assets),
            "--evidence-dir", str(self.root / "evidence"),
        ]
        if channel is not None:
            command.extend(["--channel", channel])
        environment = {
            **os.environ,
            "PATH": f"{mock_bin}{os.pathsep}{os.environ.get('PATH', '')}",
            "MOCK_GH_LOG": str(self.root / "gh-commands.jsonl"),
            "MOCK_GH_MODE": mode,
            "MOCK_EXPECT_SOURCE_DIGEST": SOURCE_SHA,
        }
        return subprocess.run(
            command, capture_output=True, text=True, timeout=10, env=environment
        )

    def test_explicit_stable_verifies_all_assets_against_exact_source_provenance(self) -> None:
        self.prepare_receipt()
        result = self.verify("stable")
        self.assertEqual(0, result.returncode, result.stderr)
        summary = json.loads(result.stdout)
        self.assertEqual("3.1.0", summary["version"])
        self.assertEqual("refs/tags/v3.1.0", summary["source_ref"])
        self.assertEqual(SOURCE_SHA, summary["source_sha"])
        self.assertTrue(summary["deny_self_hosted_runners"])
        self.assertTrue(summary["assets_revalidated_after_attestations"])
        self.assertEqual(7, summary["asset_count"])
        self.assertEqual(8, len(list((self.root / "evidence").iterdir())))
        commands = [
            json.loads(line)
            for line in (self.root / "gh-commands.jsonl").read_text().splitlines()
        ]
        self.assertEqual(7, len(commands))
        for command in commands:
            self.assertEqual("refs/tags/v3.1.0", command[command.index("--source-ref") + 1])
            self.assertEqual(SOURCE_SHA, command[command.index("--source-digest") + 1])
            self.assertEqual(
                "WuKongIM/WuKongIM/.github/workflows/binary-release-publish.yml",
                command[command.index("--signer-workflow") + 1],
            )
            self.assertIn("--deny-self-hosted-runners", command)

    def test_default_preview_verifier_rejects_stable_before_external_verification(self) -> None:
        self.prepare_receipt()
        result = self.verify()
        self.assertNotEqual(0, result.returncode)
        self.assertIn("preview source tag must be strict pre-release SemVer", result.stderr)
        self.assertFalse((self.root / "gh-commands.jsonl").exists())
        self.assertFalse((self.root / "evidence").exists())

    def test_stable_verifier_rejects_prerelease_before_external_verification(self) -> None:
        self.prepare_receipt(stable=False)
        result = self.verify("stable")
        self.assertNotEqual(0, result.returncode)
        self.assertIn("stable source tag must not be a SemVer pre-release", result.stderr)
        self.assertFalse((self.root / "gh-commands.jsonl").exists())
        self.assertFalse((self.root / "evidence").exists())

    def test_stable_verifier_rejects_receipt_classification_conflicts(self) -> None:
        receipt = self.prepare_receipt()
        for classification in (True, "false", 0):
            with self.subTest(classification=classification):
                receipt["prerelease"] = classification
                (self.root / "receipt.json").write_text(json.dumps(receipt))
                result = self.verify("stable")
                self.assertNotEqual(0, result.returncode)
                self.assertIn("prerelease classification conflicts", result.stderr)
                self.assertFalse((self.root / "gh-commands.jsonl").exists())
                self.assertFalse((self.root / "evidence").exists())

    def test_stable_verifier_does_not_accept_failed_provenance(self) -> None:
        self.prepare_receipt()
        result = self.verify("stable", "fail")
        self.assertNotEqual(0, result.returncode)
        self.assertIn("gh attestation verification failed", result.stderr)
        self.assertFalse((self.root / "evidence").exists())


if __name__ == "__main__":
    unittest.main()
