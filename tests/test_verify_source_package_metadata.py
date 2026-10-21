from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from test_resolve_source_release import FixtureState, RELEASE_ID, SOURCE_SHA, serve


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "verify-source-package-metadata.py"
RESOLVER = ROOT / "scripts" / "resolve-source-release.py"


class SourcePackageMetadataTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.assets = self.root / "assets"
        self.receipt_path = self.root / "source.json"
        self.log = self.root / "commands.jsonl"
        self.config_path = self.root / "queries.json"
        self.bin = self.root / "bin"
        self.bin.mkdir()
        # Stub only the native-tool process boundary. The source receipt,
        # downloaded files and verifier CLI remain real.
        query = '''#!/usr/bin/env python3
import json, os, pathlib, sys
config = json.loads(pathlib.Path(CONFIG).read_text())
with pathlib.Path(LOG).open('a') as log:
    log.write(json.dumps([pathlib.Path(sys.argv[0]).name, *sys.argv[1:]]) + '\\n')
if config.get('fail'):
    sys.exit(2)
if config.get('invalid_utf8'):
    sys.stdout.buffer.write(b'\\xff')
    sys.exit(0)
if config.get('oversized'):
    print('x' * 5000)
    sys.exit(0)
if config.get('mutate'):
    target = pathlib.Path(config['mutate'])
    target.chmod(0o600)
    target.write_bytes(b'changed bytes')
if pathlib.Path(sys.argv[0]).name == 'dpkg-deb':
    assert len(sys.argv) == 4 and sys.argv[1] == '--field', sys.argv
    field = sys.argv[3]
    assert field in ('Package', 'Architecture', 'Version'), field
    print(config['deb'][field])
else:
    assert len(sys.argv) == 5 and sys.argv[1:3] == ['-qp', '--queryformat'], sys.argv
    field = sys.argv[3]
    assert field in ('%{NAME}', '%{ARCH}', '%{VERSION}', '%{RELEASE}', '%{EPOCHNUM}', '%{SIGPGP:pgpsig}', '%{SIGGPG:pgpsig}', '%{RSAHEADER:pgpsig}', '%{DSAHEADER:pgpsig}'), field
    print(config['rpm'][field])
'''.replace("CONFIG", repr(str(self.config_path))).replace("LOG", repr(str(self.log)))
        for name in ("dpkg-deb", "rpm"):
            tool = self.bin / name
            tool.write_text(query)
            tool.chmod(0o755)

    def prepare(self, tag: str = "v3.1.0", channel: str = "stable") -> dict:
        with serve(FixtureState(tag, channel == "preview")) as (api, download):
            resolved = subprocess.run(
                [sys.executable, str(RESOLVER), "--release-id", str(RELEASE_ID),
                 "--channel", channel, "--output-dir", str(self.assets),
                 "--api-base-url", api, "--download-base-url", download,
                 "--token-env", ""], capture_output=True, text=True, timeout=10,
            )
        self.assertEqual(0, resolved.returncode, resolved.stderr)
        self.receipt_path.write_text(resolved.stdout)
        self.receipt = json.loads(resolved.stdout)
        self.config = {
            "deb": {"Package": "wukongim", "Architecture": "amd64", "Version": "3.1.0"},
            "rpm": {"%{NAME}": "wukongim", "%{ARCH}": "x86_64", "%{VERSION}": "3.1.0",
                    "%{RELEASE}": "1", "%{EPOCHNUM}": "0", "%{SIGPGP:pgpsig}": "(none)", "%{SIGGPG:pgpsig}": "(none)",
                    "%{RSAHEADER:pgpsig}": "(none)", "%{DSAHEADER:pgpsig}": "(none)"},
        }
        return self.receipt

    def verify(self, channel: str | None = "stable") -> subprocess.CompletedProcess:
        self.config_path.write_text(json.dumps(self.config))
        command = [sys.executable, str(SCRIPT), "--receipt", str(self.receipt_path),
                   "--asset-dir", str(self.assets)]
        if channel is not None:
            command.extend(["--channel", channel])
        return subprocess.run(command, capture_output=True, text=True, timeout=10,
                              env={**os.environ, "PATH": f"{self.bin}{os.pathsep}{os.environ['PATH']}"})

    def rejected(self, result: subprocess.CompletedProcess, message: str) -> None:
        self.assertNotEqual(0, result.returncode)
        self.assertEqual("", result.stdout)
        self.assertIn(message, result.stderr)

    def test_stable_metadata_binds_source_and_exact_package_bytes(self) -> None:
        receipt = self.prepare()
        before = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in self.assets.iterdir()}
        result = self.verify()
        self.assertEqual(0, result.returncode, result.stderr)
        evidence = json.loads(result.stdout)
        self.assertEqual("wukongim/source-package-metadata/v2", evidence["schema"])
        self.assertEqual("stable", evidence["channel"])
        self.assertEqual({"repository": "WuKongIM/WuKongIM", "release_id": RELEASE_ID,
                          "tag": "v3.1.0", "source_sha": SOURCE_SHA}, evidence["source"])
        self.assertEqual("3.1.0", evidence["version"])
        self.assertTrue(evidence["assets_revalidated_after_metadata"])
        for family in ("deb", "rpm"):
            fact = next(a for a in receipt["assets"] if a["name"].endswith("." + family))
            self.assertEqual({key: fact[key] for key in ("id", "name", "size", "sha256")}, evidence[family]["asset"])
            self.assertEqual("3.1.0", evidence[family]["version"])
        self.assertEqual("1", evidence["rpm"]["release"])
        self.assertIs(False, evidence["rpm"]["signed"])
        self.assertEqual(before, {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in self.assets.iterdir()})

    def test_default_preview_preserves_hyphen_and_tilde_mapping(self) -> None:
        self.prepare("v3.1.0-rc.1-hotfix", "preview")
        self.config["deb"]["Version"] = "3.1.0~rc.1-hotfix"
        self.config["rpm"]["%{VERSION}"] = "3.1.0~rc.1_hotfix"
        result = self.verify(None)
        self.assertEqual(0, result.returncode, result.stderr)
        evidence = json.loads(result.stdout)
        self.assertEqual("preview", evidence["channel"])
        self.assertEqual("3.1.0~rc.1-hotfix", evidence["deb"]["version"])
        self.assertEqual("3.1.0~rc.1_hotfix", evidence["rpm"]["version"])

    def test_default_preview_rejects_stable_before_native_queries(self) -> None:
        self.prepare()
        self.rejected(self.verify(None), "preview source tag")
        self.assertFalse(self.log.exists())

    def test_stable_rejects_preview_before_native_queries(self) -> None:
        self.prepare("v3.1.0-rc.1", "preview")
        self.rejected(self.verify(), "stable source tag")
        self.assertFalse(self.log.exists())

    def test_unknown_channel_rejected_before_native_queries(self) -> None:
        self.prepare()
        self.rejected(self.verify("production"), "invalid choice")
        self.assertFalse(self.log.exists())

    def test_each_native_package_field_must_match(self) -> None:
        self.prepare()
        for family in ("deb", "rpm"):
            for field in self.config[family]:
                with self.subTest(family=family, field=field):
                    original = self.config[family][field]
                    self.config[family][field] = "unexpected"
                    self.rejected(self.verify(), "mismatch")
                    self.config[family][field] = original

    def test_invalid_receipt_classification_rejected_before_queries(self) -> None:
        self.prepare()
        self.receipt["prerelease"] = "false"
        self.receipt_path.write_text(json.dumps(self.receipt))
        self.rejected(self.verify(), "classification conflicts")
        self.assertFalse(self.log.exists())

    def test_receipt_unknown_and_duplicate_keys_fail_closed(self) -> None:
        self.prepare()
        self.receipt_path.write_text(json.dumps({**self.receipt, "unexpected": True}))
        self.rejected(self.verify(), "unexpected")
        self.receipt_path.write_text('{"version":"wrong",' + json.dumps(self.receipt)[1:])
        self.rejected(self.verify(), "duplicate key")
        self.assertFalse(self.log.exists())

    def test_changed_package_rejected_before_queries(self) -> None:
        self.prepare()
        target = next(self.assets.glob("*.deb"))
        target.chmod(0o600)
        target.write_bytes(b"wrong bytes")
        self.rejected(self.verify(), "conflicts with receipt")
        self.assertFalse(self.log.exists())

    def test_missing_asset_rejected_before_queries(self) -> None:
        self.prepare()
        self.assets.chmod(0o755)
        next(self.assets.glob("*.tar.gz")).unlink()
        self.rejected(self.verify(), "exact seven receipt assets")
        self.assertFalse(self.log.exists())

    def test_linked_package_rejected_before_queries(self) -> None:
        self.prepare()
        target = next(self.assets.glob("*.deb"))
        self.assets.chmod(0o755)
        outside = self.root / "original.deb"
        target.rename(outside)
        target.symlink_to(outside)
        self.rejected(self.verify(), "regular single-link file")
        target.unlink()
        os.link(outside, target)
        self.rejected(self.verify(), "regular single-link file")
        self.assertFalse(self.log.exists())

    def test_native_query_failure_never_emits_success_receipt(self) -> None:
        self.prepare()
        self.config["fail"] = True
        self.rejected(self.verify(), "failed")

    def test_invalid_native_output_never_emits_success_receipt(self) -> None:
        self.prepare()
        for mode in ("invalid_utf8", "oversized"):
            self.config[mode] = True
            self.rejected(self.verify(), "output")
            del self.config[mode]

    def test_package_mutation_during_queries_never_emits_success_receipt(self) -> None:
        self.prepare()
        self.config["mutate"] = str(next(self.assets.glob("*.deb")))
        self.rejected(self.verify(), "conflicts with receipt")


if __name__ == "__main__":
    unittest.main()
