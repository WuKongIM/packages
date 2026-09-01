from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location(
    "prepare_package_site", ROOT / "scripts/prepare-package-site.py"
)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def write_v3_base_identity(base: Path) -> dict[str, object]:
    key_values = {
        "apt": (b"apt public certificate\n", "A" * 40, "B" * 40, "C" * 40),
        "rpm": (b"rpm public certificate\n", "D" * 40, "E" * 40, "F" * 40),
    }
    public_keys = {}
    for family, (raw, primary, current, successor) in key_values.items():
        relative = f"keys/{family}-preview.asc"
        path = base / "site" / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        public_keys[family] = {
            "path": relative,
            "sha256": sha(raw),
            "size": len(raw),
            "primary_fingerprint": primary,
            "current_signing_subkey_fingerprint": current,
            "next_signing_subkey_fingerprint": successor,
            "historical_signing_subkey_fingerprints": [],
        }

    toolchain_raw = b'{"schema":"test signing toolchain"}\n'
    toolchain_path = base / "audit/signing-toolchain.json"
    toolchain_path.parent.mkdir(parents=True, exist_ok=True)
    toolchain_path.write_bytes(toolchain_raw)
    toolchain = {
        "image": MODULE.SIGNING_TOOLCHAIN_IMAGE,
        "digest": "sha256:" + "1" * 64,
        "workflow_sha": "2" * 40,
        "manifest_sha256": sha(toolchain_raw),
        "manifest_size": len(toolchain_raw),
    }

    evidence_root = base / "audit/source-attestations"
    evidence_root.mkdir(parents=True)
    evidence_names = [f"asset-{index}.attestation.json" for index in range(7)]
    evidence_names.append("source-attestations.json")
    artifacts = []
    summary_sha = ""
    for index, name in enumerate(sorted(evidence_names)):
        raw = json.dumps({"index": index}, sort_keys=True, separators=(",", ":")).encode() + b"\n"
        (evidence_root / name).write_bytes(raw)
        artifact = {
            "path": f"audit/source-attestations/{name}",
            "sha256": sha(raw),
            "size": len(raw),
        }
        artifacts.append(artifact)
        if name == "source-attestations.json":
            summary_sha = artifact["sha256"]
    return {
        "public_keys": public_keys,
        "source_attestations": {"summary_sha256": summary_sha, "files": artifacts},
        "toolchain": toolchain,
    }


class PreparePackageSiteTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.channels = self.root / "channels.json"
        self.plan = self.root / "plan.json"
        self.source = self.root / "source"
        self.source.mkdir()
        self.output = self.root / "output"
        self.inventory = self.root / "inventory.json"
        self.builder = self.root / "builder.py"
        self.builder.write_text(
            """#!/usr/bin/env python3
import os, pathlib, shutil, sys
args = dict(zip(sys.argv[1::2], sys.argv[2::2]))
packages = pathlib.Path(args['--packages-dir'])
output = pathlib.Path(args['--output'])
apt = output / 'apt/pool/main/w/wukongim'
rpm = output / 'rpm/preview/el/9/x86_64/Packages'
apt.mkdir(parents=True)
rpm.mkdir(parents=True)
for item in packages.iterdir():
    if item.suffix == '.deb': shutil.copyfile(item, apt / item.name)
    if item.suffix == '.rpm': shutil.copyfile(item, rpm / item.name)
(output / 'apt/dists/preview').mkdir(parents=True)
(output / 'apt/dists/preview/Release').write_text('Acquire-By-Hash: yes\\n')
(output / 'rpm/preview/el/9/x86_64/repodata').mkdir(parents=True)
(output / 'rpm/preview/el/9/x86_64/repodata/repomd.xml').write_text('<repomd/>')
race_output = os.environ.get('WK_PREPARE_TEST_RACE_OUTPUT')
if race_output:
    pathlib.Path(race_output).mkdir()
race_inventory = os.environ.get('WK_PREPARE_TEST_RACE_INVENTORY')
if race_inventory:
    pathlib.Path(race_inventory).symlink_to(os.environ['WK_PREPARE_TEST_RACE_TARGET'])
""",
            encoding="utf-8",
        )
        self.builder.chmod(0o755)

    def tearDown(self):
        self.temporary.cleanup()

    def write_inputs(self, releases, active, retained, new):
        self.channels.write_text(json.dumps({
            "schema": "wukongim.native_package_channels/v3",
            "channels": {"preview": {"releases": releases}},
        }), encoding="utf-8")
        self.plan.write_text(json.dumps({
            "schema": MODULE.PLAN_SCHEMA,
            "audit_release_id": 10,
            "base_audit_release_id": None,
            "active_versions": active,
            "retained_versions": retained,
            "new_versions": new,
        }), encoding="utf-8")

    def args(self, base=None):
        return Namespace(
            channels=self.channels,
            plan=self.plan,
            base_root=base,
            source_assets=self.source,
            builder=self.builder,
            output=self.output,
            inventory=self.inventory,
        )

    def arrange_first_release(self):
        deb = b"deb"
        rpm = b"rpm"
        assets = self.source / "110"
        assets.mkdir()
        (assets / "wukongim_3.1.0-rc.1_linux_amd64.deb").write_bytes(deb)
        (assets / "wukongim_3.1.0-rc.1_linux_amd64.rpm").write_bytes(rpm)
        release = {
            "version": "3.1.0-rc.1",
            "source_release_id": 110,
            "deb_sha256": sha(deb),
            "rpm_sha256": sha(rpm),
        }
        self.write_inputs([release], [release["version"]], [], [release["version"]])
        return release

    def test_first_release_prepares_exact_payloads(self):
        deb = b"deb"
        rpm = b"rpm"
        assets = self.source / "110"
        assets.mkdir()
        (assets / "wukongim_3.1.0-rc.1_linux_amd64.deb").write_bytes(deb)
        (assets / "wukongim_3.1.0-rc.1_linux_amd64.rpm").write_bytes(rpm)
        release = {
            "version": "3.1.0-rc.1",
            "source_release_id": 110,
            "deb_sha256": sha(deb),
            "rpm_sha256": sha(rpm),
        }
        self.write_inputs([release], [release["version"]], [], [release["version"]])
        inventory = MODULE.prepare(self.args())
        self.assertTrue((self.output / "apt/pool/main/w/wukongim/wukongim_3.1.0-rc.1_linux_amd64.deb").is_file())
        self.assertTrue(all(item["new"] for values in inventory["payloads"].values() for item in values))

    def test_rejects_source_digest_mismatch(self):
        assets = self.source / "110"
        assets.mkdir()
        (assets / "wukongim_3.1.0-rc.1_linux_amd64.deb").write_bytes(b"wrong")
        (assets / "wukongim_3.1.0-rc.1_linux_amd64.rpm").write_bytes(b"rpm")
        release = {
            "version": "3.1.0-rc.1",
            "source_release_id": 110,
            "deb_sha256": "a" * 64,
            "rpm_sha256": sha(b"rpm"),
        }
        self.write_inputs([release], [release["version"]], [], [release["version"]])
        with self.assertRaisesRegex(MODULE.PreparationError, "SHA-256"):
            MODULE.prepare(self.args())

    def test_rejects_existing_output(self):
        self.output.mkdir()
        self.write_inputs([], [], [], [])
        with self.assertRaises(MODULE.PreparationError):
            MODULE.prepare(self.args())

    def test_exclusive_directory_publish_never_replaces_an_existing_empty_directory(self):
        staged = self.root / "staged"
        destination = self.root / "destination"
        staged.mkdir()
        destination.mkdir()

        with self.assertRaisesRegex(MODULE.PreparationError, "appeared"):
            MODULE.rename_directory_exclusive(staged, destination)

        self.assertTrue(staged.is_dir())
        self.assertTrue(destination.is_dir())

    def test_rejects_dangling_inventory_symlink_without_publishing(self):
        self.arrange_first_release()
        victim = self.root / "outside-inventory.json"
        self.inventory.symlink_to(victim)

        with self.assertRaisesRegex(MODULE.PreparationError, "inventory output"):
            MODULE.prepare(self.args())

        self.assertFalse(self.output.exists())
        self.assertFalse(victim.exists())
        self.assertTrue(self.inventory.is_symlink())

    def test_inventory_race_cannot_redirect_write_and_rolls_back_repository(self):
        self.arrange_first_release()
        victim = self.root / "outside-inventory.json"

        with mock.patch.dict(os.environ, {
            "WK_PREPARE_TEST_RACE_INVENTORY": str(self.inventory),
            "WK_PREPARE_TEST_RACE_TARGET": str(victim),
        }):
            with self.assertRaisesRegex(MODULE.PreparationError, "inventory output"):
                MODULE.prepare(self.args())

        self.assertFalse(self.output.exists())
        self.assertFalse(victim.exists())
        self.assertTrue(self.inventory.is_symlink())

    def test_output_race_rolls_back_the_created_inventory(self):
        self.arrange_first_release()

        with mock.patch.dict(os.environ, {
            "WK_PREPARE_TEST_RACE_OUTPUT": str(self.output),
        }):
            with self.assertRaisesRegex(MODULE.PreparationError, "output"):
                MODULE.prepare(self.args())

        self.assertTrue(self.output.is_dir())
        self.assertEqual([], list(self.output.iterdir()))
        self.assertFalse(os.path.lexists(self.inventory))

    def test_inventory_write_failure_rolls_back_both_outputs(self):
        self.arrange_first_release()

        with mock.patch.object(MODULE.os, "write", side_effect=OSError("disk full")):
            with self.assertRaisesRegex(MODULE.PreparationError, "write inventory output"):
                MODULE.prepare(self.args())

        self.assertFalse(os.path.lexists(self.output))
        self.assertFalse(os.path.lexists(self.inventory))

    def test_rejects_inventory_nested_inside_repository_without_creating_output(self):
        self.arrange_first_release()
        self.inventory = self.output / "inventory.json"

        with self.assertRaisesRegex(MODULE.PreparationError, "inside repository"):
            MODULE.prepare(self.args())

        self.assertFalse(os.path.lexists(self.output))

    def test_accepts_a_composed_v3_base_snapshot(self):
        old_deb = b"old deb"
        old_rpm = b"old signed rpm"
        new_deb = b"new deb"
        new_rpm = b"new rpm"
        old = {
            "version": "3.1.0-rc.1",
            "source_release_id": 109,
            "deb_sha256": sha(old_deb),
            "rpm_sha256": sha(old_rpm),
        }
        new = {
            "version": "3.1.0-rc.2",
            "source_release_id": 110,
            "deb_sha256": sha(new_deb),
            "rpm_sha256": sha(new_rpm),
        }
        assets = self.source / "110"
        assets.mkdir()
        (assets / "wukongim_3.1.0-rc.2_linux_amd64.deb").write_bytes(new_deb)
        (assets / "wukongim_3.1.0-rc.2_linux_amd64.rpm").write_bytes(new_rpm)
        self.write_inputs([old, new], [old["version"], new["version"]], [], [new["version"]])
        plan = json.loads(self.plan.read_text(encoding="utf-8"))
        plan["base_audit_release_id"] = 9
        self.plan.write_text(json.dumps(plan), encoding="utf-8")

        base = self.root / "base"
        apt_path = "apt/pool/main/w/wukongim/wukongim_3.1.0-rc.1_linux_amd64.deb"
        rpm_path = "rpm/preview/el/9/x86_64/Packages/wukongim_3.1.0-rc.1_linux_amd64.rpm"
        (base / "audit").mkdir(parents=True)
        (base / "site" / Path(apt_path).parent).mkdir(parents=True)
        (base / "site" / Path(rpm_path).parent).mkdir(parents=True)
        (base / "site" / apt_path).write_bytes(old_deb)
        (base / "site" / rpm_path).write_bytes(old_rpm)
        identity = write_v3_base_identity(base)
        (base / "audit/snapshot.json").write_text(json.dumps({
            "schema": "wukongim.native_package_snapshot/v3",
            "audit_release_id": 9,
            "control_sha": "a" * 40,
            "releases": [],
            "retirement": {"phase": "none", "version": None, "not_before": None},
            "payloads": {
                "apt": [{
                    "version": old["version"], "path": apt_path,
                    "source_sha256": sha(old_deb), "published_sha256": sha(old_deb),
                    "indexed": True,
                }],
                "rpm": [{
                    "version": old["version"], "path": rpm_path,
                    "source_sha256": sha(old_rpm), "published_sha256": sha(old_rpm),
                    "indexed": True,
                }],
            },
            **identity,
        }), encoding="utf-8")

        inventory = MODULE.prepare(self.args(base))

        self.assertEqual(
            [old["version"], new["version"]],
            [item["version"] for item in inventory["payloads"]["apt"]],
        )
        self.assertTrue((self.output / apt_path).is_file())

    def test_rejects_v3_base_when_archived_toolchain_manifest_differs(self):
        base = self.root / "base"
        (base / "audit").mkdir(parents=True)
        (base / "site").mkdir(parents=True)
        identity = write_v3_base_identity(base)
        (base / "audit/snapshot.json").write_text(json.dumps({
            "schema": MODULE.SNAPSHOT_SCHEMA,
            "audit_release_id": 9,
            "control_sha": "a" * 40,
            "releases": [],
            "retirement": {"phase": "none", "version": None, "not_before": None},
            "payloads": {"apt": [], "rpm": []},
            **identity,
        }), encoding="utf-8")
        (base / "audit/signing-toolchain.json").write_bytes(b"changed\n")

        with self.assertRaisesRegex(MODULE.PreparationError, "toolchain manifest differs"):
            MODULE.load_base(base, 9)

    def test_rejects_a_symbolic_link_base_root(self):
        base = self.root / "real-base"
        (base / "audit").mkdir(parents=True)
        (base / "site").mkdir()
        (base / "audit/snapshot.json").write_text(json.dumps({
            "schema": MODULE.SNAPSHOT_SCHEMA,
            "audit_release_id": 9,
            "payloads": {"apt": [], "rpm": []},
        }), encoding="utf-8")
        linked_base = self.root / "linked-base"
        linked_base.symlink_to(base, target_is_directory=True)

        with self.assertRaisesRegex(MODULE.PreparationError, "non-symbolic-link"):
            MODULE.load_base(linked_base, 9)


if __name__ == "__main__":
    unittest.main()
