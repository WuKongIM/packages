from __future__ import annotations

import ast
import importlib.util
import json
import subprocess
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location(
    "plan_package_publication", ROOT / "scripts/plan-package-publication.py"
)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

SHA = "1" * 40
DIGEST_A = "a" * 64
DIGEST_B = "b" * 64


def release(version: str, audit_id: int, state: str = "active", not_before=None):
    return {
        "version": version,
        "source_sha": SHA,
        "source_release_id": audit_id + 100,
        "package_release_id": audit_id,
        "deb_sha256": DIGEST_A,
        "rpm_sha256": DIGEST_B,
        "state": state,
        "not_before": not_before,
    }


def channels(operation: str, audit_id, base_id, target, releases):
    return {
        "schema": MODULE.CHANNELS_SCHEMA,
        "channels": {
            "preview": {
                "releases": releases,
                "publication": {
                    "audit_release_id": audit_id,
                    "base_audit_release_id": base_id,
                    "operation": operation,
                    "target_version": target,
                },
            }
        },
    }


def snapshot(audit_id: int, releases):
    return {
        "schema": MODULE.SNAPSHOT_SCHEMA,
        "audit_release_id": audit_id,
        "control_sha": "2" * 40,
        "releases": releases,
        "retirement": {"phase": "none", "version": None, "not_before": None},
        "payloads": {"apt": [], "rpm": []},
        "public_keys": {
            "apt": {
                "path": "keys/apt-preview.asc",
                "sha256": "3" * 64,
                "size": 100,
                "primary_fingerprint": "A" * 40,
                "current_signing_subkey_fingerprint": "B" * 40,
                "next_signing_subkey_fingerprint": "C" * 40,
                "historical_signing_subkey_fingerprints": [],
            },
            "rpm": {
                "path": "keys/rpm-preview.asc",
                "sha256": "4" * 64,
                "size": 100,
                "primary_fingerprint": "D" * 40,
                "current_signing_subkey_fingerprint": "E" * 40,
                "next_signing_subkey_fingerprint": "F" * 40,
                "historical_signing_subkey_fingerprints": [],
            },
        },
        "source_attestations": None,
        "toolchain": {
            "image": MODULE.SIGNING_TOOLCHAIN_IMAGE,
            "digest": "sha256:" + "5" * 64,
            "workflow_sha": "6" * 40,
            "manifest_sha256": "7" * 64,
            "manifest_size": 100,
        },
    }


class PublicationPlanTests(unittest.TestCase):
    def test_first_add_release(self):
        desired = channels("add_release", 10, None, "3.1.0-rc.1", [release("3.1.0-rc.1", 10)])
        plan = MODULE.build_plan(desired, None, SHA, datetime.now(timezone.utc))
        self.assertEqual(plan["new_versions"], ["3.1.0-rc.1"])
        self.assertEqual(plan["active_versions"], ["3.1.0-rc.1"])

    def test_plan_result_fields_are_exact_and_source_literals_have_no_duplicate_keys(self):
        desired = channels("add_release", 10, None, "3.1.0-rc.1", [release("3.1.0-rc.1", 10)])
        plan = MODULE.build_plan(desired, None, SHA, datetime.now(timezone.utc))
        self.assertEqual({
            "schema", "control_sha", "operation", "audit_release_id",
            "base_audit_release_id", "target_version", "active_versions",
            "retained_versions", "new_versions", "removed_versions", "not_before",
        }, set(plan))

        tree = ast.parse((ROOT / "scripts/plan-package-publication.py").read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Dict):
                continue
            literal_keys = [
                key.value for key in node.keys
                if isinstance(key, ast.Constant) and isinstance(key.value, str)
            ]
            self.assertEqual(len(literal_keys), len(set(literal_keys)))

    def test_add_to_base_preserves_existing_identity(self):
        old = release("3.1.0-rc.1", 10)
        new = release("3.1.0-rc.2", 20)
        desired = channels("add_release", 20, 10, new["version"], [old, new])
        plan = MODULE.build_plan(desired, snapshot(10, [old]), SHA, datetime.now(timezone.utc))
        self.assertEqual(plan["new_versions"], [new["version"]])

    def test_add_rejects_version_rollback_and_prerelease_misordering(self):
        for old_version, target_version in (
            ("9.0.0-rc.1", "1.0.0-rc.1"),
            ("3.1.0-rc.10", "3.1.0-rc.2"),
        ):
            with self.subTest(old=old_version, target=target_version):
                old = release(old_version, 10)
                new = release(target_version, 20)
                desired = channels("add_release", 20, 10, target_version, [old, new])
                with self.assertRaisesRegex(MODULE.PlanError, "must be newer"):
                    MODULE.build_plan(
                        desired, snapshot(10, [old]), SHA, datetime.now(timezone.utc)
                    )

    def test_semver_prerelease_numeric_and_text_precedence(self):
        self.assertTrue(MODULE.semver_is_greater("3.1.0-rc.10", "3.1.0-rc.2"))
        self.assertTrue(MODULE.semver_is_greater("3.1.0-rc.1", "3.1.0-10"))
        self.assertTrue(MODULE.semver_is_greater("3.1.0-rc.1.1", "3.1.0-rc.1"))
        self.assertFalse(MODULE.semver_is_greater("3.1.0-alpha", "3.1.0-rc.1"))

    def test_native_comparison_uses_exact_deb_and_rpm_mappings(self):
        calls = []

        def runner(command, **kwargs):
            calls.append(command)
            if command[0] == "/fixed/dpkg":
                return subprocess.CompletedProcess(command, 0, b"", b"")
            return subprocess.CompletedProcess(command, 0, b"1\n", b"")

        with mock.patch.object(MODULE.shutil, "which", side_effect=("/fixed/dpkg", "/fixed/rpm")):
            self.assertTrue(
                MODULE.native_version_is_greater(
                    "3.1.0-rc.2-hotfix", "3.1.0-rc.1", runner=runner
                )
            )
        self.assertEqual(
            calls[0],
            ["/fixed/dpkg", "--compare-versions", "3.1.0~rc.2-hotfix", "gt", "3.1.0~rc.1"],
        )
        self.assertIn('rpm.vercmp("3.1.0~rc.2_hotfix", "3.1.0~rc.1")', calls[1][2])

    def test_add_rejects_existing_mutation(self):
        old = release("3.1.0-rc.1", 10)
        changed = dict(old, deb_sha256="c" * 64)
        new = release("3.1.0-rc.2", 20)
        desired = channels("add_release", 20, 10, new["version"], [changed, new])
        with self.assertRaisesRegex(MODULE.PlanError, "changed existing"):
            MODULE.build_plan(desired, snapshot(10, [old]), SHA, datetime.now(timezone.utc))

    def test_remove_indexes_preserves_payload_identity(self):
        old = release("3.1.0-rc.1", 10)
        newer = release("3.1.0-rc.2", 20)
        retired = dict(old, state="index_removed", not_before="2026-09-01T01:00:00Z")
        desired = channels("remove_indexes", 30, 20, old["version"], [retired, newer])
        plan = MODULE.build_plan(desired, snapshot(20, [old, newer]), SHA,
                                 datetime(2026, 9, 1, tzinfo=timezone.utc))
        self.assertEqual(plan["retained_versions"], [old["version"]])

    def test_remove_indexes_rejects_newest_active_version(self):
        old = release("3.1.0-rc.1", 10)
        newer = release("3.1.0-rc.2", 20)
        removed_newer = dict(
            newer, state="index_removed", not_before="2026-09-01T01:00:00Z"
        )
        desired = channels(
            "remove_indexes", 30, 20, newer["version"], [old, removed_newer]
        )
        with self.assertRaisesRegex(MODULE.PlanError, "oldest active"):
            MODULE.build_plan(
                desired,
                snapshot(20, [old, newer]),
                SHA,
                datetime(2026, 9, 1, tzinfo=timezone.utc),
            )

    def test_remove_indexes_requires_a_full_thirty_minute_safety_window(self):
        now = datetime(2026, 9, 1, tzinfo=timezone.utc)
        old = release("3.1.0-rc.1", 10)
        newer = release("3.1.0-rc.2", 20)
        base = snapshot(20, [old, newer])

        too_soon = dict(
            old,
            state="index_removed",
            not_before="2026-09-01T00:29:59Z",
        )
        with self.assertRaisesRegex(MODULE.PlanError, "at least 30 minutes"):
            MODULE.build_plan(
                channels("remove_indexes", 30, 20, old["version"], [too_soon, newer]),
                base,
                SHA,
                now,
            )

        exact_boundary = dict(
            old,
            state="index_removed",
            not_before="2026-09-01T00:30:00Z",
        )
        plan = MODULE.build_plan(
            channels(
                "remove_indexes",
                30,
                20,
                old["version"],
                [exact_boundary, newer],
            ),
            base,
            SHA,
            now,
        )
        self.assertEqual(plan["not_before"], "2026-09-01T00:30:00Z")

    def test_remove_payloads_enforces_not_before(self):
        retired = release("3.1.0-rc.1", 10, "index_removed", "2026-09-01T01:00:00Z")
        active = release("3.1.0-rc.2", 20)
        desired = channels("remove_payloads", 40, 30, retired["version"], [active])
        base = snapshot(30, [retired, active])
        with self.assertRaisesRegex(MODULE.PlanError, "earlier"):
            MODULE.build_plan(desired, base, SHA,
                              datetime(2026, 9, 1, 0, 59, 59, tzinfo=timezone.utc))
        plan = MODULE.build_plan(desired, base, SHA,
                                 datetime(2026, 9, 1, 1, 0, 0, tzinfo=timezone.utc))
        self.assertEqual(plan["removed_versions"], [retired["version"]])
        self.assertEqual(plan["not_before"], retired["not_before"])

    def test_none_is_only_valid_without_snapshot_or_releases(self):
        desired = channels("none", None, None, None, [])
        plan = MODULE.build_plan(desired, None, SHA, datetime.now(timezone.utc))
        self.assertEqual(plan["operation"], "none")
        invalid = channels("none", None, None, None, [release("3.1.0-rc.1", 10)])
        with self.assertRaises(MODULE.PlanError):
            MODULE.build_plan(invalid, None, SHA, datetime.now(timezone.utc))

    def test_load_base_rejects_duplicate_json_keys(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "snapshot.json"
            path.write_text('{"schema":"x","schema":"y"}', encoding="utf-8")
            with self.assertRaisesRegex(MODULE.PlanError, "duplicate JSON key"):
                MODULE.load_base(path, 1)

    def test_load_base_accepts_the_composed_v3_snapshot_schema(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "snapshot.json"
            path.write_text(json.dumps(snapshot(7, [])), encoding="utf-8")

            loaded = MODULE.load_base(path, 7)

        self.assertIsNotNone(loaded)
        self.assertEqual("wukongim.native_package_snapshot/v3", loaded["schema"])

    def test_load_base_requires_the_complete_v3_identity_fields(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "snapshot.json"
            value = snapshot(7, [])
            del value["toolchain"]
            path.write_text(json.dumps(value), encoding="utf-8")

            with self.assertRaisesRegex(MODULE.PlanError, "fields must be exactly"):
                MODULE.load_base(path, 7)


if __name__ == "__main__":
    unittest.main()
