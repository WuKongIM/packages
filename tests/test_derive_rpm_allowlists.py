from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "derive-rpm-allowlists.py"
PREFIX = "rpm/preview/el/9/x86_64/"


def canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"


def sha256(contents: bytes) -> str:
    return hashlib.sha256(contents).hexdigest()


class DeriveRPMAllowlistsTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = TemporaryDirectory(prefix="wk-rpm-allowlists-TEST-ONLY-", dir="/tmp")
        self.root = Path(self.temporary.name)
        self.repository = self.root / "repository"
        (self.repository / "Packages").mkdir(parents=True)
        self.inventory_path = self.root / "inventory.json"
        self.bootstrap_inventory_path = self.root / "bootstrap-inventory.json"
        self.outputs = (
            self.root / "new.json",
            self.root / "signed.json",
            self.root / "active.json",
        )
        self.write_bootstrap_inventory()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def add_package(
        self,
        version: str,
        filename: str,
        *,
        indexed: bool,
        new: bool,
        contents: bytes | None = None,
    ) -> dict[str, object]:
        payload = contents or f"RPM-TEST-ONLY:{version}:{filename}\n".encode()
        path = self.repository / "Packages" / filename
        path.write_bytes(payload)
        published = sha256(payload)
        source = published if new else sha256(b"unsigned:" + payload)
        return {
            "indexed": indexed,
            "new": new,
            "path": f"{PREFIX}Packages/{filename}",
            "published_sha256": published,
            "source_sha256": source,
            "version": version,
        }

    @staticmethod
    def inventory(
        entries: list[dict[str, object]],
        *,
        active: list[str],
        retained: list[str],
    ) -> dict[str, object]:
        return {
            "active_versions": active,
            "audit_release_id": 12345,
            "payloads": {"apt": [], "rpm": entries},
            "retained_versions": retained,
            "schema": "wukongim.native_package_payload_inventory/v1",
        }

    def write_inventory(self, value: object) -> None:
        self.inventory_path.write_bytes(canonical_json(value))

    def write_bootstrap_inventory(
        self,
        *,
        repository: Path | None = None,
        output: Path | None = None,
        new: bool = True,
        contents: bytes | None = None,
    ) -> dict[str, object]:
        repository = repository or self.repository
        output = output or self.bootstrap_inventory_path
        version = "1.0.0"
        rpm_contents = contents or b"RPM-BOOTSTRAP-TEST-ONLY\n"
        rpm_filename = f"wukongim-release-{version}-1.noarch.rpm"
        rpm_path = repository / "Packages" / rpm_filename
        rpm_path.parent.mkdir(parents=True, exist_ok=True)
        if contents is not None or not rpm_path.exists():
            rpm_path.write_bytes(rpm_contents)
        published = rpm_path.read_bytes()
        rpm_source = published if new else b"UNSIGNED:" + published
        apt_source = b"APT-BOOTSTRAP-TEST-ONLY\n"
        apt_filename = f"wukongim-archive-keyring_{version}_all.deb"
        value = {
            "schema": "wukongim.native_package_bootstrap_inventory/v1",
            "version": version,
            "packages": {
                "apt": {
                    "name": "wukongim-archive-keyring",
                    "version": version,
                    "architecture": "all",
                    "filename": apt_filename,
                    "repository_path": f"apt/pool/main/w/wukongim/{apt_filename}",
                    "download_path": f"bootstrap/{apt_filename}",
                    "source_sha256": sha256(apt_source),
                    "source_size": len(apt_source),
                    "published_sha256": sha256(apt_source),
                    "published_size": len(apt_source),
                    "new": new,
                },
                "rpm": {
                    "name": "wukongim-release",
                    "version": version,
                    "architecture": "noarch",
                    "filename": rpm_filename,
                    "repository_path": f"{PREFIX}Packages/{rpm_filename}",
                    "download_path": f"bootstrap/{rpm_filename}",
                    "source_sha256": sha256(rpm_source),
                    "source_size": len(rpm_source),
                    "published_sha256": sha256(published),
                    "published_size": len(published),
                    "new": new,
                },
            },
        }
        output.write_bytes(canonical_json(value))
        return value

    def run_deriver(self) -> subprocess.CompletedProcess[str]:
        new, signed, active = self.outputs
        return subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--inventory",
                str(self.inventory_path),
                "--bootstrap-inventory",
                str(self.bootstrap_inventory_path),
                "--repository-root",
                str(self.repository),
                "--new-output",
                str(new),
                "--signed-output",
                str(signed),
                "--active-output",
                str(active),
            ],
            text=True,
            capture_output=True,
            check=False,
        )

    def assert_safe_failure(self, result: subprocess.CompletedProcess[str], expected: str) -> None:
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn(expected, result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        for output in self.outputs:
            self.assertFalse(os.path.lexists(output), f"partial output remained: {output}")

    def test_derives_canonical_new_signed_and_active_closures(self) -> None:
        new = self.add_package("v3.0.0-beta.5", "new.rpm", indexed=True, new=True)
        old = self.add_package("v3.0.0-beta.4", "old.rpm", indexed=True, new=False)
        retired = self.add_package(
            "v3.0.0-beta.3", "retired.rpm", indexed=False, new=False
        )
        self.write_inventory(
            self.inventory(
                [retired, new, old],
                active=["v3.0.0-beta.5", "v3.0.0-beta.4"],
                retained=["v3.0.0-beta.3"],
            )
        )
        result = self.run_deriver()
        self.assertEqual(result.returncode, 0, result.stderr)
        receipt = json.loads(result.stdout)
        self.assertEqual(result.stdout.encode(), canonical_json(receipt))
        self.assertEqual(
            receipt,
            {
                "active_count": 3,
                "audit_release_id": 12345,
                "new_count": 2,
                "schema": "wukongim/rpm-allowlist-derivation/v1",
                "signed_count": 2,
            },
        )
        new_output, signed_output, active_output = [
            json.loads(path.read_text()) for path in self.outputs
        ]
        for path, value in zip(self.outputs, (new_output, signed_output, active_output)):
            self.assertEqual(path.read_bytes(), canonical_json(value))
            self.assertEqual(path.stat().st_nlink, 1)
        self.assertEqual(
            [entry["path"] for entry in new_output["packages"]],
            ["Packages/new.rpm", "Packages/wukongim-release-1.0.0-1.noarch.rpm"],
        )
        self.assertEqual(new_output["packages"][0]["sha256"], new["published_sha256"])
        self.assertEqual(new_output["schema"], "wukongim/rpm-package-allowlist/v1")
        self.assertEqual(
            [entry["path"] for entry in signed_output["packages"]],
            ["Packages/old.rpm", "Packages/retired.rpm"],
        )
        self.assertEqual(
            active_output,
            {
                "paths": [
                    "Packages/new.rpm",
                    "Packages/old.rpm",
                    "Packages/wukongim-release-1.0.0-1.noarch.rpm",
                ],
                "schema": "wukongim/rpm-active-allowlist/v1",
            },
        )

    def test_classifies_preserved_bootstrap_rpm_as_signed_and_active(self) -> None:
        product = self.add_package(
            "v3.0.0-beta.5", "product.rpm", indexed=True, new=True
        )
        self.write_inventory(
            self.inventory([product], active=[product["version"]], retained=[])
        )
        self.write_bootstrap_inventory(new=False, contents=b"SIGNED-BOOTSTRAP-RPM\n")

        result = self.run_deriver()

        self.assertEqual(result.returncode, 0, result.stderr)
        new_output, signed_output, active_output = [
            json.loads(path.read_text()) for path in self.outputs
        ]
        bootstrap_path = "Packages/wukongim-release-1.0.0-1.noarch.rpm"
        self.assertEqual(
            [item["path"] for item in new_output["packages"]],
            ["Packages/product.rpm"],
        )
        self.assertEqual(
            [item["path"] for item in signed_output["packages"]],
            [bootstrap_path],
        )
        self.assertEqual(
            active_output["paths"], ["Packages/product.rpm", bootstrap_path]
        )

    def test_rejects_bootstrap_inventory_digest_mismatch(self) -> None:
        product = self.add_package(
            "v3.0.0-beta.5", "product.rpm", indexed=True, new=True
        )
        self.write_inventory(
            self.inventory([product], active=[product["version"]], retained=[])
        )
        bootstrap = json.loads(self.bootstrap_inventory_path.read_text())
        bootstrap["packages"]["rpm"]["published_sha256"] = "0" * 64
        bootstrap["packages"]["rpm"]["source_sha256"] = "0" * 64
        self.bootstrap_inventory_path.write_bytes(canonical_json(bootstrap))

        result = self.run_deriver()

        self.assert_safe_failure(result, "bootstrap RPM facts do not match inventory")

    def test_rejects_wrong_prefix_and_unsafe_paths(self) -> None:
        unsafe_values = (
            "rpm/stable/el/9/x86_64/Packages/a.rpm",
            PREFIX + "Packages/../a.rpm",
            PREFIX + "Packages\\a.rpm",
            PREFIX + "Packages//a.rpm",
            PREFIX + "repodata/a.rpm",
            PREFIX + "Packages/a.deb",
        )
        for index, unsafe in enumerate(unsafe_values):
            with self.subTest(path=unsafe):
                case = self.root / f"unsafe-{index}"
                case.mkdir()
                repository = case / "repository"
                (repository / "Packages").mkdir(parents=True)
                payload = b"RPM-TEST-ONLY\n"
                (repository / "Packages/a.rpm").write_bytes(payload)
                entry = {
                    "indexed": True,
                    "new": True,
                    "path": unsafe,
                    "published_sha256": sha256(payload),
                    "source_sha256": sha256(payload),
                    "version": "v1.0.0-beta.1",
                }
                inventory = case / "inventory.json"
                inventory.write_bytes(
                    canonical_json(self.inventory([entry], active=[entry["version"]], retained=[]))
                )
                bootstrap_inventory = case / "bootstrap-inventory.json"
                self.write_bootstrap_inventory(
                    repository=repository, output=bootstrap_inventory
                )
                result = subprocess.run(
                    [
                        sys.executable, str(SCRIPT),
                        "--inventory", str(inventory),
                        "--bootstrap-inventory", str(bootstrap_inventory),
                        "--repository-root", str(repository),
                        "--new-output", str(case / "new.json"),
                        "--signed-output", str(case / "signed.json"),
                        "--active-output", str(case / "active.json"),
                    ],
                    text=True, capture_output=True, check=False,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("RPM inventory entry 0 path", result.stderr)
                self.assertNotIn("Traceback", result.stderr)

    def test_rejects_duplicate_json_keys(self) -> None:
        self.inventory_path.write_text(
            '{"schema":"wukongim.native_package_payload_inventory/v1",'
            '"schema":"wukongim.native_package_payload_inventory/v1"}\n'
        )
        result = self.run_deriver()
        self.assert_safe_failure(result, "duplicate JSON key")

    def test_rejects_missing_or_extra_rpm_entry_fields(self) -> None:
        for mutation in ("missing", "extra"):
            with self.subTest(mutation=mutation):
                entry = self.add_package(
                    f"v1.0.0-beta.{1 if mutation == 'missing' else 2}",
                    f"{mutation}.rpm",
                    indexed=True,
                    new=True,
                )
                if mutation == "missing":
                    del entry["source_sha256"]
                else:
                    entry["unexpected"] = True
                self.write_inventory(
                    self.inventory([entry], active=[entry["version"]], retained=[])
                )
                result = self.run_deriver()
                self.assert_safe_failure(result, "missing or unexpected fields")
                (self.repository / "Packages" / f"{mutation}.rpm").unlink()

    def test_rejects_duplicate_version_or_path(self) -> None:
        for duplicate in ("version", "path"):
            with self.subTest(duplicate=duplicate):
                first = self.add_package("v1.0.0-beta.1", "one.rpm", indexed=True, new=True)
                second = self.add_package("v1.0.0-beta.2", "two.rpm", indexed=True, new=True)
                if duplicate == "version":
                    second["version"] = first["version"]
                    expected = "duplicate version"
                    active = [first["version"]]
                else:
                    second["path"] = first["path"]
                    expected = "duplicate path"
                    active = [first["version"], second["version"]]
                self.write_inventory(self.inventory([first, second], active=active, retained=[]))
                result = self.run_deriver()
                self.assert_safe_failure(result, expected)
                for path in (self.repository / "Packages").iterdir():
                    path.unlink()

    def test_rejects_digest_mismatch(self) -> None:
        entry = self.add_package("v1.0.0-beta.1", "bad-digest.rpm", indexed=True, new=True)
        entry["published_sha256"] = "0" * 64
        entry["source_sha256"] = "0" * 64
        self.write_inventory(self.inventory([entry], active=[entry["version"]], retained=[]))
        result = self.run_deriver()
        self.assert_safe_failure(result, "digest does not match inventory")

    def test_rejects_extra_or_missing_repository_payload(self) -> None:
        for problem in ("extra", "missing"):
            with self.subTest(problem=problem):
                entry = self.add_package(
                    f"v1.0.0-beta.{1 if problem == 'extra' else 2}",
                    f"{problem}.rpm",
                    indexed=True,
                    new=True,
                )
                if problem == "extra":
                    (self.repository / "Packages/unlisted.rpm").write_bytes(b"unlisted")
                else:
                    (self.repository / "Packages" / f"{problem}.rpm").unlink()
                self.write_inventory(
                    self.inventory([entry], active=[entry["version"]], retained=[])
                )
                result = self.run_deriver()
                expected = "does not close over" if problem == "extra" else "cannot inspect repository RPM"
                self.assert_safe_failure(result, expected)
                for path in (self.repository / "Packages").iterdir():
                    path.unlink()

    def test_rejects_symbolic_or_hard_linked_payload(self) -> None:
        for link_type in ("symbolic", "hard"):
            with self.subTest(link_type=link_type):
                contents = b"RPM-TEST-ONLY-link\n"
                outside = self.root / f"outside-{link_type}.rpm"
                outside.write_bytes(contents)
                package = self.repository / "Packages/link.rpm"
                if link_type == "symbolic":
                    package.symlink_to(outside)
                    expected = "regular file, not a link"
                else:
                    os.link(outside, package)
                    expected = "must not be hard linked"
                entry = {
                    "indexed": True,
                    "new": True,
                    "path": PREFIX + "Packages/link.rpm",
                    "published_sha256": sha256(contents),
                    "source_sha256": sha256(contents),
                    "version": f"v1.0.0-beta.{1 if link_type == 'symbolic' else 2}",
                }
                self.write_inventory(
                    self.inventory([entry], active=[entry["version"]], retained=[])
                )
                result = self.run_deriver()
                self.assert_safe_failure(result, expected)
                package.unlink()

    def test_rejects_symbolic_or_hard_linked_inventory(self) -> None:
        entry = self.add_package("v1.0.0-beta.1", "one.rpm", indexed=True, new=True)
        inventory = canonical_json(
            self.inventory([entry], active=[entry["version"]], retained=[])
        )
        for link_type in ("symbolic", "hard"):
            with self.subTest(link_type=link_type):
                outside = self.root / f"outside-inventory-{link_type}.json"
                outside.write_bytes(inventory)
                if link_type == "symbolic":
                    self.inventory_path.symlink_to(outside)
                    expected = "regular file, not a link"
                else:
                    os.link(outside, self.inventory_path)
                    expected = "must not be hard linked"
                result = self.run_deriver()
                self.assert_safe_failure(result, expected)
                self.inventory_path.unlink()

    def test_rejects_new_retained_payload(self) -> None:
        active = self.add_package("v1.0.0-beta.2", "active.rpm", indexed=True, new=True)
        entry = self.add_package("v1.0.0-beta.1", "retained-new.rpm", indexed=False, new=True)
        self.write_inventory(
            self.inventory(
                [active, entry], active=[active["version"]], retained=[entry["version"]]
            )
        )
        result = self.run_deriver()
        self.assert_safe_failure(result, "marks a retained payload as new")

    def test_rejects_existing_or_aliased_outputs_without_partial_files(self) -> None:
        entry = self.add_package("v1.0.0-beta.1", "one.rpm", indexed=True, new=True)
        self.write_inventory(self.inventory([entry], active=[entry["version"]], retained=[]))
        self.outputs[1].write_text("do not overwrite\n")
        result = self.run_deriver()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("already exists", result.stderr)
        self.assertFalse(self.outputs[0].exists())
        self.assertEqual(self.outputs[1].read_text(), "do not overwrite\n")
        self.assertFalse(self.outputs[2].exists())

    def test_rejects_duplicate_output_targets_before_writing(self) -> None:
        entry = self.add_package("v1.0.0-beta.1", "one.rpm", indexed=True, new=True)
        self.write_inventory(self.inventory([entry], active=[entry["version"]], retained=[]))
        target = self.root / "same.json"
        result = subprocess.run(
            [
                sys.executable, str(SCRIPT),
                "--inventory", str(self.inventory_path),
                "--bootstrap-inventory", str(self.bootstrap_inventory_path),
                "--repository-root", str(self.repository),
                "--new-output", str(target),
                "--signed-output", str(target),
                "--active-output", str(self.outputs[2]),
            ],
            text=True, capture_output=True, check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("must be distinct", result.stderr)
        self.assertFalse(target.exists())
        self.assertFalse(self.outputs[2].exists())


if __name__ == "__main__":
    unittest.main()
