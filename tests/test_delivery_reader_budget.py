"""Per-instance read budgets; fixture IO never opens sockets or native tools."""
from __future__ import annotations

import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock
import urllib.error
import urllib.request


ROOT = Path(__file__).resolve().parents[1]


def load(name):
    spec = importlib.util.spec_from_file_location("budget_" + name.replace("-", "_"), ROOT / "scripts" / name)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


SOURCE = load("resolve-source-release.py")
AUDIT = load("resolve-audit-release.py")
SEAL = load("verify-stable-seal-inputs.py")


class BudgetDenied(RuntimeError):
    pass


class RecordingBudget:
    """Exercise the caller seam; it supplies no execution authorization."""
    def __init__(self, remaining=12.5, deny=False):
        self.seconds = remaining
        self.deny = deny
        self.checks = 0
        self.opens = []

    def check(self):
        self.checks += 1
        if self.deny:
            raise BudgetDenied("fixture budget exhausted")

    def remaining(self):
        return self.seconds

    def open(self, open_callable, request, timeout):
        self.check()
        self.opens.append((request, timeout))
        return open_callable(request, timeout=min(timeout, self.remaining()))


class GitHubReaderBudgetTest(unittest.TestCase):
    def test_api_and_direct_asset_open_use_the_same_instance_budget(self):
        for module in (SOURCE, AUDIT):
            with self.subTest(reader=module.__name__):
                budget = RecordingBudget()
                reader = module.GitHubReader("https://api.github.com", "https://api.github.com", None, budget=budget)
                with mock.patch.object(reader._no_redirect, "open", side_effect=[io.BytesIO(b'{"ok":true}'), io.BytesIO(b"payload")]) as opened:
                    self.assertEqual(reader.api_json("repos/fixture/repo"), {"ok": True})
                    with reader.open_asset(12) as response:
                        self.assertEqual(response.read(), b"payload")
                self.assertEqual([timeout for _, timeout in budget.opens], [30, 60])
                self.assertEqual([call.kwargs["timeout"] for call in opened.call_args_list], [12.5, 12.5])

    def test_redirected_asset_open_is_budgeted_without_forwarding_authorization(self):
        for module in (SOURCE, AUDIT):
            with self.subTest(reader=module.__name__):
                budget = RecordingBudget()
                reader = module.GitHubReader("https://api.github.com", "https://api.github.com", "FIXTURE", budget=budget)
                redirect = urllib.error.HTTPError("https://api.github.com/asset", 302, "fixture", {"Location": "https://release-assets.githubusercontent.com/fixture"}, io.BytesIO())
                with mock.patch.object(reader._no_redirect, "open", side_effect=redirect), mock.patch.object(urllib.request, "urlopen", return_value=io.BytesIO(b"payload")) as redirected:
                    with reader.open_asset(12) as response:
                        self.assertEqual(response.read(), b"payload")
                self.assertEqual([timeout for _, timeout in budget.opens], [60, 60])
                self.assertIsNone(redirected.call_args.args[0].get_header("Authorization"))
                self.assertEqual(redirected.call_args.kwargs["timeout"], 12.5)

    def test_exhausted_budget_never_calls_the_network_opener(self):
        for module in (SOURCE, AUDIT):
            with self.subTest(reader=module.__name__):
                reader = module.GitHubReader("https://api.github.com", "https://api.github.com", None, budget=RecordingBudget(deny=True))
                with mock.patch.object(reader._no_redirect, "open") as opened:
                    with self.assertRaises(BudgetDenied):
                        reader.api_json("repos/fixture/repo")
                    with self.assertRaises(BudgetDenied):
                        reader.open_asset(12)
                    opened.assert_not_called()

    def test_default_reader_keeps_original_opener_and_timeouts(self):
        for module in (SOURCE, AUDIT):
            with self.subTest(reader=module.__name__):
                reader = module.GitHubReader("https://api.github.com", "https://api.github.com", None)
                with mock.patch.object(reader._no_redirect, "open", side_effect=[io.BytesIO(b"{}"), io.BytesIO(b"payload")]) as opened:
                    self.assertEqual(reader.api_json("repos/fixture/repo"), {})
                    reader.open_asset(12).close()
                self.assertEqual([call.kwargs["timeout"] for call in opened.call_args_list], [30, 60])

    def test_resolvers_pass_the_budget_to_their_reader(self):
        class ReaderReached(RuntimeError):
            pass
        budget = RecordingBudget()
        with tempfile.TemporaryDirectory() as temporary:
            for module, resolver in ((SOURCE, SOURCE.resolve_source_release), (AUDIT, AUDIT.resolve_audit_release)):
                with self.subTest(resolver=resolver.__name__), mock.patch.object(module, "GitHubReader", side_effect=ReaderReached) as factory:
                    arguments = dict(release_id=12, output_dir=Path(temporary) / resolver.__name__, api_base_url="https://api.github.com", download_base_url="https://api.github.com", token=None, budget=budget)
                    if module is AUDIT:
                        arguments["expected_control_sha"] = "a" * 40
                    with self.assertRaises(ReaderReached):
                        resolver(**arguments)
                    self.assertIs(factory.call_args.kwargs["budget"], budget)


class SourceHelperBudgetTest(unittest.TestCase):
    def execute(self, args, **kwargs):
        kwargs["stdout"].write(b"{}")
        return SimpleNamespace(returncode=0)

    def test_native_helper_uses_remaining_budget_and_checks_both_sides(self):
        budget = RecordingBudget()
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(SEAL.subprocess, "run", side_effect=self.execute) as executed:
            result = SEAL.run_checked_helper("verify-source-package-metadata.py", [], home=Path(temporary), budget=budget)
        self.assertEqual(result, {})
        self.assertEqual(executed.call_args.kwargs["timeout"], 12.5)
        self.assertGreaterEqual(budget.checks, 2)

    def test_native_helper_never_spawns_after_budget_exhaustion(self):
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(SEAL.subprocess, "run") as executed:
            with self.assertRaises(BudgetDenied):
                SEAL.run_checked_helper("verify-source-package-metadata.py", [], home=Path(temporary), budget=RecordingBudget(deny=True))
            executed.assert_not_called()

    def test_default_native_helper_keeps_its_seven_hundred_second_limit(self):
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(SEAL.subprocess, "run", side_effect=self.execute) as executed:
            self.assertEqual(SEAL.run_checked_helper("verify-source-package-metadata.py", [], home=Path(temporary)), {})
        self.assertEqual(executed.call_args.kwargs["timeout"], 700)

    def test_fresh_source_propagates_one_budget_to_resolution_and_both_helpers(self):
        budget = RecordingBudget()
        original = dict(repository="WuKongIM/WuKongIM", release_id=12, tag="v3.0.0", version="3.0.0", prerelease=False, published_at="2026-10-21T00:00:00Z", source_sha="d" * 40, assets=[], checksum_asset="checksums", checksum_entries=[])
        metadata = {"fixture": "metadata"}
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary).resolve()
            anchors = {}
            for name, value in (("resolution.json", original), ("metadata.json", metadata)):
                raw = SEAL.C.canonical_json(value)
                (source / name).write_bytes(raw)
                anchors[name] = {"size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
            with mock.patch.object(SEAL.SOURCE, "resolve_source_release", return_value=original) as resolved, mock.patch.object(SEAL, "run_checked_helper", side_effect=[{}, metadata]) as helper:
                self.assertEqual(SEAL.verify_source(source_root=source, source_token=None, source_files=anchors, budget=budget), SEAL.source_identity(original))
            self.assertIs(resolved.call_args.kwargs["budget"], budget)
            self.assertEqual(helper.call_count, 2)
            self.assertTrue(all(call.kwargs["budget"] is budget for call in helper.call_args_list))

    def test_seal_input_verification_propagates_the_budget_to_fresh_source(self):
        budget = RecordingBudget()
        plan = {"candidate": {"source_files": {}}}
        source = {"release_id": 12, "source_sha": "d" * 40, "version": "3.0.0"}
        identity = {"plan_sha256": hashlib.sha256(SEAL.C.canonical_json(plan)).hexdigest(), "source": source, "version": "3.0.0"}
        with mock.patch.object(SEAL, "candidate_plan", return_value=plan), mock.patch.object(SEAL, "candidate_identity", return_value=identity), mock.patch.object(SEAL, "verify_control", return_value={}), mock.patch.object(SEAL, "verify_candidate"), mock.patch.object(SEAL, "current_control"), mock.patch.object(SEAL, "verify_source", return_value=source) as verify:
            SEAL.verify_seal_inputs(reader=object(), expected_control_sha="a" * 40, archive_path=Path("archive"), receipt_path=Path("receipt"), plan_path=Path("plan"), control_root=Path("control"), source_root=Path("source"), apt_receipt=Path("apt"), rpm_receipt=Path("rpm"), source_token=None, test_only=False, budget=budget)
        self.assertIs(verify.call_args.kwargs["budget"], budget)


if __name__ == "__main__":
    unittest.main()
