from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'tests/native_bootstrap_preparation_drill.py'


class NativeBootstrapDrillTests(unittest.TestCase):
    def load(self):
        self.assertTrue(SCRIPT.is_file(), 'missing native bootstrap preparation drill')
        spec = importlib.util.spec_from_file_location('bootstrap_drill_test', SCRIPT)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_help_never_runs_build_or_install(self):
        self.load()
        result = subprocess.run([sys.executable, '-B', str(SCRIPT), '--help'], capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertIn(b'--source-sha', result.stdout)
        self.assertIn(b'TEST ONLY', result.stdout)

    def test_missing_native_tool_retains_failure_and_cleanup_receipt(self):
        drill = self.load()
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp)
            with mock.patch.object(drill.shutil, 'which', return_value=None), \
                 mock.patch.object(drill.os, 'geteuid', return_value=0), \
                 mock.patch.object(drill.sys, 'platform', 'linux'):
                code = drill.main(['--output-dir', tmp, '--source-sha', 'a' * 40])
            self.assertEqual(code, 1)
            receipt = json.loads((output / 'native-bootstrap-preparation.json').read_bytes())
            self.assertIs(receipt['test_only'], True)
            self.assertIs(receipt['passed'], False)
            self.assertIs(receipt['scratch_removed'], True)
            self.assertEqual(receipt['source_sha'], 'a' * 40)
            self.assertEqual(receipt['cases'], [])
            self.assertIn('required native tool unavailable', receipt['failure'])
            self.assertEqual(list(output.iterdir()), [output / 'native-bootstrap-preparation.json'])

    def test_existing_receipt_is_not_overwritten(self):
        drill = self.load()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'native-bootstrap-preparation.json'
            path.write_text('first failure preserved\n')
            with self.assertRaises(FileExistsError):
                drill.main(['--output-dir', tmp, '--source-sha', 'a' * 40])
            self.assertEqual(path.read_text(), 'first failure preserved\n')
