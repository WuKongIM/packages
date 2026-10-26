"""Execution entry contracts; public production authority stays unavailable."""
import builtins
import importlib.util
from pathlib import Path
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]


def load():
    spec = importlib.util.spec_from_file_location('delivery_execution', ROOT / 'scripts/execute-object-storage-delivery.py')
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


class ExecutionEntryContract(unittest.TestCase):
    def test_production_entry_refuses_before_optional_sdk_import(self):
        original = builtins.__import__

        def guarded(name, *args, **kwargs):
            if name.startswith(('requests', 'aliyunsdk', 'alibabacloud')):
                self.fail('disabled production entry attempted an SDK import')
            return original(name, *args, **kwargs)

        with mock.patch.object(builtins, '__import__', side_effect=guarded):
            execution = load()
            with self.assertRaisesRegex(execution.ExecutionError, 'protected production entrypoint'):
                execution.run_delivery({'operation': 'stage_immutable'})
