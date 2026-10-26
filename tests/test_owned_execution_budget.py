"""Fast shared-budget parsers, finite counters and corruption contracts."""
import importlib.util
import os
from pathlib import Path
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / 'scripts/object-storage-owned-budget.py'
spec = importlib.util.spec_from_file_location('owned_numeric_budget', MODULE)
B = importlib.util.module_from_spec(spec)
spec.loader.exec_module(B)
REQUEST = 'a' * 64


def budget(**changes):
    now = time.monotonic_ns()
    fields = dict(request_sha256=REQUEST, effect_deadline_ns=now + 10_000_000_000,
        hard_deadline_ns=now + 12_000_000_000, max_process_output_bytes=1500, max_processes=100)
    fields.update(changes)
    return B.SharedBudget.create(**fields)


class OwnedBudgetContracts(unittest.TestCase):
    def test_exact_counter_caps_and_snapshot_after_cancel(self):
        with budget(max_process_output_bytes=5, max_processes=1) as shared:
            self.assertEqual(shared.reserve_output(4), 4)
            self.assertEqual(shared.reserve_process(), 1)
            with self.assertRaises(B.BudgetError): shared.reserve_output(2)
            with self.assertRaises(B.BudgetError): shared.reserve_process()
            self.assertEqual(shared.snapshot()['process_output_bytes'], 4)
            shared.cancel()
            with self.assertRaises(B.BudgetError): shared.reserve_output(1)
            self.assertTrue(shared.snapshot()['cancelled'])
            self.assertEqual(shared.snapshot()['processes_started'], 1)

    def test_snapshot_after_effect_deadline_does_not_grant(self):
        with budget() as shared:
            with mock.patch.object(B.time, 'monotonic_ns', return_value=shared.effect_deadline_ns + 1):
                self.assertEqual(shared.snapshot()['request_sha256'], REQUEST)
                with self.assertRaises(B.BudgetError): shared.check()
                with self.assertRaises(B.BudgetError): shared.reserve_output(1)

    def test_record_corruption_is_not_reset(self):
        with budget() as shared:
            before = os.pread(shared.fileno(), B.RECORD_SIZE, 0)
            os.pwrite(shared.fileno(), bytes([before[-1] ^ 1]), B.RECORD_SIZE - 1)
            with self.assertRaises(B.BudgetError): shared.reserve_output(1)
            self.assertEqual(os.pread(shared.fileno(), B.RECORD_SIZE - 1, 0), before[:-1])

    def test_invalid_scopes_and_second_context_refuse(self):
        for changes in ({'request_sha256': 'bad'}, {'max_process_output_bytes': True},
                        {'max_processes': 0}, {'max_process_output_bytes': 2**40}):
            with self.subTest(changes=changes), self.assertRaises(B.BudgetError): budget(**changes)
        with budget() as shared:
            with self.assertRaises(B.BudgetError):
                B.SharedBudget.attach(shared.fileno(), expected_request_sha256=REQUEST)
            self.assertEqual(shared.snapshot()['process_output_bytes'], 0)


    def test_try_cancel_persists_and_busy_path_never_waits(self):
        with budget() as shared:
            effect, hard = shared.effect_deadline_ns, shared.hard_deadline_ns
            with mock.patch.object(B.fcntl, 'lockf', side_effect=BlockingIOError(B.errno.EAGAIN, 'fixture busy')) as lock:
                with mock.patch.object(B.select, 'select', side_effect=AssertionError('busy try_cancel waited')):
                    self.assertFalse(shared.try_cancel())
                self.assertEqual(lock.call_count, 1)
            self.assertFalse(shared.snapshot()['cancelled'])
            self.assertTrue(shared.try_cancel())
            self.assertTrue(shared.snapshot()['cancelled'])
            self.assertEqual((shared.effect_deadline_ns, shared.hard_deadline_ns), (effect, hard))
            with self.assertRaises(B.BudgetError): shared.reserve_process()

    def test_try_cancel_corrupt_record_refuses_without_repair(self):
        with budget() as shared:
            fd = shared.fileno()
            raw = os.pread(fd, B.RECORD_SIZE, 0)
            os.pwrite(fd, bytes([raw[-1] ^ 1]), B.RECORD_SIZE - 1)
            broken = os.pread(fd, B.RECORD_SIZE, 0)
            with self.assertRaises(B.BudgetError): shared.try_cancel()
            self.assertEqual(os.pread(fd, B.RECORD_SIZE, 0), broken)

    def test_wrong_request_attach_and_reused_fd_fail_closed(self):
        with budget() as shared:
            # Failed attach never takes ownership of the caller's descriptor.
            with self.assertRaises(B.BudgetError):
                B.SharedBudget.attach(shared.fileno(), expected_request_sha256='b' * 64)
            self.assertEqual(shared.snapshot()['process_output_bytes'], 0)
            with self.assertRaises(B.BudgetError): shared.reserve_output(-1)


if __name__ == '__main__':
    unittest.main()
