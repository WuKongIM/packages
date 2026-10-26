"""Portable bounds only; Linux descendant ownership has a separate process suite."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock
ROOT=Path(__file__).resolve().parents[2]
def load(name):
 spec=importlib.util.spec_from_file_location(name.replace('-','_'),ROOT/'scripts'/name)
 value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value
class OwnedProcessContract(unittest.TestCase):
 def make_budget(self):
  b=load('object-storage-owned-budget.py')
  now=time.monotonic_ns()
  budget=b.SharedBudget.create(request_sha256='a'*64,effect_deadline_ns=now+5_000_000_000,
   hard_deadline_ns=now+6_000_000_000,max_process_output_bytes=2048,max_processes=4)
  self.addCleanup(budget.close);return budget
 def test_fixed_process_bounds_both_streams_without_unbounded_file(self):
  owned=load('object-storage-owned-execution.py');budget=self.make_budget()
  with self.assertRaisesRegex(ValueError,'output'):
   owned.run_fixed_process([sys.executable,'-c',"import os;os.write(1,b'x'*8192);os.write(2,b'y'*8192)"],
    env={'PATH':os.defpath},shared=budget,stdout_cap=1024,stderr_cap=512)
 def test_fixed_process_consumes_shared_spawn_and_output(self):
  owned=load('object-storage-owned-execution.py');budget=self.make_budget()
  result=owned.run_fixed_process([sys.executable,'-c',"import sys;sys.stdout.write('{}');sys.stderr.write('diagnostic')"],
   env={'PATH':os.defpath},shared=budget,stdout_cap=1024,stderr_cap=512)
  self.assertEqual(result.stdout,b'{}');self.assertEqual(result.stderr,b'')
  self.assertEqual(budget.snapshot()['processes_started'],1)
  self.assertEqual(budget.snapshot()['process_output_bytes'],12)
if __name__ == '__main__':
    import owned_contract_receipt as receipt_support
    arguments=receipt_support.arguments()
    raise SystemExit(receipt_support.run(unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__]),
        receipt=arguments.receipt,kind='bounded-fixed-process'))
