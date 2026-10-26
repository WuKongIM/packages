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
ROOT=Path(__file__).resolve().parents[1]
def load(name):
 spec=importlib.util.spec_from_file_location(name.replace('-','_'),ROOT/'scripts'/name)
 value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value
class OwnedExecutionContract(unittest.TestCase):
 def test_unsupported_platform_refuses_before_sdk_or_credential_use(self):
  owned=load('object-storage-owned-execution.py')
  with mock.patch.object(owned.sys,'platform','darwin'):
   with self.assertRaisesRegex(ValueError,'Linux'):
    owned.supervise_staging({},temporary_credentials=None)
 def test_v2_direct_path_requires_owned_context(self):
  execution=load('execute-object-storage-delivery.py')
  request={'schema':'wukongim.object_storage_execution_request/v2','operation':'stage_immutable',
   'executor_sha':'a'*40,'inputs':'/tmp/owned-input','inputs_sha256':'b'*64,'plan_sha256':'c'*64,
   'resource':{},'output_dir':'/tmp/owned-output','limits':{},
   'process_limits':{'max_process_output_bytes':4096,'max_processes':3}}
  with self.assertRaisesRegex(ValueError,'owned'):
   execution._stage_immutable(request,provider=mock.Mock())
if __name__=='__main__':unittest.main()
