"""Bounded, source-bound receipts for explicitly invoked process contracts."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import unittest
ROOT=Path(__file__).resolve().parents[2]
SOURCES=(
 'requirements-object-storage-provider.lock','.github/workflows/object-storage-provider-contract.yml',
 'scripts/aliyun-object-storage-provider.py','scripts/resolve-audit-release.py','scripts/resolve-source-release.py',
 'scripts/object-storage-owned-budget.py',
 'scripts/object-storage-owned-execution.py','scripts/execute-object-storage-delivery.py',
 'scripts/verify-object-storage-delivery-inputs.py','scripts/verify-stable-seal-inputs.py',
 'scripts/verify-source-attestations.py','scripts/verify-source-package-metadata.py',
 'tests/test_owned_execution.py','tests/test_owned_execution_budget.py',
 'tests/test_object_storage_delivery_inputs.py','tests/provider_sdk/test_aliyun_object_storage_provider.py',
 'tests/provider_sdk/owned_budget_process_integration.py',
 'tests/provider_sdk/owned_runtime_process_integration.py',
 'tests/provider_sdk/owned_execution_integration.py','tests/provider_sdk/owned_contract_receipt.py')
def hashes():return {p:hashlib.sha256((ROOT/p).read_bytes()).hexdigest() for p in SOURCES}
def arguments():
 parser=argparse.ArgumentParser();parser.add_argument('--receipt',type=Path);parser.add_argument('-v',action='store_true')
 return parser.parse_args()
def run(suite,*,receipt,kind,observations=(),supported=True):
 before=hashes()
 result=unittest.TextTestRunner(verbosity=2).run(suite) if supported else None
 after=hashes()
 passed=bool(result and result.testsRun>0 and result.wasSuccessful() and not result.skipped and before==after)
 value={'schema':'wukongim.owned_process_contract/v1','kind':kind,'passed':passed,'supported':supported,
  'tests':result.testsRun if result else 0,'skips':len(result.skipped) if result else 0,
  'errors':len(result.errors) if result else 0,'failures':len(result.failures) if result else 0,
  'source_files_sha256':before,'source_changed':before!=after,'python':sys.version.split()[0],
  'platform':sys.platform,'observed_workflow_sha':os.environ.get('GITHUB_SHA'),'network_access_permitted':False,'observations':observations,
  'production_enabled':False,'publication_verified':False,'cloud_verified':False,'github_provenance_verified':False}
 raw=json.dumps(value,sort_keys=True,separators=(',',':')).encode()+b'\n'
 if len(raw)>1024*1024:raise ValueError('process contract receipt exceeds bound')
 if receipt is not None:
  receipt.parent.mkdir(parents=True,exist_ok=True);receipt.write_bytes(raw)
 else:sys.stdout.buffer.write(raw)
 return 0 if passed else 2 if not supported else 1
