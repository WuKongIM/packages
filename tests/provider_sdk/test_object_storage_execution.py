"""Staging execution over existing GitHub and official SDK HTTP fixtures only."""
import hashlib
import importlib.util
import json
from pathlib import Path
import socket
import sys
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'tests'))
NETWORK_ATTEMPTS = []


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    sys.modules[name] = value
    spec.loader.exec_module(value)
    return value


class StagingExecutionContract(unittest.TestCase):
    def setUp(self):
        fixtures = module('execution_fresh_fixtures', ROOT / 'tests/test_object_storage_delivery_inputs.py')
        self.github = fixtures.FreshPreviewWire()
        self.github.setUp()
        self.addCleanup(self.github.doCleanups)
        self.execution = module('staging_execution', ROOT / 'scripts/execute-object-storage-delivery.py')
        self.sdk = module('execution_sdk_fixtures', ROOT / 'tests/provider_sdk/test_aliyun_object_storage_provider.py')
        provider = module('execution_sdk_provider', ROOT / 'scripts/aliyun-object-storage-provider.py')
        self.wire = self.sdk.Wire()
        self.provider = provider.Provider(resource=self.sdk.RESOURCE, access_key_id='FIXTURE-AK',
            access_key_secret=self.sdk.SECRET, security_token=self.sdk.TOKEN, http_adapter=self.wire)
        self.addCleanup(self.provider.close)
        self.connect_attempts = []

        def blocked(*args, **kwargs):
            self.connect_attempts.append(True)
            NETWORK_ATTEMPTS.append(True)
            raise AssertionError('execution network forbidden')

        patcher = mock.patch.object(socket.socket, 'connect', side_effect=blocked)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(lambda: self.assertEqual(self.connect_attempts, []))
        self.request = {'schema': 'wukongim.object_storage_execution_request/v1', 'operation': 'stage_immutable',
            'executor_sha': fixtures.HEAD, 'inputs': str(self.github.inputs),
            'inputs_sha256': hashlib.sha256(self.github.inputs.read_bytes()).hexdigest(),
            'plan_sha256': self.github.plan_sha, 'resource': self.sdk.RESOURCE,
            'output_dir': str(self.github.root / 'execution'),
            'limits': {'timeout_seconds': 60, 'max_requests': 10000, 'max_objects': 2048,
                'max_routes': 1000, 'max_put_bytes': 2 * 1024**3, 'max_get_bytes': 8 * 1024**3,
                'max_evidence_bytes': 8 * 1024**2}}

    def test_verified_materialized_inventory_uses_real_sdk_put_and_complete_get(self):
        result = self.execution._stage_immutable(self.request, provider=self.provider)
        self.assertEqual(result['status'], 'staged_readback_verified')
        self.assertGreater(len(result['objects']), 1)
        self.assertEqual(set(self.wire.objects), {x['object_key'] for x in result['objects']})
        self.assertEqual(len([x for x in self.wire.requests if x[0].method == 'PUT']), len(result['objects']))
        for item in result['objects']:
            body, cache = self.wire.objects[item['object_key']]
            self.assertEqual(hashlib.sha256(body).hexdigest(), item['facts']['sha256'])
            self.assertEqual(cache, item['facts']['cache_control'])
            self.assertTrue(item['readback_verified'])
        self.assertIn('verify-source-attestations.py', self.github.events)
        self.assertIn('verify-source-package-metadata.py', self.github.events)
        self.assertFalse(any(x[2] in ('BatchSetCdnDomainConfig', 'RefreshObjectCaches') for x in self.wire.requests))
        for key in ('production_enabled', 'publication_verified', 'cloud_verified', 'github_provenance_verified'):
            self.assertIs(result[key], False)
        evidence = Path(self.request['output_dir']) / 'execution.json'
        self.assertEqual(json.loads(evidence.read_text()), result)
        self.assertNotIn(self.sdk.SECRET, evidence.read_text())
        self.assertNotIn(self.sdk.TOKEN, evidence.read_text())


    def test_source_asset_identity_drift_stops_the_next_put(self):
        send = self.wire.send
        changed = []

        def after_first_put(request, **kwargs):
            response = send(request, **kwargs)
            if request.method == 'PUT' and not changed:
                changed.append(True)
                self.github.source_assets[0]['id'] += 50
            return response

        self.wire.send = after_first_put
        result = self.execution._stage_immutable(self.request, provider=self.provider)
        self.assertEqual(result['status'], 'incomplete')
        self.assertEqual(len([x for x in self.wire.requests if x[0].method == 'PUT']), 1)
        self.assertFalse(any(x[2] in ('BatchSetCdnDomainConfig', 'RefreshObjectCaches') for x in self.wire.requests))


    def test_metadata_fence_153_times_does_not_redownload_seven_assets(self):
        initial = self.github.verify()
        for _ in range(153):
            self.github.p.revalidate_delivery_anchors(inputs=self.github.inputs,
                expected_plan_sha256=self.github.plan_sha, previous=initial)
        self.github.verify(previous=initial)
        downloads = [x for x in self.github.events if '/WuKongIM/releases/assets/' in x]
        self.assertEqual(len(downloads), 14)
        self.assertEqual(self.github.events.count('verify-source-attestations.py'), 2)
        self.assertEqual(self.github.events.count('verify-source-package-metadata.py'), 2)

    def test_sdk_budget_expires_inside_resource_observation_before_put(self):
        now = [0.0]
        budget = self.execution.RunBudget(self.request['limits'], clock=lambda: now[0])
        send = self.wire.send

        def expire_after_identity(request, **kwargs):
            response = send(request, **kwargs)
            if self.wire.requests[-1][2] == 'GetCallerIdentity':
                now[0] = 61.0
            return response

        self.wire.send = expire_after_identity
        result = self.execution._stage_immutable(self.request, provider=self.provider, budget=budget)
        self.assertEqual(result['status'], 'incomplete')
        self.assertEqual([x[2] for x in self.wire.requests], ['GetCallerIdentity'])
        self.assertFalse(any(x[0].method == 'PUT' for x in self.wire.requests))
        self.assertTrue(result['budget']['expired'])

    def test_all_github_requests_consume_the_same_request_budget_before_sdk(self):
        self.request['limits']['max_requests'] = 2
        with self.assertRaises(ValueError):
            self.execution._stage_immutable(self.request, provider=self.provider)
        self.assertEqual(self.wire.requests, [])
        self.assertLessEqual(len(self.github.events), 2)


    def test_unknown_put_is_not_retried_and_keeps_durable_unknown_request(self):
        self.wire.put_fault = 'timeout_after'
        result = self.execution._stage_immutable(self.request, provider=self.provider)
        self.assertEqual(result['status'], 'staged_readback_verified')
        self.assertEqual(len([x for x in self.wire.requests if x[0].method == 'PUT']), len(result['objects']))
        self.assertTrue(all(x['put_outcome'] == 'unknown_readback_verified' for x in result['objects']))
        path = Path(result['journal_path'])
        raw = path.read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), result['journal_sha256'])
        events = [json.loads(x) for x in raw.splitlines()]
        self.assertEqual(events[0]['request_sha256'], result['request_sha256'])
        self.assertTrue(any(x.get('event') == 'request_result' and x.get('outcome') == 'unknown' for x in events))
        self.assertNotIn(self.sdk.SECRET.encode(), raw)
        self.assertNotIn(self.sdk.TOKEN.encode(), raw)

    def test_read_only_reconcile_observes_unknown_put_without_changing_its_outcome(self):
        self.wire.put_fault, self.wire.get_fault = 'timeout_after', 'digest'
        prior = self.execution._stage_immutable(self.request, provider=self.provider)
        self.assertEqual(prior['status'], 'incomplete')
        self.assertEqual(len([x for x in self.wire.requests if x[0].method == 'PUT']), 1)
        before = len(self.wire.requests)
        self.wire.get_fault = None
        observed = self.execution._reconcile_staging(self.request, provider=self.provider,
            journal_path=Path(prior['journal_path']), journal_sha256=prior['journal_sha256'],
            output_dir=self.github.root / 'reconciled')
        self.assertEqual(observed['status'], 'reconciled_read_only')
        self.assertEqual(observed['objects'][0]['observed_now'], 'exact')
        self.assertGreater(observed['original_unknown_outcomes'], 0)
        self.assertFalse(observed['publication_verified'])
        allowed = {'GetCallerIdentity', 'DescribeCdnDomainDetail', 'DescribeCdnDomainConfigs'}
        self.assertTrue(all(x[0].method == 'GET' or x[2] in allowed for x in self.wire.requests[before:]))
        self.assertFalse(any(x[0].method == 'PUT' for x in self.wire.requests[before:]))
        for fault in ('request', 'journal'):
            request = json.loads(json.dumps(self.request))
            expected = prior['journal_sha256']
            if fault == 'request':
                request['limits']['max_requests'] -= 1
            else:
                expected = '0' * 64
            count = len(self.wire.requests)
            with self.assertRaises(ValueError):
                self.execution._reconcile_staging(request, provider=self.provider,
                    journal_path=Path(prior['journal_path']), journal_sha256=expected,
                    output_dir=self.github.root / ('reject-' + fault))
            self.assertEqual(len(self.wire.requests), count)


    def test_main_input_and_audit_metadata_drift_stop_each_next_put(self):
        import copy
        original_inputs = self.github.inputs.read_bytes()
        original_main = self.github.main
        original_offset = self.github.asset_id_offset
        original_assets = copy.deepcopy(self.github.source_assets)
        for fault in ('main', 'inputs', 'audit_id', 'source_digest'):
            with self.subTest(fault=fault):
                self.github.inputs.write_bytes(original_inputs)
                self.github.main, self.github.asset_id_offset = original_main, original_offset
                self.github.source_assets = copy.deepcopy(original_assets)
                self.request['output_dir'] = str(self.github.root / ('execution-' + fault))
                before = len([x for x in self.wire.requests if x[0].method == 'PUT'])
                changed = []
                send = self.sdk.Wire.send.__get__(self.wire, self.sdk.Wire)

                def mutate(request, **kwargs):
                    response = send(request, **kwargs)
                    if request.method == 'PUT' and not changed:
                        changed.append(True)
                        if fault == 'main': self.github.main = 'e' * 40
                        elif fault == 'inputs': self.github.inputs.write_bytes(original_inputs + b'\n')
                        elif fault == 'audit_id': self.github.asset_id_offset += 100
                        else: self.github.source_assets[0]['digest'] = 'sha256:' + 'e' * 64
                    return response

                self.wire.send = mutate
                result = self.execution._stage_immutable(self.request, provider=self.provider)
                self.assertEqual(result['status'], 'incomplete')
                self.assertEqual(len([x for x in self.wire.requests if x[0].method == 'PUT']) - before, 1)

    def test_known_capacity_refuses_before_any_provider_request(self):
        self.request['limits']['max_objects'] = 1
        result = self.execution._stage_immutable(self.request, provider=self.provider)
        self.assertEqual(result['status'], 'incomplete')
        self.assertEqual(self.wire.requests, [])

    def test_read_only_budget_refuses_mutation_at_sdk_transport(self):
        budget = self.execution.RunBudget(self.request['limits'], read_only=True)
        self.provider.bind_execution_controls(budget=budget)
        path = self.github.root / 'must-not-upload'
        path.write_bytes(self.sdk.DATA)
        with self.assertRaises(ValueError):
            self.provider.put_create_only(self.sdk.KEY, path, self.sdk.FACTS)
        self.assertFalse(any(x[0].method == 'PUT' for x in self.wire.requests))


    def test_read_only_reconcile_can_observe_prior_effects_after_anchor_drift(self):
        import copy
        self.wire.put_fault, self.wire.get_fault = 'timeout_after', 'digest'
        prior = self.execution._stage_immutable(self.request, provider=self.provider)
        self.wire.get_fault = None
        inputs = self.github.inputs.read_bytes()
        main = self.github.main
        assets = copy.deepcopy(self.github.source_assets)
        for fault in ('main', 'inputs', 'source'):
            with self.subTest(fault=fault):
                self.github.inputs.write_bytes(inputs)
                self.github.main, self.github.source_assets = main, copy.deepcopy(assets)
                if fault == 'main': self.github.main = 'e' * 40
                elif fault == 'inputs': self.github.inputs.write_bytes(inputs + b'\n')
                else: self.github.source_assets[0]['id'] += 100
                before = len(self.wire.requests)
                result = self.execution._reconcile_staging(self.request, provider=self.provider,
                    journal_path=Path(prior['journal_path']), journal_sha256=prior['journal_sha256'],
                    output_dir=self.github.root / ('reconcile-drift-' + fault))
                self.assertEqual(result['status'], 'incomplete')
                self.assertEqual(result['fresh_anchor_status'], 'unverified')
                self.assertEqual(result['objects'][0]['observed_now'], 'exact')
                self.assertIn('configuration_observed_now', result)
                self.assertGreater(result['original_unknown_outcomes'], 0)
                self.assertFalse(any(x[0].method == 'PUT' for x in self.wire.requests[before:]))


class RunnerReceiptContract(unittest.TestCase):
    def _refused_suite(self, mode):
        import subprocess
        import tempfile
        with tempfile.TemporaryDirectory() as temporary:
            receipt = Path(temporary) / 'receipt.json'
            harness = r"""
import runpy, socket, sys, unittest
from unittest import mock
script, receipt, mode = sys.argv[1:]
class Skipped(unittest.TestCase):
    @unittest.skip('intentional runner-failure fixture')
    def test_placeholder(self): pass
suite = unittest.TestSuite() if mode == 'zero' else unittest.defaultTestLoader.loadTestsFromTestCase(Skipped)
sys.argv = [script, '--receipt', receipt]
with mock.patch.object(unittest.defaultTestLoader, 'loadTestsFromModule', return_value=suite), mock.patch.object(socket.socket, 'connect', side_effect=AssertionError('runner network forbidden')):
    runpy.run_path(script, run_name='__main__')
"""
            result = subprocess.run([sys.executable, '-B', '-c', harness, str(Path(__file__).resolve()),
                str(receipt), mode], capture_output=True, text=True, timeout=30, cwd=ROOT)
            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
            value = json.loads(receipt.read_text())
            self.assertFalse(value['passed'])
            self.assertFalse(value['provider_network_allowed'])
            self.assertFalse(value['publication_verified'])
            self.assertEqual(value['unexpected_connect_attempts'], 0)
            return value

    def test_zero_tests_fails_the_real_runner_and_retains_receipt(self):
        value = self._refused_suite('zero')
        self.assertEqual(value['tests'], 0)
        self.assertEqual(value['test_names'], [])

    def test_skipped_test_fails_the_real_runner_and_retains_receipt(self):
        value = self._refused_suite('skip')
        self.assertEqual(value['tests'], 1)
        self.assertEqual(value['skips'], 1)


if __name__ == '__main__':
    import argparse
    import importlib.metadata
    import platform
    import subprocess

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--receipt', type=Path)
    parser.add_argument('-v', action='store_true')
    parser.add_argument('tests', nargs='*')
    arguments = parser.parse_args()
    loader = unittest.defaultTestLoader
    suite = (loader.loadTestsFromNames(arguments.tests, sys.modules[__name__]) if arguments.tests
             else loader.loadTestsFromModule(sys.modules[__name__]))

    def names(value):
        for item in value:
            if isinstance(item, unittest.TestSuite):
                yield from names(item)
            else:
                yield item.id()

    test_names = list(names(suite))
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    passed = result.testsRun>0 and result.wasSuccessful() and not result.skipped and not NETWORK_ATTEMPTS
    source_files = ('scripts/execute-object-storage-delivery.py', 'scripts/aliyun-object-storage-provider.py',
        'scripts/verify-object-storage-delivery-inputs.py', 'scripts/resolve-source-release.py',
        'scripts/resolve-audit-release.py', 'scripts/verify-stable-seal-inputs.py',
        'tests/provider_sdk/test_object_storage_execution.py', 'requirements-object-storage-provider.lock')
    receipt = {'schema': 'wukongim.object_storage_execution_sdk_contract/v1', 'test_only': True,
        'passed': bool(passed), 'tests': result.testsRun, 'test_names': test_names,
        'failures': len(result.failures), 'errors': len(result.errors), 'skips': len(result.skipped),
        'unexpected_connect_attempts': len(NETWORK_ATTEMPTS), 'provider_network_allowed': False,
        'production_enabled': False, 'publication_verified': False, 'cloud_verified': False,
        'wire_equivalence_verified': False,
        'github_provenance_verified': False, 'python': platform.python_version(),
        'checkout_sha': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True, timeout=10).strip(),
        'checkout_modified': bool(subprocess.check_output(['git', 'status', '--porcelain', '--untracked-files=all'],
            cwd=ROOT, text=True, timeout=10).strip()),
        'source_files_sha256': {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in source_files},
        'sdk_versions': {name: importlib.metadata.version(name) for name in
            ('alibabacloud-oss-v2', 'aliyun-python-sdk-core', 'aliyun-python-sdk-cdn', 'aliyun-python-sdk-sts')}}
    raw = json.dumps(receipt, sort_keys=True).encode() + b'\n'
    if len(raw) > 65536:
        raise ValueError('execution SDK contract receipt exceeds 64 KiB')
    if arguments.receipt is not None:
        arguments.receipt.write_bytes(raw)
    print(raw.decode(), end='')
    sys.exit(0 if passed else 1)
