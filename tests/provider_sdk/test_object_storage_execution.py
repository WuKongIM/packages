"""Staging execution over existing GitHub and official SDK HTTP fixtures only."""
import hashlib
import importlib.util
import io
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

    def _cdn_effect_fixture(self, *, refresh=False, routes=None):
        """New evidence version is private data, never production authority."""
        import copy
        self.provider.bind_execution_controls(budget=None)
        before = self.provider.read_configuration()
        routes = routes or [self.sdk.route()]
        urls = ['https://packages.githubim.com'+x['public_uri'] for x in routes]
        request = copy.deepcopy(self.request)
        request['operation'] = 'cdn_effects'
        request['cdn_intent'] = {'routes': routes, 'configuration_before': before,
            'functions': module('effect_compiler', ROOT / 'scripts/aliyun-object-storage-provider.py').compile_rewrites(routes),
            'refresh_urls': urls}
        budget = self.execution.RunBudget(request['limits'])
        prepared_raw = self.execution.canonical({'objects': [], 'routes': routes})
        prior = self.github.root / ('refresh-prior' if refresh else 'config-prior')
        (prior / 'prepared').mkdir(parents=True, exist_ok=True)
        (prior / 'prepared/delivery.json').write_bytes(prepared_raw)
        request['output_dir'] = str(prior)
        journal = self.execution.EffectJournal(self.github.root / ('refresh-effects.jsonl' if refresh else 'config-effects.jsonl'),
            request, hashlib.sha256(prepared_raw).hexdigest(), {'fixture_anchor': 'fixed'}, budget)
        self.addCleanup(journal.close)
        budget.journal = journal
        self.provider.bind_execution_controls(budget=budget)
        return request, before, routes, urls, budget, journal, prepared_raw

    def test_cdn_effect_journal_configuration_uses_signed_sdk_and_consumed_ack(self):
        request, before, routes, urls, budget, journal, prepared = self._cdn_effect_fixture()
        result = self.provider.apply_rewrites(routes, before=before, managed_ids=[])
        writes = [x for x in self.wire.requests if x[2] == 'BatchSetCdnDomainConfig']
        print(json.dumps({'cdn_effect_fixture': 'configuration', 'mutating_wire_calls': len(writes),
            'socket_attempts': len(self.connect_attempts), 'state': result['state']}))
        self.assertEqual(result['state'], 'readback_verified')
        self.assertEqual(len(writes), 1)
        journal.close()
        events = [json.loads(line) for line in journal.path.read_bytes().splitlines()]
        self.assertEqual(events[0]['event'], 'run_start_v2')
        self.assertEqual(len([x for x in events if x['event'] == 'cdn_ack']), 1)
        self.assertNotIn(self.sdk.TOKEN, journal.path.read_text())
        self.assertNotIn(self.sdk.SECRET, journal.path.read_text())

    def test_cdn_effect_journal_refresh_uses_signed_sdk_and_consumed_ack(self):
        request, before, routes, urls, budget, journal, prepared = self._cdn_effect_fixture(refresh=True)
        try:
            result = self.provider.refresh(urls, poll_interval=0)
        except Exception:
            result = {'state': 'incomplete'}
        writes = [x for x in self.wire.requests if x[2] == 'RefreshObjectCaches']
        print(json.dumps({'cdn_effect_fixture': 'refresh', 'mutating_wire_calls': len(writes),
            'socket_attempts': len(self.connect_attempts), 'state': result['state']}))
        self.assertEqual(result['state'], 'tasks_complete')
        self.assertEqual(len(writes), 1)
        journal.close()
        events = [json.loads(line) for line in journal.path.read_bytes().splitlines()]
        self.assertEqual(events[0]['event'], 'run_start_v2')
        self.assertEqual(len([x for x in events if x['event'] == 'cdn_ack']), 1)
        self.assertNotIn(self.sdk.TOKEN, journal.path.read_text())
        self.assertNotIn(self.sdk.SECRET, journal.path.read_text())

    def _effect_summary(self, request, journal, prepared, *, raw=None):
        journal.close()
        return self.execution._bound_effect_journal(request,
            journal.path.read_bytes() if raw is None else raw, prepared)

    def test_cdn_effect_journal_default_staging_still_refuses_post(self):
        request, before, routes, urls, budget, journal, prepared = self._cdn_effect_fixture()
        budget.journal = self.execution.EffectJournal(self.github.root / 'staging-default.jsonl',
            self.request, hashlib.sha256(prepared).hexdigest(), {}, budget)
        self.addCleanup(budget.journal.close)
        self.assertEqual(self.provider.apply_rewrites(routes, before=before, managed_ids=[])['state'], 'incomplete')
        self.assertFalse(any(x[2] == 'BatchSetCdnDomainConfig' for x in self.wire.requests))

    def test_cdn_effect_journal_unknown_attempt_fsynced_before_signed_wire(self):
        request, before, routes, urls, budget, journal, prepared = self._cdn_effect_fixture()
        send = self.wire.send
        def observe(actual, **kwargs):
            from urllib.parse import parse_qs, urlsplit
            fields = parse_qs(urlsplit(actual.url).query)
            fields.update(parse_qs(actual.body.decode() if isinstance(actual.body, bytes) else actual.body or ''))
            if fields.get('Action') == ['BatchSetCdnDomainConfig']:
                events = [json.loads(x) for x in journal.path.read_bytes().splitlines()]
                attempt = events[-1]
                self.assertEqual(attempt['event'], 'request_attempt')
                self.assertEqual(attempt['outcome'], 'unknown')
                raw = actual.method.encode()+b'\n'+actual.url.encode()+b'\n'+(actual.body if isinstance(actual.body, bytes) else (actual.body or '').encode())
                self.assertEqual(attempt['serialized_request_sha256'], hashlib.sha256(raw).hexdigest())
            return send(actual, **kwargs)
        self.wire.send = observe
        self.assertEqual(self.provider.apply_rewrites(routes, before=before, managed_ids=[])['state'], 'readback_verified')
        summary = self._effect_summary(request, journal, prepared)
        self.assertEqual(summary['unknown_by_kind'], {'put': 0, 'configuration': 0, 'refresh': 0})

    def test_cdn_effect_journal_signed_payload_conflicts_stop_before_wire(self):
        from urllib.parse import parse_qs, urlencode, urlsplit
        for fault in ('domain', 'functions', 'duplicate', 'action', 'delete'):
            with self.subTest(fault=fault):
                request, before, routes, urls, budget, journal, prepared = self._cdn_effect_fixture()
                original = budget.before_sdk
                def change(actual):
                    fields = parse_qs(urlsplit(actual.url).query)
                    body = actual.body.decode() if isinstance(actual.body, bytes) else actual.body or ''
                    values = parse_qs(body)
                    action = values.get('Action', fields.get('Action', ['']))[0]
                    if action == 'BatchSetCdnDomainConfig':
                        merged = {**fields, **values}
                        if fault == 'domain': merged['DomainNames'] = ['foreign.example']
                        elif fault == 'functions': merged['Functions'] = ['[]']
                        elif fault == 'duplicate': merged['DomainNames'] *= 2
                        elif fault == 'action': merged['Action'] = ['RefreshObjectCaches']
                        else: merged['Action'] = ['DeleteSpecificConfig']
                        actual.url = 'https://cdn.aliyuncs.com/'
                        actual.body = urlencode(merged, doseq=True)
                    return original(actual)
                budget.before_sdk = change
                count = len([x for x in self.wire.requests if x[2] == 'BatchSetCdnDomainConfig'])
                self.assertEqual(self.provider.apply_rewrites(routes, before=before, managed_ids=[])['state'], 'incomplete')
                self.assertEqual(len([x for x in self.wire.requests if x[2] == 'BatchSetCdnDomainConfig']), count)
                journal.close();journal.path.unlink()

    def test_cdn_effect_journal_headers_body_faults_remain_unknown(self):
        for fault in ('interrupted', 'malformed', 'nonobject', 'duplicate_json', '503', 'extra_secret'):
            with self.subTest(fault=fault):
                request, before, routes, urls, budget, journal, prepared = self._cdn_effect_fixture()
                send = self.wire.send
                def change(actual, **kwargs):
                    response = send(actual, **kwargs)
                    if self.wire.requests[-1][2] == 'BatchSetCdnDomainConfig':
                        if fault == 'interrupted':
                            class Broken(io.BytesIO):
                                def read(self, *args, **kwargs): raise OSError(self.sdk.SECRET)
                            response.raw = Broken(b'ignored')
                        elif fault == '503': response.status_code = 503
                        else:
                            raw = b'{' if fault == 'malformed' else b'[]' if fault == 'nonobject' else b'{"DomainConfigList":{},"DomainConfigList":{}}' if fault == 'duplicate_json' else json.dumps({'DomainConfigList': {'DomainConfigModel': []}, 'Secret': self.sdk.TOKEN}).encode()
                            response.raw = io.BytesIO(raw)
                    return response
                self.wire.send = change
                self.assertEqual(self.provider.apply_rewrites(routes, before=before, managed_ids=[])['state'], 'incomplete')
                summary = self._effect_summary(request, journal, prepared)
                self.assertEqual(summary['unknown_by_kind']['configuration'], 1)
                events = [json.loads(x) for x in journal.path.read_bytes().splitlines()]
                self.assertFalse(any(x['event'] == 'cdn_ack' for x in events))
                self.assertNotIn(self.sdk.TOKEN, journal.path.read_text())
                self.assertNotIn(self.sdk.SECRET, journal.path.read_text())
                self.wire.send = send;journal.path.unlink()
                self.wire.configs = [x for x in self.wire.configs if x['FunctionName'] != 'back_to_origin_url_rewrite']

    def test_cdn_effect_journal_invalid_config_ids_do_not_resolve_original(self):
        for fault in ('zero', 'missing', 'duplicate', 'partial', 'wrongid', 'timeout'):
            with self.subTest(fault=fault):
                request, before, routes, urls, budget, journal, prepared = self._cdn_effect_fixture()
                if fault == 'partial':
                    journal.close();journal.path.unlink()
                    request, before, routes, urls, budget, journal, prepared = self._cdn_effect_fixture(routes=[self.sdk.route('/one'), self.sdk.route('/two')])
                self.wire.batch_fault = fault
                self.assertEqual(self.provider.apply_rewrites(routes, before=before, managed_ids=[])['state'], 'incomplete')
                summary = self._effect_summary(request, journal, prepared)
                self.assertEqual(summary['unknown_by_kind']['configuration'], 1)
                journal.path.unlink();self.wire.batch_fault = None
                self.wire.configs = [x for x in self.wire.configs if x['FunctionName'] != 'back_to_origin_url_rewrite']

    def test_cdn_effect_journal_fsync_failures_before_and_after_effect(self):
        for event in ('request_attempt', 'cdn_ack'):
            with self.subTest(event=event):
                request, before, routes, urls, budget, journal, prepared = self._cdn_effect_fixture()
                record = journal.record
                def broken(value):
                    if value['event'] == event and (event != 'request_attempt' or value.get('action') == 'BatchSetCdnDomainConfig'):
                        with mock.patch.object(self.execution.os, 'fsync', side_effect=OSError('fixture fsync')):
                            return record(value)
                    return record(value)
                journal.record = broken
                before_writes = len([x for x in self.wire.requests if x[2] == 'BatchSetCdnDomainConfig'])
                self.assertEqual(self.provider.apply_rewrites(routes, before=before, managed_ids=[])['state'], 'incomplete')
                count = len([x for x in self.wire.requests if x[2] == 'BatchSetCdnDomainConfig'])-before_writes
                self.assertEqual(count, 0 if event == 'request_attempt' else 1)
                summary = self._effect_summary(request, journal, prepared)
                self.assertEqual(summary['unknown_by_kind']['configuration'], 0 if event == 'request_attempt' else 1)
                journal.path.unlink();self.wire.configs = [x for x in self.wire.configs if x['FunctionName'] != 'back_to_origin_url_rewrite']

    def test_cdn_effect_journal_parser_rejects_ambiguous_events_and_old_parser(self):
        request, before, routes, urls, budget, journal, prepared = self._cdn_effect_fixture()
        self.assertEqual(self.provider.apply_rewrites(routes, before=before, managed_ids=[])['state'], 'readback_verified')
        journal.close();raw = journal.path.read_bytes();events = [json.loads(x) for x in raw.splitlines()]
        with self.assertRaises(self.execution.ExecutionError):self.execution._bound_staging_journal(request, raw, prepared)
        for fault in ('unknown_event', 'duplicate_attempt', 'duplicate_ack', 'wrong_payload', 'wrong_header', 'wrong_intent', 'boolean_ticket'):
            import copy
            damaged = copy.deepcopy(events)
            if fault == 'unknown_event':damaged.append({'event': 'not_registered'})
            elif fault == 'duplicate_attempt':damaged.append(next(x for x in damaged if x['event'] == 'request_attempt'))
            elif fault == 'duplicate_ack':damaged.append(next(x for x in damaged if x['event'] == 'cdn_ack'))
            elif fault == 'wrong_payload':next(x for x in damaged if x['event'] == 'cdn_step')['payload_sha256'] = '0'*64
            elif fault == 'wrong_header':damaged[0]['plan_sha256'] = '0'*64
            elif fault == 'boolean_ticket':next(x for x in damaged if x['event'] == 'request_result')['request_id'] = True
            else:damaged[0]['intent_sha256'] = '0'*64
            with self.subTest(fault=fault), self.assertRaises((self.execution.ExecutionError, ValueError, KeyError)):
                self.execution._bound_effect_journal(request, b''.join(self.execution.canonical(x) for x in damaged), prepared)
        summary = self.execution._bound_effect_journal(request, raw+b'{"event":', prepared)
        self.assertTrue(summary['partial_tail'])
        self.assertEqual(summary['unknown_by_kind']['configuration'], 0)

    def test_cdn_effect_journal_refresh_shared_ids_and_unknown_later_batch(self):
        routes = [self.sdk.route('/r'+str(i), 'public/r'+str(i)) for i in range(51)]
        for fault in (None, 'submit_timeout', 'submit_ids'):
            with self.subTest(fault=fault):
                wire = self.sdk.RefreshWire(mode='aggregate', fault=fault)
                self.provider.session.mount('https://', wire)
                request, before, routes, urls, budget, journal, prepared = self._cdn_effect_fixture(refresh=True, routes=routes)
                try:result = self.provider.refresh(urls, poll_interval=0)
                except Exception:result = {'state': 'incomplete'}
                summary = self._effect_summary(request, journal, prepared)
                self.assertEqual(result['state'], 'tasks_complete' if fault is None else 'incomplete')
                self.assertEqual(wire.submissions, 2 if fault != 'submit_ids' else 1)
                self.assertEqual(summary['unknown_by_kind']['refresh'], 0 if fault is None else 1)
                if fault == 'submit_timeout':self.assertEqual(len(summary['acknowledged_task_ids']), 1)
                if fault is None:self.assertEqual(len(summary['acknowledged_task_ids']), 1)
                self.assertNotIn(self.sdk.TOKEN, journal.path.read_text());journal.path.unlink()

    def test_cdn_effect_journal_original_unknown_not_cleared_by_readonly_reconcile(self):
        request, before, routes, urls, budget, journal, prepared = self._cdn_effect_fixture()
        self.wire.batch_fault = 'timeout'
        self.assertEqual(self.provider.apply_rewrites(routes, before=before, managed_ids=[])['state'], 'incomplete')
        journal.close();self.wire.batch_fault = None
        count = len(self.wire.requests)
        result = self.execution._reconcile_cdn_effects(request, provider=self.provider,
            journal_path=journal.path, journal_sha256=hashlib.sha256(journal.path.read_bytes()).hexdigest(),
            output_dir=self.github.root / 'cdn-reconcile')
        self.assertEqual(result['original_unknown_by_kind']['configuration'], 1)
        self.assertIn('configuration_observed_now', result)
        self.assertFalse(any(x[2] in ('BatchSetCdnDomainConfig','RefreshObjectCaches') for x in self.wire.requests[count:]))
        self.assertFalse(result['publication_verified'])

    def test_cdn_effect_journal_missing_refresh_id_never_queries_history(self):
        wire = self.sdk.RefreshWire(mode='aggregate', fault='submit_timeout')
        self.provider.session.mount('https://', wire)
        routes = [self.sdk.route('/r'+str(i), 'public/r'+str(i)) for i in range(51)]
        request, before, routes, urls, budget, journal, prepared = self._cdn_effect_fixture(refresh=True, routes=routes)
        with self.assertRaises(Exception):self.provider.refresh(urls, poll_interval=0)
        journal.close();wire.fault = None;count = len(wire.requests)
        result = self.execution._reconcile_cdn_effects(request, provider=self.provider,
            journal_path=journal.path, journal_sha256=hashlib.sha256(journal.path.read_bytes()).hexdigest(),
            output_dir=self.github.root / 'refresh-reconcile')
        self.assertEqual(result['original_unknown_by_kind']['refresh'], 1)
        self.assertEqual(len(result['unobservable_refresh_submissions']), 1)
        for actual, kwargs, action, fields in wire.requests[count:]:
            self.assertNotIn(action, ('BatchSetCdnDomainConfig','RefreshObjectCaches'))
            if action == 'DescribeRefreshTaskById':self.assertEqual(fields['TaskId'], ['33643947491'])

    def test_cdn_effect_journal_binding_drift_rejected_before_provider_reads(self):
        request, before, routes, urls, budget, journal, prepared = self._cdn_effect_fixture()
        journal.close()
        for field in ('plan_sha256','inputs_sha256','resource'):
            import copy
            changed = copy.deepcopy(request)
            if field == 'resource':changed[field]['bucket'] = 'other-bucket'
            else:changed[field] = '0'*64
            count = len(self.wire.requests)
            with self.subTest(field=field), self.assertRaises(self.execution.ExecutionError):
                self.execution._reconcile_cdn_effects(changed, provider=self.provider,
                    journal_path=journal.path, journal_sha256=hashlib.sha256(journal.path.read_bytes()).hexdigest(),
                    output_dir=self.github.root / ('invalid-'+field))
            self.assertEqual(len(self.wire.requests), count)

    def test_cdn_effect_journal_deadline_read_cap_and_readonly_stop_post(self):
        for fault in ('deadline','read_cap','request_cap','readonly'):
            with self.subTest(fault=fault):
                request, before, routes, urls, budget, journal, prepared = self._cdn_effect_fixture()
                if fault == 'deadline':budget.deadline = budget.clock()-1
                elif fault == 'read_cap':budget.get_bytes = budget.limits['max_get_bytes']
                elif fault == 'request_cap':budget.requests = budget.limits['max_requests']
                else:budget.read_only = True
                try:result = self.provider.apply_rewrites(routes, before=before, managed_ids=[])
                except Exception:result = {'state': 'incomplete'}
                self.assertEqual(result['state'], 'incomplete')
                self.assertFalse(any(x[2] == 'BatchSetCdnDomainConfig' for x in self.wire.requests))
                journal.close();journal.path.unlink()

    def test_cdn_effect_journal_scopes_cannot_overlap_or_reuse(self):
        request, before, routes, urls, budget, journal, prepared = self._cdn_effect_fixture()
        kwargs = dict(kind='configuration', ordinal=0, payload={'Action':'BatchSetCdnDomainConfig',
            'DomainNames':'packages.githubim.com','Functions':json.dumps(request['cdn_intent']['functions'],separators=(',',':'))},
            before_sha256=before['sha256'], target_sha256=self.execution.digest(request['cdn_intent']['functions']))
        step = budget.begin_cdn_step(**kwargs)
        with self.assertRaises(self.execution.ExecutionError):budget.begin_cdn_step(**kwargs)
        budget.end_cdn_step(step)
        with self.assertRaises(self.execution.ExecutionError):budget.begin_cdn_step(**kwargs)
        self.assertFalse(any(x[2] in ('BatchSetCdnDomainConfig','RefreshObjectCaches') for x in self.wire.requests))

    def test_cdn_effect_journal_first_batch_ack_survives_unknown_later_batch(self):
        routes = [self.sdk.route('/r'+str(i)) for i in range(21)]
        request, before, routes, urls, budget, journal, prepared = self._cdn_effect_fixture(routes=routes)
        send = self.wire.send; batches = []
        def fault(actual, **kwargs):
            from urllib.parse import parse_qs, urlsplit
            fields = parse_qs(urlsplit(actual.url).query)
            fields.update(parse_qs(actual.body.decode() if isinstance(actual.body, bytes) else actual.body or ''))
            if fields.get('Action') == ['BatchSetCdnDomainConfig']:
                batches.append(True)
                if len(batches) == 2:self.wire.batch_fault = 'timeout'
            return send(actual, **kwargs)
        self.wire.send = fault
        result = self.provider.apply_rewrites(routes, before=before, managed_ids=[])
        self.assertEqual(result['state'], 'incomplete')
        summary = self._effect_summary(request, journal, prepared)
        self.assertEqual(summary['unknown_by_kind']['configuration'], 1)
        self.assertEqual(len(summary['acknowledged_configuration_requests']), 1)
        self.assertEqual(len(batches), 2)

    def test_cdn_effect_journal_ack_is_distinct_from_unrelated_configuration_drift(self):
        request, before, routes, urls, budget, journal, prepared = self._cdn_effect_fixture()
        send = self.wire.send
        def drift(actual, **kwargs):
            response = send(actual, **kwargs)
            if self.wire.requests[-1][2] == 'BatchSetCdnDomainConfig':self.wire.detail['VisibleDrift'] = 'changed'
            return response
        self.wire.send = drift
        result = self.provider.apply_rewrites(routes, before=before, managed_ids=[])
        self.assertEqual(result['state'], 'incomplete')
        self.assertEqual(result['configuration_observed_now']['detail']['VisibleDrift'], 'changed')
        summary = self._effect_summary(request, journal, prepared)
        self.assertEqual(summary['unknown_by_kind']['configuration'], 0)
        self.assertIn('configuration_observed_now', summary)

    def test_cdn_effect_journal_configuration_argument_order_is_observed_not_semantic_drift(self):
        request, before, routes, urls, budget, journal, prepared = self._cdn_effect_fixture()
        send = self.wire.send
        def reorder(actual, **kwargs):
            response = send(actual, **kwargs)
            if self.wire.requests[-1][2] == 'BatchSetCdnDomainConfig':
                for row in self.wire.configs:
                    if row['FunctionName'] == 'back_to_origin_url_rewrite':row['FunctionArgs']['FunctionArg'].reverse()
            return response
        self.wire.send = reorder
        self.assertEqual(self.provider.apply_rewrites(routes, before=before, managed_ids=[])['state'], 'readback_verified')
        self.assertEqual(self._effect_summary(request, journal, prepared)['unknown_by_kind']['configuration'], 0)

    def test_cdn_effect_journal_C1_credential_echo_never_enters_receipt(self):
        request, before, routes, urls, budget, journal, prepared = self._cdn_effect_fixture()
        send = self.wire.send
        def echo(actual, **kwargs):
            response = send(actual, **kwargs)
            if self.wire.requests[-1][2] == 'BatchSetCdnDomainConfig':self.wire.detail['UnexpectedEcho'] = self.sdk.TOKEN
            return response
        self.wire.send = echo
        result = self.provider.apply_rewrites(routes, before=before, managed_ids=[])
        self.assertEqual(result['state'], 'incomplete')
        self.assertNotIn(self.sdk.TOKEN, json.dumps(result))
        self.assertNotIn(self.sdk.TOKEN, journal.path.read_text())
        self.assertEqual(self._effect_summary(request, journal, prepared)['unknown_by_kind']['configuration'], 1)

    def test_cdn_effect_journal_preparation_and_budget_are_checked_before_file_open(self):
        for fault in ('budget', 'preparation_bytes', 'routes'):
            with self.subTest(fault=fault):
                request, before, routes, urls, budget, journal, prepared = self._cdn_effect_fixture()
                journal.close();journal.path.unlink();created = None
                if fault == 'budget':budget.limits['max_requests'] += 1
                elif fault == 'preparation_bytes':(Path(request['output_dir']) / 'prepared/delivery.json').write_bytes(prepared+b' ')
                else:
                    prepared = self.execution.canonical({'objects': [], 'routes': [self.sdk.route('/foreign')]})
                    (Path(request['output_dir']) / 'prepared/delivery.json').write_bytes(prepared)
                try:
                    with self.assertRaises(self.execution.ExecutionError):
                        created = self.execution.EffectJournal(journal.path, request,
                            hashlib.sha256(prepared).hexdigest(), {}, budget)
                    self.assertFalse(journal.path.exists())
                finally:
                    if created is not None:created.close()
                    journal.path.unlink(missing_ok=True)

    def test_cdn_effect_journal_initial_fsync_failure_reclaims_descriptor(self):
        request, before, routes, urls, budget, journal, prepared = self._cdn_effect_fixture()
        journal.close();journal.path.unlink();opened = [];original = self.execution.os.open
        def observe(path, *args, **kwargs):
            fd = original(path, *args, **kwargs)
            if Path(path) == journal.path:opened.append(fd)
            return fd
        def close_owned():
            for fd in opened:
                try:self.execution.os.close(fd)
                except OSError:pass
        self.addCleanup(close_owned)
        with mock.patch.object(self.execution.os, 'open', side_effect=observe), mock.patch.object(self.execution.os, 'fsync', side_effect=OSError('fixture initial fsync')):
            with self.assertRaises(OSError):self.execution.EffectJournal(journal.path, request,
                hashlib.sha256(prepared).hexdigest(), {}, budget)
        self.assertEqual(len(opened), 1)
        with self.assertRaises(OSError):self.execution.os.fstat(opened[0])

    def _owner_state(self, owner, journal):
        return (owner.deadline, owner.requests, owner.get_bytes, owner.put_bytes,
            journal.bytes_written, journal.next_id, hashlib.sha256(journal.path.read_bytes()).hexdigest())

    def test_cdn_budget_owner_fresh_same_limits_cannot_transplant_original_journal(self):
        for operation in ('configuration', 'refresh'):
            for fault in ('healthy', 'expired', 'request_credit', 'read_credit', 'cancelled', 'evidence_credit'):
                with self.subTest(operation=operation, fault=fault):
                    request, before, routes, urls, owner, journal, prepared = self._cdn_effect_fixture()
                    if fault == 'expired':owner.clock = lambda: owner.deadline+1
                    elif fault == 'request_credit':owner.requests = owner.limits['max_requests']
                    elif fault == 'read_credit':owner.get_bytes = owner.limits['max_get_bytes']
                    elif fault == 'cancelled':owner.cancelled = True
                    elif fault == 'evidence_credit':journal.bytes_written = owner.limits['max_evidence_bytes']-2048
                    fresh = self.execution.RunBudget(request['limits']);fresh.journal = journal
                    original = self._owner_state(owner, journal);count = len(self.wire.requests)
                    try:
                        try:
                            self.provider.bind_execution_controls(budget=fresh)
                            if operation == 'configuration':self.provider.apply_rewrites(routes, before=before, managed_ids=[])
                            else:self.provider.refresh(urls, poll_interval=0)
                        except Exception:pass
                        calls = self.wire.requests[count:]
                        print(json.dumps({'owner_fixture': fault, 'operation': operation, 'new_wire_calls': len(calls),
                            'new_mutating_wire_calls': sum(x[2] in ('BatchSetCdnDomainConfig','RefreshObjectCaches') for x in calls),
                            'socket_attempts': len(self.connect_attempts)}))
                        self.assertEqual(len(calls), 0)
                        self.assertEqual(self._owner_state(owner, journal), original)
                        self.assertEqual((fresh.requests, fresh.get_bytes, fresh.put_bytes), (0,0,0))
                    finally:
                        journal.close();journal.path.unlink()
                        self.wire.configs = [x for x in self.wire.configs if x['FunctionName'] != 'back_to_origin_url_rewrite']

    def test_cdn_budget_owner_transport_checks_even_if_binding_method_is_bypassed(self):
        for mode in ('session_only','both_fields'):
            with self.subTest(mode=mode):
                request, before, routes, urls, owner, journal, prepared = self._cdn_effect_fixture()
                fresh = self.execution.RunBudget(request['limits']);fresh.journal = journal
                self.provider.session.execution_budget = fresh
                if mode == 'both_fields':self.provider.execution_budget = fresh
                original = self._owner_state(owner, journal);count = len(self.wire.requests)
                try:
                    try:self.provider.apply_rewrites(routes, before=before, managed_ids=[])
                    except Exception:pass
                    self.assertEqual(len(self.wire.requests[count:]), 0)
                    self.assertEqual(self._owner_state(owner, journal), original)
                finally:
                    journal.close();journal.path.unlink()
                    self.wire.configs = [x for x in self.wire.configs if x['FunctionName'] != 'back_to_origin_url_rewrite']

    def test_cdn_budget_owner_changed_after_signed_attempt_stops_before_wire(self):
        from urllib.parse import parse_qs, urlsplit
        request, before, routes, urls, owner, journal, prepared = self._cdn_effect_fixture()
        other = self.execution.RunBudget(request['limits'])
        foreign = self.execution.EffectJournal(self.github.root / 'foreign-owner.jsonl', request,
            hashlib.sha256(prepared).hexdigest(), {}, other)
        self.addCleanup(foreign.close);other.journal = foreign
        foreign_bytes = foreign.path.read_bytes();signed = owner.before_sdk; switched = []
        def change(actual):
            ticket = signed(actual)
            fields = parse_qs(urlsplit(actual.url).query)
            fields.update(parse_qs(actual.body.decode() if isinstance(actual.body, bytes) else actual.body or ''))
            if fields.get('Action') == ['BatchSetCdnDomainConfig']:
                switched.append((len(self.wire.requests), owner.requests, owner.deadline))
                owner.journal = foreign
            return ticket
        owner.before_sdk = change
        result = self.provider.apply_rewrites(routes, before=before, managed_ids=[])
        self.assertEqual(result['state'], 'incomplete');self.assertEqual(len(switched), 1)
        self.assertEqual(len(self.wire.requests[switched[0][0]:]), 0)
        self.assertEqual((owner.requests, owner.deadline), switched[0][1:])
        self.assertEqual(foreign.path.read_bytes(), foreign_bytes)
        summary = self._effect_summary(request, journal, prepared)
        self.assertEqual(summary['unknown_by_kind']['configuration'], 1)

    def test_cdn_budget_owner_completion_helpers_refuse_before_delegate(self):
        request, before, routes, urls, owner, journal, prepared = self._cdn_effect_fixture()
        payload = {'Action':'BatchSetCdnDomainConfig', 'DomainNames':'packages.githubim.com',
            'Functions':json.dumps(request['cdn_intent']['functions'],separators=(',',':'))}
        step = owner.begin_cdn_step(kind='configuration', ordinal=0, payload=payload)
        fresh = self.execution.RunBudget(request['limits']);fresh.journal = journal
        cases = (
            ('begin_cdn_step', (), {'kind':'configuration','ordinal':0,'payload':payload}, 'begin_cdn_step'),
            ('end_cdn_step', (step,), {}, 'end_cdn_step'),
            ('after_sdk', (1,200), {}, 'after_send'),
            ('consumed_sdk', (1,200,1,'a'*64), {}, 'consumed'),
            ('parsed_cdn_response', (), {}, 'parsed_response'),
            ('acknowledge_cdn_step', (step,{'config_ids':['101']}), {}, 'acknowledge'),
            ('observed_cdn_configuration', (before,), {}, 'observe_configuration'))
        original = self._owner_state(owner, journal)
        for method, args, kwargs, target in cases:
            with self.subTest(method=method), mock.patch.object(journal, target) as delegated:
                with self.assertRaises(self.execution.ExecutionError):getattr(fresh, method)(*args, **kwargs)
                delegated.assert_not_called()
                self.assertEqual(self._owner_state(owner, journal), original)
        with self.assertRaises(self.execution.ExecutionError):fresh.cdn_configuration_matches(step, ['101'], before)
        owner.end_cdn_step(step)

    def test_cdn_budget_owner_urllib_refuses_before_opener(self):
        import urllib.request
        request, before, routes, urls, owner, journal, prepared = self._cdn_effect_fixture()
        fresh = self.execution.RunBudget(request['limits']);fresh.journal = journal
        from types import SimpleNamespace
        opened = mock.Mock(return_value=SimpleNamespace(status=200))
        original = self._owner_state(owner, journal)
        with self.assertRaises(self.execution.ExecutionError):fresh.open(opened,
            urllib.request.Request('https://api.github.com/repos/WuKongIM/packages'), timeout=2)
        opened.assert_not_called();self.assertEqual(self._owner_state(owner, journal), original)

    def test_cdn_budget_owner_late_same_owner_headers_and_scope_cleanup_are_retained(self):
        for fault in ('expired','cancelled'):
            with self.subTest(fault=fault):
                request, before, routes, urls, owner, journal, prepared = self._cdn_effect_fixture()
                send = self.wire.send; switched = []
                def expire(actual, **kwargs):
                    response = send(actual, **kwargs)
                    if self.wire.requests[-1][2] == 'BatchSetCdnDomainConfig':
                        switched.append(len(self.wire.requests))
                        if fault == 'expired':owner.clock = lambda: owner.deadline+1
                        else:owner.cancelled = True
                    return response
                self.wire.send = expire
                self.assertEqual(self.provider.apply_rewrites(routes, before=before, managed_ids=[])['state'], 'incomplete')
                self.assertEqual(len(switched),1);self.assertEqual(len(self.wire.requests),switched[0])
                journal.close();events = [json.loads(x) for x in journal.path.read_bytes().splitlines()]
                attempt = next(x for x in events if x['event']=='request_attempt' and 'step_id' in x)
                self.assertTrue(any(x['event']=='request_result' and x['request_id']==attempt['request_id'] and x['status']==200 for x in events))
                self.assertTrue(any(x['event']=='cdn_step_end' for x in events))
                self.assertFalse(any(x['event'] in ('response_consumed','response_parsed','cdn_ack') for x in events))
                journal.path.unlink();self.wire.send = send
                self.wire.configs = [x for x in self.wire.configs if x['FunctionName'] != 'back_to_origin_url_rewrite']

    def test_cdn_budget_owner_header_failure_still_closes_actual_sdk_response(self):
        request, before, routes, urls, owner, journal, prepared = self._cdn_effect_fixture()
        send = self.wire.send;record = journal.record; captured = [];target = []
        owner.after_sdk = mock.Mock(wraps=owner.after_sdk)
        def response(actual, **kwargs):
            value = send(actual, **kwargs)
            if self.wire.requests[-1][2] == 'BatchSetCdnDomainConfig':
                captured.append(value.raw);target.append(journal.steps[journal.active_step]['ticket'])
            return value
        def fail_header(value):
            if value['event']=='request_result' and value['request_id'] in target:
                with mock.patch.object(self.execution.os,'fsync',side_effect=OSError('fixture header fsync')):return record(value)
            return record(value)
        self.wire.send = response;journal.record = fail_header
        self.assertEqual(self.provider.apply_rewrites(routes, before=before, managed_ids=[])['state'], 'incomplete')
        self.assertEqual(len(captured),1)
        for raw in captured:self.addCleanup(raw.close)
        self.assertTrue(captured[0].closed)
        self.assertEqual([call.args[1] for call in owner.after_sdk.call_args_list if call.args[0] in target],[200])
        self.assertEqual(self._effect_summary(request, journal, prepared)['unknown_by_kind']['configuration'],1)

    def test_cdn_budget_owner_legacy_ports_and_none_unbinding_remain_compatible(self):
        from types import SimpleNamespace
        budget = self.execution.RunBudget(self.request['limits'])
        legacy = SimpleNamespace(cdn_mode=False,after_send=mock.Mock())
        budget.journal = legacy
        budget.check();budget.after_sdk(1,200);legacy.after_send.assert_called_once_with(1,200)
        virtual = SimpleNamespace()
        self.provider.bind_execution_controls(budget=virtual)
        self.assertIs(self.provider.execution_budget,virtual);self.assertIs(self.provider.session.execution_budget,virtual)
        self.provider.bind_execution_controls(budget=None)
        self.assertIsNone(self.provider.execution_budget);self.assertIsNone(self.provider.session.execution_budget)

    def test_cdn_response_ownership_sdk_transport_error_with_and_without_response(self):
        for mode in ('attached_response','no_response'):
            with self.subTest(mode=mode):
                request, before, routes, urls, owner, journal, prepared = self._cdn_effect_fixture()
                send = self.wire.send;captured = [];target = []
                owner.after_sdk = mock.Mock(wraps=owner.after_sdk)
                def transport(actual, **kwargs):
                    response = send(actual, **kwargs)
                    if self.wire.requests[-1][2] == 'BatchSetCdnDomainConfig':
                        target.append(journal.steps[journal.active_step]['ticket'])
                        captured.append(response.raw);self.addCleanup(response.raw.close)
                        if mode == 'attached_response':
                            response.status_code = 503
                            raise self.sdk.requests.HTTPError('fixture transport response',response=response,request=actual)
                        response.close()
                        raise self.sdk.requests.ReadTimeout('fixture no response')
                    return response
                self.wire.send = transport
                try:
                    self.assertEqual(self.provider.apply_rewrites(routes,before=before,managed_ids=[])['state'],'incomplete')
                    self.assertEqual(len(captured),1);self.assertTrue(captured[0].closed)
                    self.assertEqual([call.args[1] for call in owner.after_sdk.call_args_list if call.args[0] in target],[None])
                    self.assertEqual(self._effect_summary(request,journal,prepared)['unknown_by_kind']['configuration'],1)
                finally:
                    journal.close();journal.path.unlink();self.wire.send = send
                    self.wire.configs = [x for x in self.wire.configs if x['FunctionName'] != 'back_to_origin_url_rewrite']

    def test_cdn_response_ownership_streamed_sdk_owner_change_closes_once(self):
        request, before, routes, urls, owner, journal, prepared = self._cdn_effect_fixture()
        other = self.execution.RunBudget(request['limits'])
        foreign = self.execution.EffectJournal(self.github.root / 'stream-foreign.jsonl',request,
            hashlib.sha256(prepared).hexdigest(),{},other)
        self.addCleanup(foreign.close);other.journal = foreign
        foreign_bytes = foreign.path.read_bytes();send = self.wire.send;captured = [];target = []
        self.wire.objects[self.sdk.KEY] = (self.sdk.DATA,self.sdk.FACTS['cache_control'])
        owner.after_sdk = mock.Mock(wraps=owner.after_sdk)
        def transport(actual, **kwargs):
            response = send(actual, **kwargs)
            if actual.method == 'GET' and not self.wire.requests[-1][2]:
                captured.append(response.raw);self.addCleanup(response.raw.close)
                target.append(journal.next_id);owner.journal = foreign
            return response
        self.wire.send = transport;count = len(self.wire.requests)
        with self.assertRaises(Exception):self.provider.read_object(self.sdk.KEY,self.sdk.FACTS)
        self.assertEqual(len(self.wire.requests)-count,1)
        self.assertEqual(len(captured),1);self.assertTrue(captured[0].closed)
        self.assertEqual([call.args[1] for call in owner.after_sdk.call_args_list if call.args[0] in target],[200])
        self.assertEqual(foreign.path.read_bytes(),foreign_bytes)

    def test_cdn_response_ownership_urllib_returned_response_closes_on_log_failure(self):
        import urllib.request
        from types import SimpleNamespace
        for fault in ('owner_change','journal_failure'):
            with self.subTest(fault=fault):
                request, before, routes, urls, owner, journal, prepared = self._cdn_effect_fixture()
                other = self.execution.RunBudget(request['limits'])
                foreign = self.execution.EffectJournal(self.github.root / ('returned-'+fault+'.jsonl'),request,
                    hashlib.sha256(prepared).hexdigest(),{},other)
                other.journal = foreign;foreign_bytes = foreign.path.read_bytes()
                raw = io.BytesIO(b'fixture response');self.addCleanup(raw.close)
                calls = [];record = journal.record
                owner.after_sdk = mock.Mock(wraps=owner.after_sdk)
                def opened(*args, **kwargs):
                    calls.append(True)
                    if fault == 'owner_change':owner.journal = foreign
                    return SimpleNamespace(status=200,close=raw.close,read=raw.read)
                def fail_log(value):
                    if value['event'] == 'request_result':
                        with mock.patch.object(self.execution.os,'fsync',side_effect=OSError('fixture result fsync')):return record(value)
                    return record(value)
                if fault == 'journal_failure':journal.record = fail_log
                try:
                    with self.assertRaises(self.execution.ExecutionError if fault=='owner_change' else OSError):owner.open(opened,
                        urllib.request.Request('https://'+self.sdk.RESOURCE['bucket']+'.oss-cn-hangzhou.aliyuncs.com/public/repo'),timeout=2)
                    self.assertEqual(len(calls),1);self.assertTrue(raw.closed)
                    self.assertEqual(len(owner.after_sdk.call_args_list),1)
                    self.assertEqual(foreign.path.read_bytes(),foreign_bytes)
                finally:
                    journal.close();journal.path.unlink();foreign.close()

    def test_cdn_response_ownership_urllib_http_error_fp_closes_on_all_exits(self):
        import urllib.error
        import urllib.request
        for fault in ('transport_only','owner_change','journal_failure'):
            with self.subTest(fault=fault):
                request, before, routes, urls, owner, journal, prepared = self._cdn_effect_fixture()
                other = self.execution.RunBudget(request['limits'])
                foreign = self.execution.EffectJournal(self.github.root / ('http-error-'+fault+'.jsonl'),request,
                    hashlib.sha256(prepared).hexdigest(),{},other)
                other.journal = foreign;foreign_bytes = foreign.path.read_bytes()
                raw = io.BytesIO(b'fixture error');self.addCleanup(raw.close);record = journal.record;calls = []
                address = 'https://'+self.sdk.RESOURCE['bucket']+'.oss-cn-hangzhou.aliyuncs.com/public/repo'
                error = urllib.error.HTTPError(address,503,'fixture',{},raw)
                owner.after_sdk = mock.Mock(wraps=owner.after_sdk)
                def opened(*args, **kwargs):
                    calls.append(True)
                    if fault=='owner_change':owner.journal = foreign
                    raise error
                def fail_log(value):
                    if value['event']=='request_result':
                        with mock.patch.object(self.execution.os,'fsync',side_effect=OSError('fixture error fsync')):return record(value)
                    return record(value)
                if fault=='journal_failure':journal.record = fail_log
                expected = self.execution.ExecutionError if fault=='owner_change' else OSError if fault=='journal_failure' else urllib.error.HTTPError
                try:
                    with self.assertRaises(expected):owner.open(opened,urllib.request.Request(address),timeout=2)
                    self.assertEqual(len(calls),1);self.assertTrue(raw.closed)
                    self.assertEqual([call.args[1] for call in owner.after_sdk.call_args_list],[None])
                    self.assertEqual(foreign.path.read_bytes(),foreign_bytes)
                finally:
                    error.close();journal.close();journal.path.unlink();foreign.close()

    def test_cdn_response_ownership_returned_wrapper_context_closes_after_guard(self):
        import urllib.request
        from types import SimpleNamespace
        for phase in ('before_read','during_read'):
            with self.subTest(phase=phase):
                request, before, routes, urls, owner, journal, prepared = self._cdn_effect_fixture()
                other = self.execution.RunBudget(request['limits'])
                foreign = self.execution.EffectJournal(self.github.root / ('wrapper-'+phase+'.jsonl'),request,
                    hashlib.sha256(prepared).hexdigest(),{},other)
                other.journal = foreign;foreign_bytes = foreign.path.read_bytes()
                raw = io.BytesIO(b'fixture response');self.addCleanup(raw.close);reads = []
                def read(size):
                    reads.append(True);value = raw.read(size);owner.journal = foreign;return value
                def opened(*args, **kwargs):return SimpleNamespace(status=200,close=raw.close,read=read)
                try:
                    with self.assertRaises(self.execution.ExecutionError):
                        with owner.open(opened,urllib.request.Request('https://'+self.sdk.RESOURCE['bucket']+'.oss-cn-hangzhou.aliyuncs.com/public/repo'),timeout=2) as response:
                            if phase=='before_read':owner.journal = foreign
                            response.read(2)
                    self.assertTrue(raw.closed);self.assertEqual(len(reads),0 if phase=='before_read' else 1)
                    self.assertEqual(owner.get_bytes,0);self.assertEqual(foreign.path.read_bytes(),foreign_bytes)
                finally:
                    journal.close();journal.path.unlink();foreign.close()

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

    def _reconcile_header_failure(self, mode):
        send = self.wire.send
        injected = []

        def fault_after_effect(request, **kwargs):
            response = send(request, **kwargs)
            if request.method == 'PUT' and not injected:
                injected.append(True)
                if mode == 'http503':
                    response.status_code = 503
                    response.raw = io.BytesIO(b'<Error><Code>InternalError</Code></Error>')
                else:
                    read_timeout = self.sdk.requests.ReadTimeout

                    class InterruptedBody(io.BytesIO):
                        def read(self, *args, **kwargs):
                            raise read_timeout('fixture response body interrupted')

                    response.raw = InterruptedBody()
            return response

        self.wire.send = fault_after_effect
        prior = self.execution._stage_immutable(self.request, provider=self.provider)
        self.assertEqual(prior['objects'][0]['put_outcome'],
            'unknown' if mode == 'http503' else 'unknown_readback_verified')
        events = [json.loads(line) for line in Path(prior['journal_path']).read_bytes().splitlines()]
        put = next(x for x in events if x.get('event') == 'request_attempt' and x['method'] == 'PUT')
        result = next(x for x in events if x.get('event') == 'request_result' and x['request_id'] == put['request_id'])
        self.assertEqual(result['status'], 503 if mode == 'http503' else 200)
        self.assertEqual(result['outcome'], 'response_received')
        before = len(self.wire.requests)
        observed = self.execution._reconcile_staging(self.request, provider=self.provider,
            journal_path=Path(prior['journal_path']), journal_sha256=prior['journal_sha256'],
            output_dir=self.github.root / 'reconciled')
        self.assertEqual(observed['objects'][0]['observed_now'], 'exact')
        self.assertFalse(any(x[0].method == 'PUT' for x in self.wire.requests[before:]))
        self.assertEqual(observed['original_unknown_outcomes'], 1,
            'HTTP headers and later exact GET cannot resolve the original unknown PUT')

    def test_reconcile_http503_headers_preserve_original_unknown_put(self):
        self._reconcile_header_failure('http503')

    def test_reconcile_http200_interrupted_body_preserves_original_unknown_put(self):
        self._reconcile_header_failure('interrupted_body')

    def test_reconcile_known_created_and_already_existing_puts_are_not_unknown(self):
        for number, outcome in enumerate(('created', 'already_exists')):
            with self.subTest(outcome=outcome):
                self.request['output_dir'] = str(self.github.root / ('execution-' + str(number)))
                prior = self.execution._stage_immutable(self.request, provider=self.provider)
                self.assertEqual(prior['status'], 'staged_readback_verified')
                self.assertEqual({x['put_outcome'] for x in prior['objects']}, {outcome})
                before = len(self.wire.requests)
                observed = self.execution._reconcile_staging(self.request, provider=self.provider,
                    journal_path=Path(prior['journal_path']), journal_sha256=prior['journal_sha256'],
                    output_dir=self.github.root / ('reconciled-' + str(number)))
                self.assertEqual(observed['original_unknown_outcomes'], 0)
                self.assertTrue(all(x['observed_now'] == 'exact' for x in observed['objects']))
                self.assertFalse(any(x[0].method == 'PUT' for x in self.wire.requests[before:]))

    def test_reconcile_rejects_ambiguous_or_unbound_completion_before_reads(self):
        prior = self.execution._stage_immutable(self.request, provider=self.provider)
        original = [json.loads(line) for line in Path(prior['journal_path']).read_bytes().splitlines()]
        for fault in ('duplicate_put', 'duplicate_attempt', 'duplicate_completion',
                      'facts', 'key', 'request_id'):
            with self.subTest(fault=fault):
                events = json.loads(json.dumps(original))
                attempt = next(i for i, x in enumerate(events) if x.get('event') == 'object_attempt')
                put = next(i for i, x in enumerate(events) if x.get('event') == 'request_attempt' and x['method'] == 'PUT')
                observed = next(i for i, x in enumerate(events) if x.get('event') == 'object_observed')
                if fault == 'duplicate_put':
                    extra = dict(events[put], request_id=max(x.get('request_id', 0) for x in events) + 1)
                    events.insert(put + 1, extra)
                elif fault == 'duplicate_attempt':
                    events.insert(attempt + 1, events[attempt])
                elif fault == 'duplicate_completion':
                    events.append(events[observed])
                elif fault == 'facts':
                    events[observed]['facts']['sha256'] = '0' * 64
                elif fault == 'key':
                    events[observed]['object_key'] = prior['objects'][1]['object_key']
                else:
                    events[put]['request_id'] = events[put - 1]['request_id']
                raw = b''.join(json.dumps(x, sort_keys=True).encode() + b'\n' for x in events)
                journal = self.github.root / ('ambiguous-' + fault + '.jsonl')
                journal.write_bytes(raw)
                before = len(self.wire.requests)
                with self.assertRaises(ValueError):
                    self.execution._reconcile_staging(self.request, provider=self.provider,
                        journal_path=journal, journal_sha256=hashlib.sha256(raw).hexdigest(),
                        output_dir=self.github.root / ('reconciled-' + fault))
                self.assertEqual(len(self.wire.requests), before)


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
