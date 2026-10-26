"""Object delivery execution; the protected production composition is disabled.

Internal execution consumes independently verified inputs and concrete transports.
Neither a request field nor credentials establish human publication authority.
"""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import math
import os
import time
from urllib.error import HTTPError
from urllib.parse import parse_qs, parse_qsl, unquote, urlsplit
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parent
FALSE_FIELDS = dict(production_enabled=False, publication_verified=False,
                    cloud_verified=False, github_provenance_verified=False)


class ExecutionError(ValueError):
    """Execution inputs, bounds or independently observed facts differ."""


def require(condition, message):
    if not condition:
        raise ExecutionError(message)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode() + b'\n'


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


CDN_ACTIONS = {'configuration': 'BatchSetCdnDomainConfig', 'refresh': 'RefreshObjectCaches'}
SDK_SIGNING_FIELDS = {'AccessKeyId', 'SecurityToken', 'SignatureMethod', 'SignatureVersion',
    'SignatureNonce', 'Timestamp', 'Signature', 'SignatureType', 'Format', 'Version', 'RegionId'}


def _cdn_intent(request):
    """Validate private evidence scope; the public executor still refuses this operation."""
    require(request.get('operation') == 'cdn_effects', 'private CDN evidence request required')
    base_request = {key:value for key,value in request.items() if key != 'cdn_intent'}
    base_request['operation'] = 'stage_immutable'
    _request(base_request)
    intent = copy.deepcopy(request.get('cdn_intent'))
    require(isinstance(intent, dict) and set(intent) ==
            {'routes', 'configuration_before', 'functions', 'refresh_urls'}, 'exact CDN intent required')
    routes, functions, urls, before = (intent[k] for k in
        ('routes', 'functions', 'refresh_urls', 'configuration_before'))
    require(isinstance(routes, list) and 0 < len(routes) <= 1000
            and isinstance(functions, list) and 0 < len(functions) <= 50
            and isinstance(urls, list) and 0 < len(urls) <= 1000,
            'bounded CDN intent required')
    require(isinstance(before, dict) and set(before) ==
            {'resource_sha256', 'domain', 'detail', 'configs', 'sha256'}, 'complete C0 required')
    provider_resource_digest = hashlib.sha256(canonical(request['resource'])[:-1]).hexdigest()
    require(before['domain'] == request['resource']['domain']
            and before['resource_sha256'] == provider_resource_digest
            and before['sha256'] == hashlib.sha256(canonical({k:v for k,v in before.items() if k != 'sha256'})[:-1]).hexdigest(),
            'C0 intent binding differs')
    require(all(isinstance(x, dict) and isinstance(x.get('public_uri'), str) for x in routes)
            and len({x['public_uri'] for x in routes}) == len(routes)
            and urls == ['https://' + request['resource']['domain'] + x['public_uri'] for x in routes],
            'refresh intent differs from exact route table')
    require(len(set(urls)) == len(urls), 'duplicate refresh intent')
    for function in functions:
        require(isinstance(function, dict) and set(function) == {'functionName','functionArgs'}
                and function['functionName'] == 'back_to_origin_url_rewrite'
                and isinstance(function['functionArgs'], list)
                and [x.get('argName') for x in function['functionArgs']] ==
                    ['source_url','target_url','flag','sequence']
                and all(set(x) == {'argName','argValue'} and isinstance(x['argValue'], str)
                        for x in function['functionArgs']), 'closed compiled function intent required')
    return intent


def _cdn_functions(intent):
    """Preserve only the existing source's exact ConfigId when updating a function."""
    functions = copy.deepcopy(intent['functions'])
    old = {}
    for row in intent['configuration_before']['configs']:
        if row.get('FunctionName') == 'back_to_origin_url_rewrite':
            args = {x['ArgName']:x['ArgValue'] for x in row['FunctionArgs']['FunctionArg']}
            require(args['source_url'] not in old, 'duplicate C0 source')
            old[args['source_url']] = str(row['ConfigId'])
    for row in functions:
        source = row['functionArgs'][0]['argValue']
        if source in old:row['configId'] = old.pop(source)
    require(not old, 'CDN intent requires deletion or rechunk')
    return functions


def _cdn_scope(request, kind, ordinal):
    """Derive each exact business payload from the digest-bound finite intent."""
    intent = _cdn_intent(request)
    require(kind in CDN_ACTIONS and type(ordinal) is int and ordinal >= 0, 'invalid CDN step')
    functions = _cdn_functions(intent)
    values, width = (functions, 20) if kind == 'configuration' else (intent['refresh_urls'], 50)
    batch = values[ordinal*width:(ordinal+1)*width]
    require(batch, 'CDN ordinal outside bound intent')
    payload = ({'Action':CDN_ACTIONS[kind], 'DomainNames':request['resource']['domain'],
                'Functions':json.dumps(batch, separators=(',',':'))} if kind == 'configuration' else
               {'Action':CDN_ACTIONS[kind], 'ObjectPath':'\n'.join(batch), 'ObjectType':'File'})
    return {'kind':kind, 'ordinal':ordinal, 'domain':request['resource']['domain'],
        'payload_sha256':digest(payload), 'before_sha256':intent['configuration_before']['sha256'],
        'target_sha256':digest(functions if kind == 'configuration' else intent['refresh_urls'])}, payload


def _cdn_ack_facts(request, kind, ordinal, facts):
    """Accept only finite positive IDs; task IDs may legitimately span submissions."""
    scope, payload = _cdn_scope(request, kind, ordinal)
    key = 'config_ids' if kind == 'configuration' else 'task_ids'
    require(isinstance(facts, dict) and set(facts) == {key} and isinstance(facts[key], list),
            'closed CDN acknowledgement facts required')
    ids = facts[key]
    size = len(json.loads(payload['Functions'])) if kind == 'configuration' else len(payload['ObjectPath'].split('\n'))
    require(0 < len(ids) <= size and len(set(ids)) == len(ids)
            and all(isinstance(x, str) and re.fullmatch('[1-9][0-9]{0,31}', x) for x in ids)
            and (kind != 'configuration' or len(ids) == size), 'CDN acknowledgement IDs differ')
    if kind == 'configuration':
        for row in json.loads(payload['Functions']):
            require('configId' not in row or row['configId'] in ids, 'CDN existing configuration ID changed')


def _cdn_snapshot(request, value):
    require(isinstance(value, dict) and set(value) ==
            {'resource_sha256','domain','detail','configs','sha256'}
            and isinstance(value['configs'], list) and isinstance(value['detail'], dict)
            and value['domain'] == request['resource']['domain']
            and value['resource_sha256'] == hashlib.sha256(canonical(request['resource'])[:-1]).hexdigest()
            and value['sha256'] == hashlib.sha256(canonical({k:v for k,v in value.items() if k != 'sha256'})[:-1]).hexdigest(),
            'complete current configuration binding differs')


def _configuration_ack_matches(request, ordinal, ids, after):
    """Associate returned IDs with the exact batch functions in full current C1."""
    _cdn_snapshot(request, after)
    _cdn_ack_facts(request, 'configuration', ordinal, {'config_ids':ids})
    scope, payload = _cdn_scope(request, 'configuration', ordinal)
    actual = after['configs']; matched = set()
    for function in json.loads(payload['Functions']):
        args = {x['argName']:x['argValue'] for x in function['functionArgs']}
        rows = []
        for item in actual:
            if not (isinstance(item, dict) and str(item.get('ConfigId')) in ids
                    and item.get('FunctionName') == function['functionName'] and item.get('Status') == 'success'
                    and isinstance(item.get('FunctionArgs'), dict)):continue
            fields = item['FunctionArgs'].get('FunctionArg')
            if (isinstance(fields, list) and len(fields) == len(args)
                    and all(isinstance(x,dict) and set(x) == {'ArgName','ArgValue'} for x in fields)
                    and len({x['ArgName'] for x in fields}) == len(fields)
                    and {x['ArgName']:x['ArgValue'] for x in fields} == args):rows.append(item)
        if len(rows) != 1:return False
        number = str(rows[0]['ConfigId'])
        if number in matched or ('configId' in function and function['configId'] != number):return False
        matched.add(number)
    return matched == set(ids)


def module(filename):
    spec = importlib.util.spec_from_file_location('execution_' + filename.replace('-', '_'), ROOT / filename)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


class _BudgetedResponse:
    """Keep urllib reads under the same finite execution budget."""
    def __init__(self, raw, budget):
        self.raw, self.budget = raw, budget

    def __getattr__(self, name):
        return getattr(self.raw, name)

    def __enter__(self):
        return self

    def __exit__(self, *unused):
        self.raw.close()

    def read(self, size=-1):
        self.budget.check()
        available = self.budget.limits['max_get_bytes'] - self.budget.get_bytes
        amount = min(size if size >= 0 else 65536, available + 1)
        raw = self.raw.read(amount)
        self.budget.consume_read(len(raw))
        return raw


class RunBudget:
    """Bound one invocation's reads, requests and time; this grants no authority."""
    def __init__(self, limits, *, clock=time.monotonic, read_only=False,
                 owned_shared=None, absolute_deadline=None):
        bounds = {'max_requests': 50000, 'max_objects': 2048, 'max_routes': 1000,
            'max_put_bytes': 2 * 1024**3, 'max_get_bytes': 8 * 1024**3,
            'max_evidence_bytes': 8 * 1024**2}
        require(isinstance(limits, dict) and set(limits) == set(bounds) | {'timeout_seconds'}, 'exact run limits required')
        for name, maximum in bounds.items():
            require(type(limits[name]) is int and 0 < limits[name] <= maximum, 'run limit outside hard bound')
        seconds = limits['timeout_seconds']
        require(type(seconds) in (int, float) and math.isfinite(seconds) and 0 < seconds <= 3600,
                'bounded run timeout required')
        require(limits['max_evidence_bytes'] >= 4096, 'evidence bound too small')
        self.limits, self.clock = copy.deepcopy(limits), clock
        self.deadline = clock() + seconds
        if absolute_deadline is not None:
            require(owned_shared is not None and absolute_deadline <= self.deadline, 'owned deadline cannot widen limits')
            self.deadline = absolute_deadline
        self.owned_shared = owned_shared
        self.requests = self.get_bytes = self.put_bytes = 0
        self.read_only, self.cancelled, self.journal = read_only, False, None

    def _check_journal_owner(self):
        """A CDN journal cannot borrow a fresh ledger; legacy ports keep their contract."""
        if getattr(self.journal, 'cdn_mode', False):
            require(getattr(self.journal, 'budget', None) is self,
                    'CDN journal belongs to a different execution budget')

    def check(self):
        self._check_journal_owner()
        require(not self.cancelled and self.clock() < self.deadline, 'execution deadline or cancellation reached')
        if self.owned_shared is not None:
            self.owned_shared.check()

    def remaining(self):
        self.check()
        return self.deadline - self.clock()

    def run_process(self, argv, *, env, stdout_cap=1024*1024, stderr_cap=65536, timeout=None, pass_fds=()):
        """Run only the fixed command chosen by a reviewed helper, under owned bounds."""
        require(self.owned_shared is not None, 'owned process context required')
        return module('object-storage-owned-execution.py').run_fixed_process(argv, env=env,
            shared=self.owned_shared, stdout_cap=stdout_cap, stderr_cap=stderr_cap,
            timeout=timeout, pass_fds=pass_fds)

    def before_request(self, method, url, *, action='', size=0):
        self.check()
        read_actions = {'GetCallerIdentity', 'DescribeCdnDomainDetail', 'DescribeCdnDomainConfigs', 'DescribeRefreshTaskById'}
        require(not self.read_only or method == 'GET' or (method == 'POST' and action in read_actions),
                'read-only execution refused a mutating request')
        require(self.requests < self.limits['max_requests'], 'execution request count exceeded')
        if method == 'PUT':
            require(type(size) is int and size >= 0 and self.put_bytes + size <= self.limits['max_put_bytes'],
                    'execution upload bytes exceeded')
            self.put_bytes += size
        self.requests += 1

    def consume_read(self, size):
        self.check()
        require(self.get_bytes + size <= self.limits['max_get_bytes'], 'execution read bytes exceeded')
        self.get_bytes += size

    def open(self, opener, request, *, timeout):
        self.before_request(request.get_method(), request.full_url)
        parsed = urlsplit(request.full_url)
        ticket = self.journal.before_send(request.get_method(), parsed.hostname, parsed.path, '') if self.journal else None
        try:
            response = opener(request, timeout=min(timeout, self.remaining()))
        except Exception as error:
            try:
                self.after_sdk(ticket, None)
            finally:
                # urllib transfers an HTTPError's body through the exception.
                if isinstance(error, HTTPError):error.close()
            raise
        try:
            self.after_sdk(ticket, getattr(response, 'status', 200))
            return _BudgetedResponse(response, self)
        except Exception:
            # Ownership transfers only after headers and wrapper construction.
            response.close()
            raise

    def before_sdk(self, request):
        parsed = urlsplit(request.url)
        fields = parse_qs(parsed.query, keep_blank_values=True)
        if request.method == 'POST' and request.body:
            raw = request.body.decode() if isinstance(request.body, bytes) else request.body
            if isinstance(raw, str):
                fields.update(parse_qs(raw, keep_blank_values=True))
        action = fields.get('Action', [''])[0]
        self.before_request(request.method, request.url, action=action,
            size=int(request.headers.get('Content-Length', 0)))
        if self.journal is not None:
            if self.journal.cdn_mode:
                pairs = parse_qsl(parsed.query, keep_blank_values=True)
                raw = request.body if isinstance(request.body, bytes) else (request.body or '').encode()
                require(isinstance(raw, bytes), 'SDK business body must be bytes')
                pairs += parse_qsl(raw.decode('utf-8'), keep_blank_values=True)
                require(len({key for key, value in pairs}) == len(pairs), 'duplicate SDK field')
                unique = dict(pairs)
                business = {key:value for key,value in pairs if key not in SDK_SIGNING_FIELDS}
                if parsed.hostname in ('cdn.aliyuncs.com','sts.aliyuncs.com'):
                    require(unique.get('RegionId') == self.journal.request['resource']['region']
                            and unique.get('Format') == 'JSON'
                            and unique.get('Version') == ('2015-04-01' if parsed.hostname == 'sts.aliyuncs.com' else '2018-05-10'),
                            'SDK protocol/resource fields differ')
                require(parsed.scheme == 'https' and parsed.hostname in
                        ('cdn.aliyuncs.com','sts.aliyuncs.com', self.request_origin())
                        and parsed.port in (None,443) and not parsed.fragment
                        and parsed.username is None and parsed.password is None, 'SDK journal endpoint differs')
                serialized = request.method.encode()+b'\n'+request.url.encode()+b'\n'+raw
                return self.journal.before_send(request.method, parsed.hostname, parsed.path,
                    unique.get('Action',''), business=business,
                    serialized_sha256=hashlib.sha256(serialized).hexdigest())
            return self.journal.before_send(request.method, parsed.hostname, parsed.path, action)
        return None

    def request_origin(self):
        resource = self.journal.request['resource']
        return resource['bucket'] + '.oss-' + resource['region'] + '.aliyuncs.com'

    def begin_cdn_step(self, *, kind, ordinal, payload, before_sha256=None, target_sha256=None):
        """Open one Provider-owned data scope, without granting execution authority."""
        self.check()
        if self.journal is None:return None
        return self.journal.begin_cdn_step(kind, ordinal, payload, before_sha256, target_sha256)

    def end_cdn_step(self, step):
        self._check_journal_owner()
        if self.journal is not None and step is not None:self.journal.end_cdn_step(step)

    def consumed_sdk(self, ticket, status, size, body_sha256):
        self.check()
        if self.journal is not None:self.journal.consumed(ticket, status, size, body_sha256)

    def parsed_cdn_response(self):
        self.check()
        if self.journal is not None:self.journal.parsed_response()

    def acknowledge_cdn_step(self, step, facts):
        self.check()
        if self.journal is not None and step is not None:self.journal.acknowledge(step, facts)

    def observed_cdn_configuration(self, observation):
        self.check()
        if self.journal is not None and self.journal.cdn_mode:
            self.journal.observe_configuration(observation)

    def cdn_configuration_matches(self, step, ids, observation):
        self.check()
        return (step is not None and self.journal is not None
                and _configuration_ack_matches(self.journal.request,
                    self.journal.steps[step]['scope']['ordinal'], ids, observation))

    def after_sdk(self, ticket, status=None):
        # Keep late headers as observations, without allowing another owner.
        self._check_journal_owner()
        if self.journal is not None and ticket is not None:
            self.journal.after_send(ticket, status)

    def snapshot(self):
        return {'requests': self.requests, 'get_bytes': self.get_bytes, 'put_bytes': self.put_bytes,
            'expired': self.cancelled or self.clock() >= self.deadline, 'limits': copy.deepcopy(self.limits)}


class EffectJournal:
    """Durably bind sanitized attempts before transport; never infer rollback."""
    def __init__(self, path, request, prepared_sha256, initial, budget):
        self.path, self.budget, self.request = path, budget, copy.deepcopy(request)
        self.active_object, self.next_id, self.bytes_written = None, 0, 0
        self.cdn_mode = request.get('operation') == 'cdn_effects'
        self.active_step, self.steps, self.tickets, self.broken = None, {}, {}, False
        self.configuration_observed = None
        if self.cdn_mode:
            budget.check()
            require(budget.limits == request['limits'], 'CDN budget differs from exact request')
            intent = _cdn_intent(request)
            fresh = module('verify-object-storage-delivery-inputs.py')
            prepared_raw = fresh.D._read(Path(request['output_dir']) / 'prepared/delivery.json', 'CDN preparation')
            require(hashlib.sha256(prepared_raw).hexdigest() == prepared_sha256, 'CDN preparation bytes differ')
            prepared = json.loads(prepared_raw, object_pairs_hook=fresh.C.reject_duplicate_pairs)
            require(prepared['routes'] == intent['routes'], 'CDN intent differs from exact prepared routes')
        self.fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            self.record({'event': 'run_start_v2' if self.cdn_mode else 'run_start', 'request_sha256': digest(request),
                'inputs_sha256': request['inputs_sha256'], 'plan_sha256': request['plan_sha256'],
                'resource_sha256': digest(request['resource']), 'preparation_sha256': prepared_sha256,
                'fresh_initial': initial, **({'intent_sha256':digest(request['cdn_intent']),
                    'effect_deadline_ns':int(budget.deadline*1e9)} if self.cdn_mode else {})})
        except Exception:
            self.close()
            raise

    def record(self, value):
        require(not self.broken, 'execution journal is incomplete')
        raw = canonical(value)
        require(self.bytes_written + len(raw) <= self.budget.limits['max_evidence_bytes']
                - (10240 if self.budget.owned_shared is not None else 2048),
                'execution journal exceeds evidence bound')
        view = memoryview(raw)
        try:
            while view:
                count = os.write(self.fd, view)
                require(count > 0, 'execution journal write incomplete')
                view = view[count:]
            os.fsync(self.fd)
        except Exception:
            if self.cdn_mode:
                # A locally visible but uncommitted acknowledgement must not
                # resolve an original unknown after fsync failure.
                self.broken = True
                os.ftruncate(self.fd, self.bytes_written)
            raise
        self.bytes_written += len(raw)

    def begin_cdn_step(self, kind, ordinal, payload, before_sha256, target_sha256):
        require(self.cdn_mode and self.active_step is None, 'CDN scope missing or overlapping')
        expected, business = _cdn_scope(self.request, kind, ordinal)
        step = kind + ':' + str(ordinal)
        require(step not in self.steps and payload == business
                and before_sha256 in (None, expected['before_sha256'])
                and target_sha256 in (None, expected['target_sha256']), 'CDN scope differs from intent')
        self.record({'event':'cdn_step', 'step_id':step, **expected})
        self.steps[step] = {'scope':expected, 'payload':business, 'ticket':None, 'ended':False}
        self.active_step = step
        return step

    def end_cdn_step(self, step):
        require(self.active_step == step and not self.steps[step]['ended'], 'CDN scope ownership differs')
        self.record({'event':'cdn_step_end', 'step_id':step})
        self.steps[step]['ended'] = True
        self.active_step = None

    def before_send(self, method, host, path, action, *, business=None, serialized_sha256=None):
        reads = {'GetCallerIdentity', 'DescribeCdnDomainDetail', 'DescribeCdnDomainConfigs', 'DescribeRefreshTaskById'}
        mutating = method == 'POST' and action not in reads
        require(method == 'GET' or (method == 'POST' and action in reads) or method == 'PUT'
                or (self.cdn_mode and mutating),
                'staging journal refuses an unscoped effect')
        step = self.steps.get(self.active_step) if self.cdn_mode and mutating else None
        if self.cdn_mode and mutating:
            require(step is not None and step['ticket'] is None and host == 'cdn.aliyuncs.com'
                    and path == '/' and business == step['payload'] and action in CDN_ACTIONS.values()
                    and re.fullmatch('[0-9a-f]{64}', serialized_sha256 or ''), 'signed CDN request differs from active scope')
        if method == 'PUT':
            require(self.active_object is not None and unquote(path) == '/' + self.active_object['object_key'],
                    'PUT differs from the exact staging object')
            resource = self.request['resource']
            require(host == resource['bucket'] + '.oss-' + resource['region'] + '.aliyuncs.com',
                    'PUT host differs from staging resource')
            self.active_object['write_attempted'] = True
        self.next_id += 1
        self.record({'event': 'request_attempt', 'request_id': self.next_id,
            'method': method, 'host': host, 'path': path, 'action': action,
            'object_key': self.active_object['object_key'] if self.active_object is not None else None,
            'outcome': 'unknown',
            'effect_deadline_ns': int(self.budget.deadline * 1e9),
            **({'step_id':self.active_step, 'payload_sha256':digest(business),
                'serialized_request_sha256':serialized_sha256} if step is not None else {})})
        if step is not None:
            step['ticket'] = self.next_id
            self.tickets[self.next_id] = {'step_id':self.active_step, 'headers':False,
                'consumed':False, 'parsed':False, 'acknowledged':False}
        return self.next_id

    def after_send(self, ticket, status):
        self.record({'event': 'request_result', 'request_id': ticket, 'status': status,
            'outcome': 'response_received' if status is not None else 'unknown'})
        if ticket in self.tickets:
            self.tickets[ticket].update(headers=True, status=status)

    def consumed(self, ticket, status, size, body_sha256):
        if ticket not in self.tickets:return
        state = self.tickets[ticket]
        require(state['headers'] and not state['consumed'] and state['status'] == status,
                'CDN consumed response ownership differs')
        self.record({'event':'response_consumed', 'request_id':ticket, 'status':status,
            'bytes':size, 'body_sha256':body_sha256})
        state['consumed'] = True

    def parsed_response(self):
        if self.active_step is None:return
        ticket = self.steps[self.active_step]['ticket']
        state = self.tickets[ticket]
        require(state['consumed'] and not state['parsed'] and 200 <= state['status'] < 300,
                'CDN parsed response lacks bounded consumption')
        self.record({'event':'response_parsed', 'request_id':ticket})
        state['parsed'] = True

    def observe_configuration(self, observation):
        _cdn_snapshot(self.request, observation)
        self.record({'event':'configuration_observed', 'observation':observation})
        self.configuration_observed = copy.deepcopy(observation)

    def acknowledge(self, step, facts):
        require(step in self.steps, 'unknown CDN scope')
        ticket = self.steps[step]['ticket']
        require(ticket in self.tickets and self.tickets[ticket]['parsed']
                and not self.tickets[ticket]['acknowledged'], 'CDN acknowledgement lacks consumed response')
        kind = self.steps[step]['scope']['kind']
        _cdn_ack_facts(self.request, kind, self.steps[step]['scope']['ordinal'], facts)
        if kind == 'configuration':
            require(self.configuration_observed is not None and _configuration_ack_matches(self.request,
                self.steps[step]['scope']['ordinal'], facts['config_ids'], self.configuration_observed),
                'configuration acknowledgement differs from full C1')
        self.record({'event':'cdn_ack', 'request_id':ticket, 'step_id':step, 'facts':facts,
            'original_request_outcome':'acknowledged'})
        self.tickets[ticket]['acknowledged'] = True

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None


def _save_receipt(fresh, output, receipt, budget, journal):
    """Retain a bounded incomplete summary if detailed evidence cannot fit."""
    journal.close()
    receipt['journal_path'] = str(journal.path)
    receipt['journal_sha256'] = hashlib.sha256(journal.path.read_bytes()).hexdigest()
    receipt['budget'] = budget.snapshot()
    raw = canonical(receipt)
    evidence_limit = budget.limits['max_evidence_bytes'] - (8192 if budget.owned_shared is not None else 0)
    if len(raw) + journal.bytes_written > evidence_limit:
        receipt = {'schema': 'wukongim.object_storage_execution/v1', 'status': 'incomplete',
            'stage': 'evidence_limit', 'request_sha256': receipt['request_sha256'],
            'journal_path': str(journal.path), 'journal_sha256': receipt['journal_sha256'],
            'omitted_receipt_bytes': len(raw), 'omitted_receipt_sha256': hashlib.sha256(raw).hexdigest(),
            **FALSE_FIELDS}
        require(len(canonical(receipt)) + journal.bytes_written <= evidence_limit,
                'bounded incomplete receipt cannot fit')
    fresh.D._json_write(output / 'execution.json', receipt)
    return receipt


def run_delivery(request):
    """Refuse before SDK construction until the protected entrypoint is provisioned."""
    raise ExecutionError('protected production entrypoint is not implemented or enabled')


def _request(request):
    """Validate data scope without interpreting a field as human authority."""
    fields = {'schema', 'operation', 'executor_sha', 'inputs', 'inputs_sha256',
              'plan_sha256', 'resource', 'output_dir', 'limits'}
    require(isinstance(request, dict), 'exact execution request required')
    if request.get('schema') == 'wukongim.object_storage_execution_request/v2':
        fields.add('process_limits')
    require(set(request) == fields, 'exact execution request required')
    value = copy.deepcopy(request)
    require(value['schema'] in ('wukongim.object_storage_execution_request/v1',
            'wukongim.object_storage_execution_request/v2')
            and value['operation'] == 'stage_immutable', 'unsupported execution operation')
    require(isinstance(value['executor_sha'], str) and re.fullmatch('[0-9a-f]{40}', value['executor_sha']),
            'executor SHA invalid')
    for name in ('inputs_sha256', 'plan_sha256'):
        require(isinstance(value[name], str) and re.fullmatch('[0-9a-f]{64}', value[name]), 'input digest invalid')
    for name in ('inputs', 'output_dir'):
        require(isinstance(value[name], str) and Path(value[name]).is_absolute(), 'canonical absolute paths required')
    return value


def _input_bytes(fresh, request):
    raw = fresh.D._read(Path(request['inputs']), 'execution transport inputs')
    require(hashlib.sha256(raw).hexdigest() == request['inputs_sha256'], 'execution input bytes changed')
    return raw


def _light_fence(fresh, request, initial, budget):
    """Bind each next PUT to fresh API identities without payload downloads."""
    _input_bytes(fresh, request)
    return fresh.revalidate_delivery_anchors(inputs=Path(request['inputs']),
        expected_plan_sha256=request['plan_sha256'], previous=initial, budget=budget, source_token=getattr(budget, 'source_token', None),
            package_token=getattr(budget, 'package_token', None))


def _stage_immutable(request, *, provider, budget=None):
    """Execute internal staging after composition-root authority checks.

    This is the actual staging implementation, not an authorization interface.
    Tests exercise its concrete provider through the official SDK HTTP seam.
    The public production entry remains disabled and cannot call it yet.
    """
    request = _request(request)
    owned = request['schema'].endswith('/v2')
    if owned:
        require(budget is not None and budget.owned_shared is not None
                and getattr(budget, 'owned_root_identity', None) is not None, 'owned v2 process context required')
    budget = budget or RunBudget(request['limits'])
    require(budget.limits == request['limits'], 'budget differs from exact request')
    budget.check()
    provider.bind_execution_controls(budget=budget)
    require(provider.resource == request['resource'], 'provider resource differs from request')
    fresh = module('verify-object-storage-delivery-inputs.py')
    _input_bytes(fresh, request)
    initial = fresh.verify_delivery_inputs(inputs=Path(request['inputs']),
        expected_plan_sha256=request['plan_sha256'], executor_sha=request['executor_sha'], budget=budget,
        source_token=getattr(budget, 'source_token', None), package_token=getattr(budget, 'package_token', None))
    output = Path(request['output_dir'])
    if owned:
        metadata = output.stat(follow_symlinks=False)
        require((metadata.st_dev, metadata.st_ino) == budget.owned_root_identity, 'owned output changed')
        output = output / 'staging'
    require(not output.exists() and output.parent.is_dir(), 'execution output must be new')
    fresh.C.validate_candidate_output_paths((output,), (Path(request['inputs']),))
    output.mkdir(mode=0o700)
    prepared = fresh.D.prepare_delivery(inputs=Path(request['inputs']),
        expected_plan_sha256=request['plan_sha256'], output_dir=output / 'prepared',
        resource_intent={'production_enabled': False, 'account_id': None, 'bucket': None,
                         'region': None, 'endpoint': None, 'domain': 'packages.githubim.com'},
        activation_control_sha=request['executor_sha'], max_routes=1000,
        composite=False, test_only=False)
    receipt = {'schema': 'wukongim.object_storage_execution/v1', 'operation': 'stage_immutable',
        'status': 'incomplete', 'stage': 'resource', 'request_sha256': digest(request),
        'inputs_sha256': request['inputs_sha256'], 'plan_sha256': request['plan_sha256'],
        'resource_sha256': digest(request['resource']), 'executor_sha': request['executor_sha'],
        'preparation_sha256': hashlib.sha256((output / 'prepared/delivery.json').read_bytes()).hexdigest(), 'objects': [], 'fresh_initial': initial,
        **FALSE_FIELDS}
    journal = EffectJournal(output / 'effects.jsonl', request, receipt['preparation_sha256'], initial, budget)
    budget.journal = journal
    try:
        budget.check()
        require(len(prepared['objects']) <= request['limits']['max_objects']
                and len(prepared['routes']) <= request['limits']['max_routes'], 'prepared inventory exceeds execution capacity')
        require(sum(x['size'] for x in prepared['objects']) <= request['limits']['max_put_bytes'], 'planned upload bytes exceed limit')
        receipt['resource'] = provider.observe_resource()
        receipt['stage'] = 'objects'
        for item in prepared['objects']:
            fence = _light_fence(fresh, request, initial, budget)
            journal.record({'event': 'metadata_fence', 'sha256': digest(fence)})
            require(hashlib.sha256((output / 'prepared/delivery.json').read_bytes()).hexdigest()
                    == receipt['preparation_sha256'], 'prepared inventory changed')
            facts = {name: item[name] for name in ('size', 'sha256', 'cache_control')}
            path = fresh.C.candidate_path(output / 'prepared', item['materialized_file'], 'staging object')
            require(fresh.C.hash_file(path, 'staging object', maximum_bytes=item['size'])
                    == {name: item[name] for name in ('size', 'sha256')}, 'staging object changed')
            row = {'object_key': item['object_key'], 'facts': facts,
                   'put_outcome': 'unknown', 'readback_verified': False, 'write_attempted': False}
            receipt['objects'].append(row)
            journal.active_object = row
            journal.record({'event': 'object_attempt', 'object_key': item['object_key'], 'facts': facts})
            observed = provider.put_create_only(item['object_key'], path, facts)
            row.update(put_outcome=observed['outcome'], readback_verified=True, readback=observed['readback'])
            journal.record({'event': 'object_observed', **row})
            journal.active_object = None
        receipt['stage'] = 'final_fence'
        receipt['fresh_final'] = fresh.verify_delivery_inputs(inputs=Path(request['inputs']),
            expected_plan_sha256=request['plan_sha256'], executor_sha=request['executor_sha'], previous=initial, budget=budget, source_token=getattr(budget, 'source_token', None),
            package_token=getattr(budget, 'package_token', None))
        receipt.update(status='staged_readback_verified', stage='complete')
    except Exception:
        receipt['error'] = 'staging incomplete; inspect exact recorded attempts'
    budget.journal = None
    return _save_receipt(fresh, output, receipt, budget, journal)



def _bound_staging_journal(request, raw, prepared_raw):
    """Interpret only the exact digest-bound unique staging attempt sequence."""
    fresh = module('verify-object-storage-delivery-inputs.py')
    lines = raw.splitlines(keepends=True)
    tail = lines.pop() if lines and not lines[-1].endswith(b'\n') else b''
    events = [json.loads(line, object_pairs_hook=fresh.C.reject_duplicate_pairs) for line in lines]
    require(events and events[0].get('event') == 'run_start', 'prior journal header missing')
    header = events[0]
    require(header.get('request_sha256') == digest(request)
            and header.get('resource_sha256') == digest(request['resource'])
            and header.get('inputs_sha256') == request['inputs_sha256']
            and header.get('plan_sha256') == request['plan_sha256'], 'prior request/plan/resource differs')
    require(hashlib.sha256(prepared_raw).hexdigest() == header['preparation_sha256'], 'prior preparation differs')
    prepared = json.loads(prepared_raw, object_pairs_hook=fresh.C.reject_duplicate_pairs)
    allowed = {x['object_key']: {k: x[k] for k in ('size', 'sha256', 'cache_control')} for x in prepared['objects']}
    objects = {}
    attempts, puts, completions = {}, {}, {}
    active = None
    for event in events[1:]:
        if event.get('event') == 'object_attempt':
            key, facts = event['object_key'], event['facts']
            require(key in allowed and facts == allowed[key], 'prior object outside exact preparation')
            require(active is None and key not in objects, 'ambiguous prior object attempt')
            objects[key] = facts
            active = key
        elif event.get('event') == 'request_attempt':
            number = event['request_id']
            require(type(number) is int and number > 0 and number not in attempts, 'ambiguous prior request attempt')
            attempts[number] = event
            if event['method'] == 'PUT':
                require(active is not None and event.get('object_key') == active and active not in puts
                        and event.get('host') == request['resource']['bucket'] + '.oss-'
                            + request['resource']['region'] + '.aliyuncs.com'
                        and unquote(event.get('path', '')) == '/' + active and event.get('action') == '',
                        'prior PUT outside unique bound object attempt')
                puts[active] = number
        elif event.get('event') == 'object_observed':
            key, facts = event.get('object_key'), event.get('facts')
            readback = event.get('readback', {})
            require(key == active and key in puts and key not in completions and facts == objects[key]
                    and event.get('write_attempted') is True and event.get('readback_verified') is True
                    and isinstance(readback, dict) and readback.get('status') == 200
                    and {k: readback.get(k) for k in ('size', 'sha256', 'cache_control')} == facts,
                    'prior completion differs from unique bound object attempt')
            completions[key] = event.get('put_outcome')
            active = None
    # Headers and a later exact GET do not resolve the original SDK operation.
    unknown = sum(1 for key in puts if completions.get(key) not in ('created', 'already_exists'))
    return objects, unknown, tail, header


def _bound_effect_journal(request, raw, prepared_raw):
    """Parse one bounded version with strict CDN ordering and shared unknown accounting."""
    require(len(raw) <= request['limits']['max_evidence_bytes'], 'prior journal exceeds bound')
    fresh = module('verify-object-storage-delivery-inputs.py')
    lines = raw.splitlines(keepends=True)
    tail = lines.pop() if lines and not lines[-1].endswith(b'\n') else b''
    events = [json.loads(line, object_pairs_hook=fresh.C.reject_duplicate_pairs) for line in lines]
    require(events and isinstance(events[0], dict), 'prior journal header missing')
    if events[0].get('event') == 'run_start':
        objects, unknown, tail, header = _bound_staging_journal(request, raw, prepared_raw)
        return {'objects':objects, 'unknown':unknown, 'unknown_by_kind':{'put':unknown,'configuration':0,'refresh':0},
            'partial_tail':tail, 'header':header, 'cdn_steps':[], 'incomplete':bool(tail)}
    header = events[0]
    require(set(header) == {'event','request_sha256','inputs_sha256','plan_sha256','resource_sha256',
        'preparation_sha256','fresh_initial','intent_sha256','effect_deadline_ns'}
        and header['event'] == 'run_start_v2', 'unsupported effect journal version')
    intent = _cdn_intent(request)
    require(header['request_sha256'] == digest(request) and header['inputs_sha256'] == request['inputs_sha256']
            and header['plan_sha256'] == request['plan_sha256']
            and header['resource_sha256'] == digest(request['resource'])
            and header['intent_sha256'] == digest(intent)
            and type(header['effect_deadline_ns']) is int and header['effect_deadline_ns'] > 0,
            'prior request/plan/resource/intent differs')
    require(hashlib.sha256(prepared_raw).hexdigest() == header['preparation_sha256'], 'prior preparation differs')
    prepared = json.loads(prepared_raw, object_pairs_hook=fresh.C.reject_duplicate_pairs)
    require(prepared['routes'] == intent['routes'], 'prior intent differs from exact prepared routes')
    steps, attempts, results, consumed, parsed, acknowledgements = {}, {}, {}, {}, set(), {}
    next_ordinal = {'configuration':0, 'refresh':0}
    active, current = None, None
    reads = {'GetCallerIdentity','DescribeCdnDomainDetail','DescribeCdnDomainConfigs','DescribeRefreshTaskById'}
    for event in events[1:]:
        require(isinstance(event, dict), 'invalid effect event')
        name = event.get('event')
        if name == 'cdn_step':
            require(active is None and set(event) == {'event','step_id','kind','ordinal','domain',
                'payload_sha256','before_sha256','target_sha256'}, 'ambiguous CDN scope')
            expected, payload = _cdn_scope(request, event['kind'], event['ordinal'])
            step = event['kind'] + ':' + str(event['ordinal'])
            require(event['step_id'] == step and step not in steps and event['ordinal'] == next_ordinal[event['kind']]
                    and {k:v for k,v in event.items() if k not in ('event','step_id')} == expected,
                    'prior CDN scope differs')
            next_ordinal[event['kind']] += 1
            steps[step] = {'scope':expected, 'payload':payload, 'ticket':None, 'ended':False}
            active = step
        elif name == 'cdn_step_end':
            require(set(event) == {'event','step_id'} and active == event['step_id'], 'CDN scope end differs')
            steps[active]['ended'] = True
            active = None
        elif name == 'request_attempt':
            number = event.get('request_id')
            require(type(number) is int and number == len(attempts)+1
                    and number <= request['limits']['max_requests'] and event.get('outcome') == 'unknown'
                    and event.get('effect_deadline_ns') == header['effect_deadline_ns']
                    and event.get('object_key') is None, 'ambiguous prior request attempt')
            fields = {'event','request_id','method','host','path','action','object_key','outcome','effect_deadline_ns'}
            if event.get('action') in CDN_ACTIONS.values():
                require(set(event) == fields | {'step_id','payload_sha256','serialized_request_sha256'}
                        and active == event['step_id'] and active in steps
                        and steps[active]['ticket'] is None and event['method'] == 'POST'
                        and event['host'] == 'cdn.aliyuncs.com' and event['path'] == '/'
                        and event['action'] == steps[active]['payload']['Action']
                        and event['payload_sha256'] == steps[active]['scope']['payload_sha256']
                        and re.fullmatch('[0-9a-f]{64}',event['serialized_request_sha256']), 'prior signed CDN attempt differs')
                steps[active]['ticket'] = number
            else:
                origin = request['resource']['bucket']+'.oss-'+request['resource']['region']+'.aliyuncs.com'
                require(set(event) == fields and active is None
                        and ((event['method'] == 'GET' and event['host'] == origin and event['action'] == '')
                            or (event['method'] == 'POST' and event['action'] in reads and event['path'] == '/'
                                and event['host'] == ('sts.aliyuncs.com' if event['action'] == 'GetCallerIdentity' else 'cdn.aliyuncs.com'))),
                        'unscoped prior effect or read')
            attempts[number] = event
        elif name == 'request_result':
            number = event.get('request_id');status = event.get('status')
            require(set(event) == {'event','request_id','status','outcome'} and type(number) is int and number in attempts and number not in results
                    and (status is None or (type(status) is int and 100 <= status <= 599))
                    and event['outcome'] == ('unknown' if status is None else 'response_received'), 'ambiguous prior response headers')
            results[number] = event
        elif name == 'response_consumed':
            number = event.get('request_id')
            require(set(event) == {'event','request_id','status','bytes','body_sha256'}
                    and type(number) is int and number in results and number not in consumed and 'step_id' in attempts[number]
                    and results[number]['status'] == event['status'] and type(event['bytes']) is int
                    and 0 <= event['bytes'] <= 2*1024**2 and re.fullmatch('[0-9a-f]{64}',event['body_sha256']),
                    'ambiguous prior consumed response')
            consumed[number] = event
        elif name == 'response_parsed':
            number = event.get('request_id')
            require(set(event) == {'event','request_id'} and type(number) is int and number in consumed and number not in parsed
                    and type(consumed[number]['status']) is int and 200 <= consumed[number]['status'] < 300,
                    'prior parsed response lacks consumption')
            parsed.add(number)
        elif name == 'configuration_observed':
            require(set(event) == {'event','observation'} and active is None, 'configuration observation order differs')
            _cdn_snapshot(request, event['observation'])
            current = event['observation']
        elif name == 'cdn_ack':
            number, step = event.get('request_id'), event.get('step_id')
            require(set(event) == {'event','request_id','step_id','facts','original_request_outcome'}
                    and type(number) is int and step in steps and number == steps[step]['ticket'] and number in parsed
                    and number not in acknowledgements and event['original_request_outcome'] == 'acknowledged',
                    'ambiguous prior CDN acknowledgement')
            kind, ordinal = steps[step]['scope']['kind'], steps[step]['scope']['ordinal']
            _cdn_ack_facts(request, kind, ordinal, event['facts'])
            if kind == 'configuration':
                require(current is not None and _configuration_ack_matches(request, ordinal,
                    event['facts']['config_ids'], current), 'prior configuration acknowledgement differs from C1')
            acknowledgements[number] = event
        else:
            raise ExecutionError('unregistered effect journal event')
    unknown = {'put':0,'configuration':0,'refresh':0}
    for number, attempt in attempts.items():
        if 'step_id' in attempt and number not in acknowledgements:
            unknown[steps[attempt['step_id']]['scope']['kind']] += 1
    task_ids = []
    for event in acknowledgements.values():
        for number in event['facts'].get('task_ids', []):
            if number not in task_ids:task_ids.append(number)
    result = {'objects':{}, 'unknown':sum(unknown.values()), 'unknown_by_kind':unknown,
        'partial_tail':tail, 'header':header, 'cdn_steps':list(steps.values()),
        'acknowledged_task_ids':task_ids,
        'acknowledged_refresh_ordinals':[steps[x['step_id']]['scope']['ordinal']
            for x in acknowledgements.values() if 'task_ids' in x['facts']],
        'acknowledged_configuration_requests':[number for number,x in acknowledgements.items() if 'config_ids' in x['facts']],
        'incomplete':bool(tail) or active is not None or any(x['ticket'] not in acknowledgements for x in steps.values())}
    if current is not None:result['configuration_observed_now'] = current
    return result


def _reconcile_staging(request, *, provider, journal_path, journal_sha256, output_dir):
    """Observe exact prior keys/config without retry, rollback or causal rewriting."""
    request = _request(request)
    require(provider.resource == request['resource'], 'reconcile resource differs')
    fresh = module('verify-object-storage-delivery-inputs.py')
    raw = fresh.D._read(Path(journal_path), 'prior execution journal')
    require(hashlib.sha256(raw).hexdigest() == journal_sha256, 'prior journal digest differs')
    prepared_root = Path(request['output_dir'])
    if request['schema'].endswith('/v2'):
        prepared_root = prepared_root / 'staging'
    prepared_path = prepared_root / 'prepared/delivery.json'
    prepared_raw = fresh.D._read(prepared_path, 'prior prepared inventory')
    objects, unknown, tail, header = _bound_staging_journal(request, raw, prepared_raw)
    budget = RunBudget(request['limits'], read_only=True)
    provider.bind_execution_controls(budget=budget)
    fresh_anchor_status = 'verified'
    try:
        _input_bytes(fresh, request)
        fresh.revalidate_delivery_anchors(inputs=Path(request['inputs']),
            expected_plan_sha256=request['plan_sha256'], previous=header['fresh_initial'], budget=budget)
    except Exception:
        # Current drift cannot widen reads, but must not hide prior unknown effects.
        fresh_anchor_status = 'unverified'
    output = Path(output_dir)
    require(output.is_absolute() and not output.exists() and output.parent.is_dir(), 'new reconcile output required')
    fresh.C.validate_candidate_output_paths((output,), (Path(request['output_dir']), Path(request['inputs'])))
    output.mkdir(mode=0o700)
    result = {'schema': 'wukongim.object_storage_reconciliation/v1',
        'status': 'reconciled_read_only' if fresh_anchor_status == 'verified' else 'incomplete',
        'fresh_anchor_status': fresh_anchor_status,
        'request_sha256': digest(request), 'prior_journal_sha256': journal_sha256,
        'resource_sha256': digest(request['resource']), 'original_unknown_outcomes': unknown,
        'partial_tail_bytes': len(tail), 'objects': [], **FALSE_FIELDS}
    try:
        result['resource'] = provider.observe_resource()
        for key, facts in objects.items():
            row = {'object_key': key, 'facts': facts, 'observed_now': 'unknown'}
            result['objects'].append(row)
            try:
                row['readback'] = provider.read_object(key, facts)
                row['observed_now'] = 'exact'
            except Exception:
                pass
        result['configuration_observed_now'] = provider.read_configuration()
    except Exception:
        result['status'] = 'incomplete'
        result['error'] = 'read-only reconciliation incomplete'
    result['budget'] = budget.snapshot()
    require(len(canonical(result)) <= request['limits']['max_evidence_bytes'], 'reconciliation evidence exceeds limit')
    fresh.D._json_write(output / 'reconciliation.json', result)
    return result


def _reconcile_cdn_effects(request, *, provider, journal_path, journal_sha256, output_dir):
    """Observe prior finite CDN scope without retrying or resolving original unknowns."""
    require(provider.resource == request['resource'], 'reconcile resource differs')
    fresh = module('verify-object-storage-delivery-inputs.py')
    raw = fresh.D._read(Path(journal_path), 'prior CDN effect journal')
    require(hashlib.sha256(raw).hexdigest() == journal_sha256, 'prior journal digest differs')
    prepared_raw = fresh.D._read(Path(request['output_dir']) / 'prepared/delivery.json', 'prior CDN preparation')
    prior = _bound_effect_journal(request, raw, prepared_raw)
    require(prior['header']['event'] == 'run_start_v2', 'CDN reconciliation requires scoped journal')
    intent = _cdn_intent(request)
    budget = RunBudget(request['limits'], read_only=True)
    provider.bind_execution_controls(budget=budget)
    fresh_status = 'verified'
    try:
        _input_bytes(fresh, request)
        fresh.revalidate_delivery_anchors(inputs=Path(request['inputs']), expected_plan_sha256=request['plan_sha256'],
            previous=prior['header']['fresh_initial'], budget=budget)
    except Exception:
        fresh_status = 'unverified'
    output = Path(output_dir)
    require(output.is_absolute() and not output.exists() and output.parent.is_dir(), 'new reconcile output required')
    fresh.C.validate_candidate_output_paths((output,), (Path(request['output_dir']), Path(request['inputs'])))
    output.mkdir(mode=0o700)
    missing_ids = [x['scope']['ordinal'] for x in prior['cdn_steps']
        if x['scope']['kind'] == 'refresh' and x['ticket'] is not None
        and x['scope']['ordinal'] not in prior['acknowledged_refresh_ordinals']]
    result = {'schema':'wukongim.cdn_effect_reconciliation/v1', 'status':'incomplete',
        'request_sha256':digest(request), 'prior_journal_sha256':journal_sha256,
        'resource_sha256':digest(request['resource']), 'intent_sha256':digest(intent),
        'preparation_sha256':prior['header']['preparation_sha256'], 'fresh_anchor_status':fresh_status,
        'original_effect_deadline_ns':prior['header']['effect_deadline_ns'],
        'original_unknown_outcomes':prior['unknown'], 'original_unknown_by_kind':prior['unknown_by_kind'],
        'partial_tail_bytes':len(prior['partial_tail']), 'unobservable_refresh_submissions':missing_ids,
        'refresh_observed_now':[], **FALSE_FIELDS}
    try:
        result['resource'] = provider.observe_resource()
        result['configuration_observed_now'] = provider.read_configuration()
        if prior['acknowledged_task_ids']:
            rows = provider._read_refresh_tasks(prior['acknowledged_task_ids'], intent['refresh_urls'])
            result['refresh_observed_now'] = [{key:row[key] for key in ('TaskId','ObjectPath','ObjectType','Status')}
                for row in rows]
        if fresh_status == 'verified' and not prior['incomplete'] and not prior['unknown']:
            result['status'] = 'reconciled_read_only'
    except Exception:
        result['error'] = 'read-only CDN reconciliation incomplete'
    result['budget'] = budget.snapshot()
    text = canonical(result)
    require(not any(marker.encode() in text for marker in provider._credential_markers), 'reconciliation contains credential echo')
    require(len(text) <= request['limits']['max_evidence_bytes'], 'reconciliation evidence exceeds limit')
    fresh.D._json_write(output / 'reconciliation.json', result)
    return result
