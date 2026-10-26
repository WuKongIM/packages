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
from urllib.parse import parse_qs, unquote, urlsplit
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
    def __init__(self, limits, *, clock=time.monotonic, read_only=False):
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
        self.requests = self.get_bytes = self.put_bytes = 0
        self.read_only, self.cancelled, self.journal = read_only, False, None

    def check(self):
        require(not self.cancelled and self.clock() < self.deadline, 'execution deadline or cancellation reached')

    def remaining(self):
        self.check()
        return self.deadline - self.clock()

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
        except Exception:
            self.after_sdk(ticket, None)
            raise
        self.after_sdk(ticket, getattr(response, 'status', 200))
        return _BudgetedResponse(response, self)

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
            return self.journal.before_send(request.method, parsed.hostname, parsed.path, action)
        return None

    def after_sdk(self, ticket, status=None):
        if self.journal is not None and ticket is not None:
            self.journal.after_send(ticket, status)

    def snapshot(self):
        return {'requests': self.requests, 'get_bytes': self.get_bytes, 'put_bytes': self.put_bytes,
            'expired': self.cancelled or self.clock() >= self.deadline, 'limits': copy.deepcopy(self.limits)}


class EffectJournal:
    """Durably bind sanitized attempts before transport; never infer rollback."""
    def __init__(self, path, request, prepared_sha256, initial, budget):
        self.path, self.budget, self.request = path, budget, request
        self.active_object, self.next_id, self.bytes_written = None, 0, 0
        self.fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        self.record({'event': 'run_start', 'request_sha256': digest(request),
            'inputs_sha256': request['inputs_sha256'], 'plan_sha256': request['plan_sha256'],
            'resource_sha256': digest(request['resource']), 'preparation_sha256': prepared_sha256,
            'fresh_initial': initial})

    def record(self, value):
        raw = canonical(value)
        require(self.bytes_written + len(raw) <= self.budget.limits['max_evidence_bytes'] - 2048,
                'execution journal exceeds evidence bound')
        view = memoryview(raw)
        while view:
            count = os.write(self.fd, view)
            require(count > 0, 'execution journal write incomplete')
            view = view[count:]
        os.fsync(self.fd)
        self.bytes_written += len(raw)

    def before_send(self, method, host, path, action):
        reads = {'GetCallerIdentity', 'DescribeCdnDomainDetail', 'DescribeCdnDomainConfigs', 'DescribeRefreshTaskById'}
        require(method == 'GET' or (method == 'POST' and action in reads) or method == 'PUT',
                'staging journal refuses an unscoped effect')
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
            'outcome': 'unknown'})
        return self.next_id

    def after_send(self, ticket, status):
        self.record({'event': 'request_result', 'request_id': ticket, 'status': status,
            'outcome': 'response_received' if status is not None else 'unknown'})

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
    if len(raw) + journal.bytes_written > budget.limits['max_evidence_bytes']:
        receipt = {'schema': 'wukongim.object_storage_execution/v1', 'status': 'incomplete',
            'stage': 'evidence_limit', 'request_sha256': receipt['request_sha256'],
            'journal_path': str(journal.path), 'journal_sha256': receipt['journal_sha256'],
            'omitted_receipt_bytes': len(raw), 'omitted_receipt_sha256': hashlib.sha256(raw).hexdigest(),
            **FALSE_FIELDS}
        require(len(canonical(receipt)) + journal.bytes_written <= budget.limits['max_evidence_bytes'],
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
    require(isinstance(request, dict) and set(request) == fields, 'exact execution request required')
    value = copy.deepcopy(request)
    require(value['schema'] == 'wukongim.object_storage_execution_request/v1'
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
        expected_plan_sha256=request['plan_sha256'], previous=initial, budget=budget)


def _stage_immutable(request, *, provider, budget=None):
    """Execute internal staging after composition-root authority checks.

    This is the actual staging implementation, not an authorization interface.
    Tests exercise its concrete provider through the official SDK HTTP seam.
    The public production entry remains disabled and cannot call it yet.
    """
    request = _request(request)
    budget = budget or RunBudget(request['limits'])
    require(budget.limits == request['limits'], 'budget differs from exact request')
    budget.check()
    provider.bind_execution_controls(budget=budget)
    require(provider.resource == request['resource'], 'provider resource differs from request')
    fresh = module('verify-object-storage-delivery-inputs.py')
    _input_bytes(fresh, request)
    initial = fresh.verify_delivery_inputs(inputs=Path(request['inputs']),
        expected_plan_sha256=request['plan_sha256'], executor_sha=request['executor_sha'], budget=budget)
    output = Path(request['output_dir'])
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
            expected_plan_sha256=request['plan_sha256'], executor_sha=request['executor_sha'], previous=initial, budget=budget)
        receipt.update(status='staged_readback_verified', stage='complete')
    except Exception:
        receipt['error'] = 'staging incomplete; inspect exact recorded attempts'
    budget.journal = None
    return _save_receipt(fresh, output, receipt, budget, journal)



def _reconcile_staging(request, *, provider, journal_path, journal_sha256, output_dir):
    """Observe exact prior keys/config without retry, rollback or causal rewriting."""
    request = _request(request)
    require(provider.resource == request['resource'], 'reconcile resource differs')
    fresh = module('verify-object-storage-delivery-inputs.py')
    raw = fresh.D._read(Path(journal_path), 'prior execution journal')
    require(hashlib.sha256(raw).hexdigest() == journal_sha256, 'prior journal digest differs')
    lines = raw.splitlines(keepends=True)
    tail = lines.pop() if lines and not lines[-1].endswith(b'\n') else b''
    events = [json.loads(line, object_pairs_hook=fresh.C.reject_duplicate_pairs) for line in lines]
    require(events and events[0].get('event') == 'run_start', 'prior journal header missing')
    header = events[0]
    require(header.get('request_sha256') == digest(request)
            and header.get('resource_sha256') == digest(request['resource'])
            and header.get('inputs_sha256') == request['inputs_sha256']
            and header.get('plan_sha256') == request['plan_sha256'], 'prior request/plan/resource differs')
    prepared_path = Path(request['output_dir']) / 'prepared/delivery.json'
    prepared_raw = fresh.D._read(prepared_path, 'prior prepared inventory')
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
