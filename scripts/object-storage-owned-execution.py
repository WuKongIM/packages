"""Internal Linux process containment; neither FDs nor credentials grant authority."""
from __future__ import annotations
import ctypes
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import selectors
import signal
import stat
import subprocess
import sys
import threading
import time

ROOT = Path(__file__).resolve().parent
MAX_CONTROL = 65536
MAX_RESULT = 1024 * 1024
FALSE = dict(production_enabled=False, publication_verified=False,
             cloud_verified=False, github_provenance_verified=False)


def module(name):
    spec = importlib.util.spec_from_file_location('owned_' + name.replace('-', '_'), ROOT / name)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def require(ok, message):
    if not ok:
        raise ValueError(message)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode() + b'\n'


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def run_fixed_process(argv, *, env, shared, stdout_cap=MAX_RESULT, stderr_cap=65536,
                      pass_fds=(), timeout=None):
    """Drain an internally selected fixed command under inherited bounds and PGID."""
    shared.reserve_process()
    deadline = shared.effect_deadline_ns / 1e9
    if timeout is not None:
        deadline = min(deadline, time.monotonic() + timeout)
    require(0 < stdout_cap <= MAX_RESULT and 0 < stderr_cap <= 65536, 'process output cap invalid')
    process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, env=env, close_fds=True, pass_fds=tuple(pass_fds), start_new_session=False, cwd=ROOT.parent)
    selector = None
    output, counts = bytearray(), {'stdout': 0, 'stderr': 0}
    try:
        selector = selectors.DefaultSelector()
        for pipe, name in ((process.stdout, 'stdout'), (process.stderr, 'stderr')):
            os.set_blocking(pipe.fileno(), False)
            selector.register(pipe, selectors.EVENT_READ, name)
        while selector.get_map():
            shared.check()
            require(time.monotonic() < deadline, 'owned process deadline reached')
            for key, unused in selector.select(min(.05, max(0, deadline-time.monotonic()))):
                raw = os.read(key.fileobj.fileno(), 4096)
                if not raw:
                    selector.unregister(key.fileobj)
                    continue
                shared.reserve_output(len(raw))
                name = key.data
                counts[name] += len(raw)
                require(counts[name] <= (stdout_cap if name == 'stdout' else stderr_cap), 'process output exceeds bound')
                if name == 'stdout':
                    output.extend(raw)
        remaining = max(0, deadline-time.monotonic())
        code = process.wait(timeout=remaining)
        shared.check()
        return subprocess.CompletedProcess(argv, code, bytes(output), b'')
    except Exception:
        raise ValueError('bounded owned process failed or output exceeded bound') from None
    finally:
        if selector is not None:
            selector.close()
        process.stdout.close()
        process.stderr.close()
        if process.poll() is None:
            process.kill()
        # The outer supervisor owns remaining descendants; never reset its deadline.
        try:
            process.wait(timeout=max(0, (shared.hard_deadline_ns-time.monotonic_ns())/1e9))
        except subprocess.TimeoutExpired:
            pass


def helper_context(fd, request_sha256):
    """Attach numeric runtime restrictions only; no authority is inferred."""
    require((fd is None) == (request_sha256 is None), 'complete owned helper context required')
    if fd is None:
        return None
    return module('object-storage-owned-budget.py').SharedBudget.attach(fd,
        expected_request_sha256=request_sha256)


def _write_new(path, value):
    raw = canonical(value)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())



def _remember_failure(ownership, code):
    """Keep the first cause; later cleanup/evidence failures remain secondary."""
    if code is None:
        return
    if ownership.get('first_failure') is None:
        ownership['first_failure'] = code
    elif code != ownership['first_failure']:
        secondary = ownership.setdefault('secondary_failures', [])
        if code not in secondary and len(secondary) < 8:
            secondary.append(code)


def _envelope(ownership, *, schema='wukongim.owned_execution/v1'):
    """Retain portable bindings and known facts even before any effect journal."""
    request = ownership['request']
    process = ownership.get('process')
    result = {'schema':schema, 'status':'incomplete',
        'request_sha256':digest(request), 'plan_sha256':request['plan_sha256'],
        'inputs_sha256':request['inputs_sha256'], 'resource_sha256':digest(request['resource']),
        'executor_sha':request['executor_sha'], 'protocol':'wukongim.owned_worker/v1',
        'supervisor_pid':os.getpid(), 'worker_pid':process.pid if process is not None else None,
        'worker_pgid':process.pid if process is not None else None,
        'started_ns':ownership.get('started'), 'effect_deadline_ns':ownership.get('effect'),
        'hard_deadline_ns':ownership.get('hard'), 'output_identity':ownership.get('output_identity'),
        'output_bounds':{**request['process_limits'], 'max_evidence_bytes':request['limits']['max_evidence_bytes'],
            'max_control_bytes':MAX_CONTROL, 'max_result_bytes':MAX_RESULT},
        'cleanup_verified':process is None, 'journal_verified':False,
        'original_unknown_outcomes':None, **FALSE}
    result.update(ownership.get('facts', {}))
    # An exception cannot promote a cached successful candidate.
    result['status'] = 'incomplete'
    result['first_failure'] = ownership.get('first_failure')
    result['secondary_failures'] = list(ownership.get('secondary_failures', []))
    return result


class _LateEvidence(ValueError):
    """A successful tempfile was already late before its owned rename."""


def _replace_evidence(path, value):
    """Atomically replace only this run's owned final receipt, with bounded IO."""
    temporary = path.with_name('.'+path.name+'.'+os.urandom(8).hex())
    try:
        _write_new(temporary, value)
        if value.get('status') == 'staged_readback_verified':
            hard = value.get('hard_deadline_ns')
            require(type(hard) is int, 'successful evidence requires an absolute deadline')
            if time.monotonic_ns() >= hard:
                raise _LateEvidence('successful evidence exceeded deadline before rename')
        os.replace(temporary, path)
        descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    finally:
        try: temporary.unlink()
        except FileNotFoundError: pass


def _finalize_evidence(ownership, candidate):
    """Gate success after verification and each final persistence completion."""
    result = _envelope(ownership)
    hard = ownership['hard']
    def checkpoint():
        result['finished_ns'] = time.monotonic_ns()
        if result['finished_ns'] >= hard:
            _remember_failure(ownership, 'hard_deadline')
        result['first_failure'] = ownership.get('first_failure')
        result['secondary_failures'] = list(ownership.get('secondary_failures', []))
        ownership['facts'].update(result)
    checkpoint()
    path = ownership['output']/'supervision.json'
    require(len(canonical(result)) <= 4096, 'supervision evidence exceeds bound')
    # A crash or failure before the post-fsync check leaves an incomplete record.
    _write_new(path, result)
    result['evidence_persisted'] = True
    checkpoint()
    if candidate == 'staged_readback_verified' and ownership.get('first_failure') is None:
        result['status'] = candidate
    # The commit contains a timestamp sampled after the initial evidence fsync.
    try:
        _replace_evidence(path, result)
    except _LateEvidence:
        _remember_failure(ownership, 'hard_deadline')
        result['status'] = 'incomplete'
        checkpoint()
        # Write fresh incomplete bytes; the expired success tempfile was removed.
        _replace_evidence(path, result)
    checkpoint()
    if result['status'] == 'staged_readback_verified' and ownership.get('first_failure') is not None:
        result['status'] = 'incomplete'
        # A late commit is explicitly downgraded; it cannot remain a success file.
        _replace_evidence(path, result)
        checkpoint()
    ownership['facts'].update(result)
    return result

def _read_pipe(fd, maximum):
    raw = bytearray()
    while True:
        chunk = os.read(fd, min(4096, maximum+1-len(raw)))
        if not chunk:
            break
        raw.extend(chunk)
        require(len(raw) <= maximum, 'owned pipe exceeds bound')
    return json.loads(raw, object_pairs_hook=_unique_pairs)


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate owned protocol field')
        result[key] = value
    return result


def _make_provider(request, credentials):
    return module('aliyun-object-storage-provider.py').Provider(resource=request['resource'],
        access_key_id=credentials['access_key_id'], access_key_secret=credentials['access_key_secret'],
        security_token=credentials['security_token'])


def worker_main(control_fd, credential_fd, result_fd, budget_fd, root_fd):
    """Run actual staging with exact transient inputs in an owned child session."""
    provider = shared = None
    result = {'status': 'incomplete', 'error': 'owned worker incomplete', **FALSE}
    try:
        control = _read_pipe(control_fd, MAX_CONTROL)
        credentials = _read_pipe(credential_fd, 16384)
        os.close(control_fd)
        os.close(credential_fd)
        request = control['request']
        require(digest(request) == control['request_sha256'], 'owned request digest differs')
        shared = helper_context(budget_fd, control['request_sha256'])
        shared.check()
        metadata = os.fstat(root_fd)
        actual = os.stat(request['output_dir'], follow_symlinks=False)
        require(stat.S_ISDIR(actual.st_mode) and (metadata.st_dev, metadata.st_ino) ==
                (actual.st_dev, actual.st_ino) == tuple(control['output_identity']), 'owned output identity differs')
        execution = module('execute-object-storage-delivery.py')
        budget = execution.RunBudget(request['limits'], owned_shared=shared,
            absolute_deadline=shared.effect_deadline_ns / 1e9)
        budget.owned_root_identity = (metadata.st_dev, metadata.st_ino)
        signal.signal(signal.SIGTERM, lambda _signum, _frame: setattr(budget, 'cancelled', True))
        signal.signal(signal.SIGINT, lambda _signum, _frame: setattr(budget, 'cancelled', True))
        budget.source_token = credentials.get('source_token')
        budget.package_token = credentials.get('package_token')
        provider = _make_provider(request, credentials)
        result = execution._stage_immutable(request, provider=provider, budget=budget)
        result = {'request_sha256': control['request_sha256'], 'status': result['status'],
            'execution_path': str(Path(request['output_dir'])/'staging/execution.json'), **FALSE}
    except Exception:
        pass
    finally:
        if provider is not None:
            provider.close()
        if shared is not None:
            shared.close()
        os.close(root_fd)
    raw = canonical(result)
    require(len(raw) <= MAX_RESULT, 'owned result exceeds bound')
    while raw:
        count = os.write(result_fd, raw)
        require(count > 0, 'owned result write incomplete')
        raw = raw[count:]
    os.close(result_fd)


def _worker_command(fds):
    """Fixed reviewed executable; request/environment cannot choose code."""
    return [sys.executable, '-B', str(Path(__file__).resolve()), '--owned-worker', *map(str, fds)]


def _journal_summary(output, request, maximum):
    path = output/'staging/effects.jsonl'
    if not path.exists():
        return {'journal_verified': False, 'original_unknown_outcomes': None}
    metadata = path.lstat()
    require(stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1 and metadata.st_size <= maximum,
            'owned journal exceeds bound')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as stream:
        raw = stream.read(maximum+1)
    require(len(raw) <= maximum, 'owned journal exceeds bound')
    execution = module('execute-object-storage-delivery.py')
    fresh = module('verify-object-storage-delivery-inputs.py')
    prepared_raw = fresh.D._read(output/'staging/prepared/delivery.json', 'owned prepared inventory')
    journal = execution._bound_effect_journal(request, raw, prepared_raw)
    return {'journal_verified': True, 'journal_path': str(path),
        'journal_sha256': hashlib.sha256(raw).hexdigest(), 'partial_tail_bytes': len(journal['partial_tail']),
        'original_unknown_outcomes': journal['unknown']}



def _supervise_staging(request, *, temporary_credentials, cancel_fd=None, ownership):
    """Contain internal staging; the public production entry remains disabled."""
    require(sys.platform == 'linux', 'owned process execution requires Linux')
    require(threading.active_count() == 1, 'dedicated single-thread supervisor required')
    children = Path('/proc/self/task/'+str(os.getpid())+'/children').read_text()
    require(not children.strip(), 'dedicated supervisor must not own unrelated children')
    def own_fd(fd):
        ownership['fds'].add(fd)
        return fd
    def close_fd(fd):
        ownership['fds'].discard(fd)
        os.close(fd)
    started = time.monotonic_ns()
    ownership['started'] = started
    execution = module('execute-object-storage-delivery.py')
    request = execution._request(request)
    ownership['request'] = request
    require(request['schema'].endswith('/v2'), 'owned v2 request required')
    execution.RunBudget(request['limits'])
    seconds = request['limits']['timeout_seconds']
    require(seconds >= 1, 'owned timeout too short')
    require(request['limits']['max_evidence_bytes'] >= 16384, 'owned evidence reserve too small')
    hard = started + int(seconds*1e9)
    ownership['hard'] = hard
    effect = hard - min(2_000_000_000, int(seconds*1e9/5))
    ownership['effect'] = effect
    process_limits = request['process_limits']
    require(set(process_limits) == {'max_process_output_bytes','max_processes'}, 'exact process limits required')
    credentials = canonical(temporary_credentials)
    require(len(credentials) <= 16384 and isinstance(temporary_credentials, dict)
        and set(temporary_credentials) <= {'access_key_id','access_key_secret','security_token','source_token','package_token'}
        and all(isinstance(temporary_credentials.get(k), str) and temporary_credentials[k]
                for k in ('access_key_id','access_key_secret','security_token')), 'explicit bounded temporary credentials required')
    output = Path(request['output_dir'])
    require(not output.exists() and output.parent.is_dir(), 'owned output must be new')
    fresh = module('verify-object-storage-delivery-inputs.py')
    fresh.C.validate_candidate_output_paths((output,), (Path(request['inputs']),))
    shared = module('object-storage-owned-budget.py').SharedBudget.create(
        request_sha256=digest(request), effect_deadline_ns=effect, hard_deadline_ns=hard, **process_limits)
    ownership['shared'] = shared
    # Linux adoption applies only to this explicitly isolated process.
    require(ctypes.CDLL(None, use_errno=True).prctl(36, 1, 0, 0, 0) == 0, 'cannot establish owned subreaper')
    output.mkdir(mode=0o700)
    ownership['output'] = output
    root_fd = own_fd(os.open(output, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW))
    metadata = os.fstat(root_fd)
    ownership['output_identity'] = (metadata.st_dev, metadata.st_ino)
    _write_new(output/'supervision-start.json',
        _envelope(ownership, schema='wukongim.owned_execution_start/v1'))
    cr, cw = os.pipe(); ownership['fds'].update((cr,cw))
    kr, kw = os.pipe(); ownership['fds'].update((kr,kw))
    rr, rw = os.pipe(); ownership['fds'].update((rr,rw))
    fds = (cr, kr, rw, shared.fileno(), root_fd)
    control = canonical({'request':request,'request_sha256':digest(request),
        'output_identity':[metadata.st_dev, metadata.st_ino]})
    require(len(control) <= MAX_CONTROL, 'owned control too large')
    shared.reserve_process()
    process = subprocess.Popen(_worker_command(fds), stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env={'PATH':os.environ.get('PATH',os.defpath),
        'PYTHONNOUSERSITE':'1','PYTHONDONTWRITEBYTECODE':'1'}, close_fds=True,
        pass_fds=fds, start_new_session=True)
    ownership['process'] = process
    for fd in (cr, kr, rw):
        close_fd(fd)
    selector = selectors.DefaultSelector()
    ownership['selectors'].append(selector)
    pending = {cw:control, kw:credentials}
    for fd in pending:
        os.set_blocking(fd, False); selector.register(fd, selectors.EVENT_WRITE, 'input')
    os.set_blocking(rr, False); selector.register(rr, selectors.EVENT_READ, 'result')
    if cancel_fd is not None:
        selector.register(cancel_fd, selectors.EVENT_READ, 'cancel')
    raw, reason, worker_done = bytearray(), None, False
    try:
        while time.monotonic_ns() < effect and reason is None:
            status = os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
            worker_done = status is not None
            if worker_done and rr not in [k.fd for k in selector.get_map().values()]:
                break
            for key, unused in selector.select(min(.05, max(0,(effect-time.monotonic_ns())/1e9))):
                if key.data == 'cancel':
                    reason = 'cancelled'; break
                if key.data == 'input':
                    try:
                        n = os.write(key.fd, pending[key.fd])
                        pending[key.fd] = pending[key.fd][n:]
                    except BrokenPipeError:
                        reason = 'worker_protocol'; break
                    if not pending[key.fd]:
                        selector.unregister(key.fd); close_fd(key.fd); pending.pop(key.fd)
                else:
                    chunk = os.read(rr, 4096)
                    raw.extend(chunk)
                    if len(raw) > MAX_RESULT:
                        reason = 'worker_output_limit'; break
                    if not chunk:
                        selector.unregister(rr); close_fd(rr)
        if reason is None and time.monotonic_ns() >= effect:
            reason = 'deadline'
        _remember_failure(ownership, reason)
    finally:
        # Cancellation never waits for the shared record lock to stop owned work.
        if reason is not None or not worker_done:
            try: shared.try_cancel()
            except Exception: pass
        # Leader stays waitable until group termination, so PGID cannot be reused.
        try: os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError: pass
        grace = min(hard, time.monotonic_ns()+min(250_000_000,(hard-effect)//4))
        while time.monotonic_ns() < grace:
            if reason is not None or not worker_done:
                try: shared.try_cancel()
                except Exception: pass
            # The dedicated owner may have adopted helper grandchildren.
            time.sleep(min(.01, max(0,(grace-time.monotonic_ns())/1e9)))
        try: os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError: pass
        ownership['group_killed'] = True
        reaped, cleanup = [], False
        while time.monotonic_ns() < hard:
            try:
                pid, status = os.waitpid(-1, os.WNOHANG)
            except ChildProcessError:
                cleanup = True; break
            if pid:
                reaped.append({'pid':pid,'status':status})
                if pid == process.pid:
                    process.returncode = os.waitstatus_to_exitcode(status)
            else:
                time.sleep(min(.01,max(0,(hard-time.monotonic_ns())/1e9)))
        for key in list(selector.get_map().values()):
            selector.unregister(key.fd)
            if key.data != 'cancel':
                close_fd(key.fd)
        selector.close(); close_fd(root_fd)
        ownership['cleaned'] = True
        ownership['facts'].update(cleanup_verified=cleanup, reaped=reaped[:16],
            reaped_total=len(reaped), reaped_sha256=digest(reaped))
    facts = ownership['facts']
    try:
        facts['process_budget'] = shared.snapshot()
        facts['budget_verified'] = True
    except Exception:
        facts['budget_verified'] = False
        _remember_failure(ownership, 'budget_unverified')
    shared.close()
    try:
        facts.update(_journal_summary(output, request, request['limits']['max_evidence_bytes']-4096))
    except Exception:
        facts.update(journal_verified=False, original_unknown_outcomes=None)
        _remember_failure(ownership, 'journal_unverified')
    candidate = 'incomplete'
    try:
        child = json.loads(raw, object_pairs_hook=_unique_pairs)
        require(child.get('request_sha256') == digest(request)
            and child.get('status') in ('staged_readback_verified','incomplete')
            and all(child.get(key) is False for key in FALSE), 'worker result differs')
        if (ownership.get('first_failure') is None and cleanup and process.returncode == 0
                and facts.get('journal_verified') is True and facts.get('budget_verified') is True):
            candidate = child['status']
        if child['status'] == 'incomplete':
            _remember_failure(ownership, 'worker_incomplete')
    except Exception:
        _remember_failure(ownership, 'worker_protocol')
    return _finalize_evidence(ownership, candidate)


def supervise_staging(request, *, temporary_credentials, cancel_fd=None):
    """Own startup failures as well as the successful worker lifecycle."""
    ownership = {'fds':set(), 'shared':None, 'process':None, 'cleaned':False, 'selectors':[], 'facts':{}}
    outcome = None
    try:
        outcome = _supervise_staging(request, temporary_credentials=temporary_credentials,
            cancel_fd=cancel_fd, ownership=ownership)
        return outcome
    except Exception:
        if 'output' not in ownership:
            raise
        _remember_failure(ownership, 'owned_evidence_failure' if ownership.get('cleaned') else 'owned_startup_failure')
        process = ownership['process']
        if process is not None and not ownership['cleaned']:
            if not ownership.get('group_killed'):
                try: os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError: pass
            cleanup = False
            while time.monotonic_ns() < ownership['hard']:
                try:
                    pid, unused = os.waitpid(-1, os.WNOHANG)
                except ChildProcessError:
                    cleanup = True; break
                if not pid: time.sleep(.005)
            ownership['facts']['cleanup_verified'] = cleanup
        facts = ownership['facts']
        if 'process_budget' not in facts and ownership['shared'] is not None:
            try:
                facts['process_budget'] = ownership['shared'].snapshot()
                facts['budget_verified'] = True
            except Exception:
                facts['budget_verified'] = False
        if 'journal_verified' not in facts:
            try:
                facts.update(_journal_summary(ownership['output'], ownership['request'],
                    ownership['request']['limits']['max_evidence_bytes']-4096))
            except Exception:
                facts.update(journal_verified=False, original_unknown_outcomes=None)
        result = _envelope(ownership)
        result['finished_ns'] = time.monotonic_ns()
        result['evidence_persisted'] = True
        path = ownership['output']/'supervision.json'
        try:
            require(len(canonical(result)) <= 4096, 'supervision evidence exceeds bound')
            _replace_evidence(path, result)
        except Exception:
            result['evidence_persisted'] = False
            # Never knowingly leave this call's unverified success candidate.
            try: path.unlink()
            except OSError: pass
        result['finished_ns'] = time.monotonic_ns()
        outcome = result
        return result
    finally:
        close_failed = False
        for selector in ownership['selectors']:
            try: selector.close()
            except Exception: close_failed = True
        for fd in ownership['fds']:
            try: os.close(fd)
            except OSError: close_failed = True
        if ownership['shared'] is not None:
            try: ownership['shared'].close()
            except Exception: close_failed = True
        if outcome is not None:
            outcome['finished_ns'] = time.monotonic_ns()
            if close_failed:
                _remember_failure(ownership, 'owned_close_failure')
            late = outcome['finished_ns'] >= ownership['hard']
            if late:
                _remember_failure(ownership, 'hard_deadline')
            if close_failed or (late and outcome['status'] == 'staged_readback_verified'):
                outcome.update(status='incomplete', first_failure=ownership.get('first_failure'),
                    secondary_failures=list(ownership.get('secondary_failures', [])))
                path = ownership['output']/'supervision.json'
                try: _replace_evidence(path, outcome)
                except Exception:
                    outcome['evidence_persisted'] = False
                    try: path.unlink()
                    except OSError: pass
                outcome['finished_ns'] = time.monotonic_ns()


if __name__ == '__main__':
    require(len(sys.argv) == 7 and sys.argv[1] == '--owned-worker', 'internal owned worker protocol required')
    worker_main(*map(int, sys.argv[2:]))
