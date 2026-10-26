"""Explicit Linux-only owned-process acceptance; never a live SDK/network run."""
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
import shutil
import owned_contract_receipt as receipt_support
OBSERVATIONS=[]
RECEIPT_PATH=None
ROOT=Path(__file__).resolve().parents[2]
SELF=Path(__file__).resolve()

def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    value=importlib.util.module_from_spec(spec);sys.modules[name]=value;spec.loader.exec_module(value);return value

def fixture_worker(mode,fds):
    runtime=load('fixture_owned_worker',ROOT/'scripts/object-storage-owned-execution.py')
    control=runtime._read_pipe(fds[0],runtime.MAX_CONTROL)
    os.close(fds[0]); cr,cw=os.pipe();os.write(cw,runtime.canonical(control));os.close(cw)
    fds[0]=cr
    fixture=load('fixture_execution',ROOT/'tests/provider_sdk/test_object_storage_execution.py')
    case=fixture.StagingExecutionContract('test_verified_materialized_inventory_uses_real_sdk_put_and_complete_get')
    case.setUp()
    inputs=Path(control['request']['inputs']);descriptor=json.loads(inputs.read_text())['current']
    for number,field in enumerate(('archive','receipt'),6001):
        path=(inputs.parent/descriptor[field]).resolve();raw=path.read_bytes()
        case.github.downloads[number]=raw
        case.github.audit_assets[number-6001].update(name=path.name,size=len(raw),digest='sha256:'+__import__('hashlib').sha256(raw).hexdigest())
    original=runtime.module
    active_budget=[]
    def modules(name):
        value=original(name)
        if name=='execute-object-storage-delivery.py':
            init=value.RunBudget.__init__
            def capture(budget,*args,**kwargs):
                init(budget,*args,**kwargs);active_budget.append(budget)
            value.RunBudget.__init__=capture
            def bounded_fixture_command(budget,argv,*,env,**kwargs):
                budget.owned_shared.reserve_process()
                with tempfile.TemporaryFile() as output:
                    result=subprocess.run(argv,env=env,stdout=output,stderr=output,check=False)
                    if argv[0]=='git':raw=result.stdout.encode()
                    else:output.seek(0);raw=output.read(1024*1024+1)
                budget.owned_shared.reserve_output(len(raw))
                return subprocess.CompletedProcess(argv,result.returncode,raw,b'')
            value.RunBudget.run_process=bounded_fixture_command
        return value
    runtime.module=modules
    runtime._make_provider=lambda request,credentials:case.provider
    if mode.startswith('blocked'):
        signal.signal(signal.SIGTERM,signal.SIG_IGN)
        send=case.wire.send
        def block_after_effect(request,**kwargs):
            response=send(request,**kwargs)
            if request.method=='PUT':
                marker=str(Path(control['request']['output_dir'])/'owned-descendants.json')
                code="import os,sys,json,signal,subprocess,time;signal.signal(signal.SIGTERM,signal.SIG_IGN);p=subprocess.Popen([sys.executable,'-c','import signal,time;signal.signal(signal.SIGTERM,signal.SIG_IGN);time.sleep(60)']);open(sys.argv[1],'w').write(json.dumps([os.getpid(),p.pid]));time.sleep(60)"
                shared=active_budget[0].owned_shared
                # Use a private test-only command seam, no executable comes from request JSON.
                runtime.run_fixed_process([sys.executable,'-c',code,marker],env={'PATH':os.defpath},shared=shared)
            return response
        case.wire.send=block_after_effect
    runtime.worker_main(*fds)

def fixture_supervisor(mode,directory,cancel_fd):
    runtime=load('fixture_owned_supervisor',ROOT/'scripts/object-storage-owned-execution.py')
    fixture=load('fixture_supervisor_execution',ROOT/'tests/provider_sdk/test_object_storage_execution.py')
    case=fixture.StagingExecutionContract('test_verified_materialized_inventory_uses_real_sdk_put_and_complete_get');case.setUp()
    request=case.request
    request.update(schema='wukongim.object_storage_execution_request/v2',output_dir=str(Path(directory)/'owned'),
        process_limits={'max_process_output_bytes':4*1024*1024,'max_processes':2000})
    request['limits']['timeout_seconds']=6 if mode=='blocked' and cancel_fd is None else 15
    # Fixture native tools/GitHub remain at their existing subprocess/HTTP seams.
    # Spawn, transport SDK, journal, process group and supervisor are real.
    runtime._worker_command=lambda fds:([str(Path(directory)/'missing-fixture-executable')] if mode=='spawnfail' else [sys.executable,'-B',str(SELF),'--fixture-worker',mode,*map(str,fds)])
    # These fixed private fault seams run only in this isolated test supervisor.
    # Source/worker/SDK effects stay real; only the late verification clock moves.
    real_clock=runtime.time.monotonic_ns
    clock_offset=[0]
    runtime.time.monotonic_ns=lambda:real_clock()+clock_offset[0]
    journal_summary=runtime._journal_summary
    def late_journal(*args,**kwargs):
        value=journal_summary(*args,**kwargs)
        if mode=='late-journal':clock_offset[0]+=60_000_000_000
        return value
    runtime._journal_summary=late_journal
    write_new=runtime._write_new
    def evidence_write(path,value):
        if ((mode=='start-writefail' and path.name=='supervision-start.json')
                or (mode in ('writefail','blocked-writefail') and path.name=='supervision.json')):
            raise OSError('fixture evidence persistence failure')
        write_new(path,value)
        if mode in ('late-write','late-publish') and 'supervision.json' in path.name and value.get('status')=='staged_readback_verified':
            clock_offset[0]+=60_000_000_000
    runtime._write_new=evidence_write
    evidence_publications=[]
    replace=runtime.os.replace
    def observe_evidence_replace(source,target):
        if Path(target).name=='supervision.json':
            content=json.loads(Path(source).read_text())
            evidence_publications.append({'status':content.get('status'),
                'at_ns':runtime.time.monotonic_ns(),'hard_deadline_ns':content.get('hard_deadline_ns')})
        return replace(source,target)
    runtime.os.replace=observe_evidence_replace
    before_fds=len(list(Path('/proc/self/fd').iterdir()))
    result=runtime.supervise_staging(request,temporary_credentials={
        'access_key_id':'FIXTURE-AK','access_key_secret':'FIXTURE-SECRET-NEVER-REAL','security_token':'FIXTURE-TOKEN-NEVER-REAL'},cancel_fd=cancel_fd)
    result['fixture_fd_count_restored']=len(list(Path('/proc/self/fd').iterdir()))==before_fds
    result['fixture_evidence_publications']=evidence_publications
    result['fixture_expected_bindings']={
        'request_sha256':runtime.digest(request),'plan_sha256':request['plan_sha256'],
        'inputs_sha256':request['inputs_sha256'],'resource_sha256':runtime.digest(request['resource']),
        'executor_sha':request['executor_sha']}
    result['fixture_disk_status']=(json.loads((Path(directory)/'owned/supervision.json').read_text()).get('status')
        if (Path(directory)/'owned/supervision.json').exists() else None)
    result['fixture_start_record']=(json.loads((Path(directory)/'owned/supervision-start.json').read_text())
        if (Path(directory)/'owned/supervision-start.json').exists() else None)
    print(json.dumps(result,sort_keys=True));case.doCleanups()

class LinuxOwnedProcessAcceptance(unittest.TestCase):
    def scenario(self,mode,cancel=False):
        with tempfile.TemporaryDirectory() as scratch:
            r,w=os.pipe() if cancel else (None,None)
            args=[sys.executable,'-B',str(SELF),'--fixture-supervisor',mode,scratch,str(r) if r is not None else '-']
            sentinel=subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            self.addCleanup(lambda:(sentinel.terminate(),sentinel.wait(timeout=3)) if sentinel.poll() is None else None)
            process=subprocess.Popen(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                pass_fds=(r,) if r is not None else (),env={**os.environ,'PYTHONDONTWRITEBYTECODE':'1'})
            if r is not None:os.close(r)
            marker=Path(scratch)/'owned/owned-descendants.json'
            if cancel:
                until=time.monotonic()+8
                while not marker.exists() and time.monotonic()<until:time.sleep(.02)
                self.assertTrue(marker.exists(),'actual PUT and nested helper did not reach handshake')
                os.write(w,b'cancel');os.close(w)
            stdout,stderr=process.communicate(timeout=22)
            self.assertEqual(process.returncode,0,stderr.decode(errors='replace'))
            result=json.loads(stdout)
            self.assertIsNone(sentinel.poll(),'unrelated process was affected')
            self.assertTrue(result['fixture_fd_count_restored'])
            self.assertTrue(result['cleanup_verified'])
            if mode in ('normal','blocked'):
                self.assertLess(result['finished_ns'],result['hard_deadline_ns'])
            self.assertFalse(result['publication_verified'])
            if mode.startswith('blocked'):
                self.assertEqual(result['status'],'incomplete')
                self.assertEqual(result['original_unknown_outcomes'],1)
                self.assertEqual(result['first_failure'],'cancelled' if cancel else 'deadline')
                self.assertTrue(marker.exists())
                for pid in json.loads(marker.read_text()):
                    with self.assertRaises(ProcessLookupError):os.kill(pid,0)
            elif mode in ('spawnfail','writefail','start-writefail'):
                self.assertEqual(result['status'],'incomplete')
            elif mode in ('late-journal','late-write','late-publish'):
                self.assertEqual(result['status'],'incomplete','late final verification or evidence fsync cannot complete')
                self.assertEqual(result['fixture_disk_status'],'incomplete')
                self.assertGreaterEqual(result['finished_ns'],result['hard_deadline_ns'])
            else:self.assertEqual(result['status'],'staged_readback_verified')
            if mode not in ('normal','blocked'):
                for key,value in result['fixture_expected_bindings'].items():
                    self.assertEqual(result.get(key),value,'portable binding lost: '+key)
                self.assertIn('effect_deadline_ns',result)
                self.assertIn('hard_deadline_ns',result)
                self.assertIn('worker_pid',result)
                self.assertIn('worker_pgid',result)
                self.assertIn('journal_verified',result)
                self.assertIn('original_unknown_outcomes',result)
                self.assertEqual(result.get('protocol'),'wukongim.owned_worker/v1')
                self.assertIn('output_bounds',result)
                if result['fixture_start_record'] is not None:
                    for key,value in result['fixture_expected_bindings'].items():
                        self.assertEqual(result['fixture_start_record'].get(key),value)
                    self.assertEqual(result['fixture_start_record'].get('protocol'),'wukongim.owned_worker/v1')
                    self.assertIn('output_bounds',result['fixture_start_record'])
                if mode in ('writefail','blocked-writefail'):
                    self.assertIsNotNone(result['worker_pid'])
                    self.assertTrue(result['journal_verified'])
                    self.assertEqual(result['original_unknown_outcomes'],1 if mode.startswith('blocked') else 0)
                if mode in ('spawnfail','start-writefail'):
                    self.assertIsNone(result['worker_pid'])
                    self.assertFalse(result['journal_verified'])
                    self.assertIsNone(result['original_unknown_outcomes'])
            if mode=='late-publish':
                self.assertFalse([event for event in result['fixture_evidence_publications']
                    if event['status']=='staged_readback_verified' and event['at_ns']>=event['hard_deadline_ns']],
                    'a candidate already late after tempfile fsync must not be renamed as success')
            label=mode+('-cancel' if cancel else '')
            if RECEIPT_PATH is not None:
                evidence=RECEIPT_PATH.parent/(RECEIPT_PATH.stem+'-cases')/label
                evidence.mkdir(parents=True,exist_ok=True)
                for relative in ('supervision-start.json','supervision.json','staging/effects.jsonl','staging/execution.json','staging/prepared/delivery.json'):
                    path=Path(scratch)/'owned'/relative
                    if path.is_file():
                        self.assertLessEqual(path.stat().st_size,8*1024*1024)
                        target=evidence/relative;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(path,target)
            OBSERVATIONS.append(result)
            return result
    def test_late_tempfile_is_never_renamed_as_success(self):self.scenario('late-publish')
    def test_final_journal_verification_crossing_deadline_cannot_complete(self):self.scenario('late-journal')
    def test_final_evidence_fsync_crossing_deadline_cannot_complete(self):self.scenario('late-write')
    def test_final_evidence_failure_retains_bound_worker_and_journal(self):self.scenario('writefail')
    def test_start_evidence_failure_retains_available_bindings(self):self.scenario('start-writefail')
    def test_cancelled_evidence_failure_retains_original_cause_and_unknown(self):self.scenario('blocked-writefail',cancel=True)
    def test_spawn_failure_restores_owned_fds_and_persists_incomplete(self):self.scenario('spawnfail')
    def test_actual_sdk_staging_completes_under_owned_deadline(self):self.scenario('normal')
    def test_blocked_sdk_and_nested_helpers_are_killed_and_unknown_survives(self):self.scenario('blocked')
    def test_cancellation_uses_same_owned_cleanup_without_new_effect(self):self.scenario('blocked',cancel=True)

if __name__=='__main__':
    if len(sys.argv)>1 and sys.argv[1]=='--fixture-worker':fixture_worker(sys.argv[2],list(map(int,sys.argv[3:])))
    elif len(sys.argv)>1 and sys.argv[1]=='--fixture-supervisor':fixture_supervisor(sys.argv[2],sys.argv[3],None if sys.argv[4]=='-' else int(sys.argv[4]))
    else:
        arguments=receipt_support.arguments();RECEIPT_PATH=arguments.receipt
        raise SystemExit(receipt_support.run(unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__]),
            receipt=arguments.receipt,kind='linux-owned-staging',observations=OBSERVATIONS,supported=sys.platform=='linux'))
