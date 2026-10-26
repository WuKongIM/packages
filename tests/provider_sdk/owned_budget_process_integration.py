"""Explicit POSIX lock/process contracts; no Linux subreaper claim is made."""
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import time
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('owned_budget_fast_contracts', ROOT / 'tests/test_owned_execution_budget.py')
FAST = importlib.util.module_from_spec(spec)
spec.loader.exec_module(FAST)
B, budget, REQUEST, MODULE = FAST.B, FAST.budget, FAST.REQUEST, FAST.MODULE


class OwnedBudgetProcessContracts(unittest.TestCase):
    def probe(self, shared, action):
        code = r"""import fcntl,json,os,sys
fd=int(sys.argv[1]); kind=sys.argv[2]
try:
 if kind=='flock': fcntl.flock(fd, fcntl.LOCK_EX|fcntl.LOCK_NB)
 else: fcntl.lockf(fd, fcntl.LOCK_EX|fcntl.LOCK_NB, 0, 0, os.SEEK_SET)
 print(json.dumps({'acquired':True,'pid':os.getpid(),'inode':os.fstat(fd).st_ino}))
except BlockingIOError: print(json.dumps({'acquired':False,'pid':os.getpid(),'inode':os.fstat(fd).st_ino}))
"""
        result = subprocess.run([sys.executable, '-B', '-c', code, str(shared.fileno()), action],
            pass_fds=(shared.fileno(),), capture_output=True, text=True, timeout=3)
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def test_real_inherited_record_lock_excludes_but_flock_does_not(self):
        with budget() as shared:
            fd = shared.fileno()
            fcntl.lockf(fd, fcntl.LOCK_EX | fcntl.LOCK_NB, 0, 0, os.SEEK_SET)
            try:
                observation = self.probe(shared, 'record')
                self.assertFalse(observation['acquired'])
                self.assertNotEqual(observation['pid'], os.getpid())
                self.assertEqual(observation['inode'], os.fstat(fd).st_ino)
            finally: fcntl.lockf(fd, fcntl.LOCK_UN, 0, 0, os.SEEK_SET)
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            try: self.assertTrue(self.probe(shared, 'flock')['acquired'])
            finally: fcntl.flock(fd, fcntl.LOCK_UN)

    def test_real_close_alias_demonstrates_record_lock_lifetime_constraint(self):
        with budget() as shared:
            fd = shared.fileno()
            fcntl.lockf(fd, fcntl.LOCK_EX | fcntl.LOCK_NB, 0, 0, os.SEEK_SET)
            alias = os.dup(fd)
            self.assertFalse(self.probe(shared, 'record')['acquired'])
            os.close(alias)
            self.assertTrue(self.probe(shared, 'record')['acquired'])
            fcntl.lockf(fd, fcntl.LOCK_UN, 0, 0, os.SEEK_SET)

    def test_parent_worker_and_nested_helper_have_no_lost_update_or_overcap(self):
        code = r"""import importlib.util,json,os,subprocess,sys,time
path,fd,role=sys.argv[1],int(sys.argv[2]),sys.argv[3]
spec=importlib.util.spec_from_file_location('numeric_child_budget',path)
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
b=m.SharedBudget.attach(fd,expected_request_sha256='a'*64)
child=None
if role=='worker':
 child=subprocess.Popen([sys.executable,'-B','-c',sys.argv[4],path,str(fd),'nested',''],pass_fds=(fd,),stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
 assert child.stdout.readline().strip()=='ready'
print('ready',flush=True); assert sys.stdin.readline().strip()=='go'
if child: child.stdin.write('go\n');child.stdin.flush()
seq=[]
for i in range(1000):
 try: seq.append(b.reserve_output(1))
 except m.BudgetError: break
 time.sleep(.00005)
result={'pid':os.getpid(),'inode':os.fstat(fd).st_ino,'seq':seq}
if child:
 raw,errors=child.communicate(timeout=8);assert child.returncode==0,errors
 result['nested']=json.loads(raw)
print(json.dumps(result),flush=True);b.close()
"""
        with budget() as shared:
            process = subprocess.Popen([sys.executable, '-B', '-c', code, str(MODULE),
                str(shared.fileno()), 'worker', code], pass_fds=(shared.fileno(),),
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            self.addCleanup(lambda: process.poll() is None and (process.kill(), process.wait(timeout=2)))
            self.assertEqual(process.stdout.readline().strip(), 'ready')
            process.stdin.write('go\n'); process.stdin.flush()
            mine = []
            for _ in range(1000):
                try: mine.append(shared.reserve_output(1))
                except B.BudgetError: break
                time.sleep(.00005)
            raw, errors = process.communicate(timeout=8)
            self.assertEqual(process.returncode, 0, errors)
            worker = json.loads(raw)
            nested = worker['nested']
            self.assertEqual(len({os.getpid(), worker['pid'], nested['pid']}), 3)
            self.assertEqual({worker['inode'], nested['inode']}, {os.fstat(shared.fileno()).st_ino})
            self.assertTrue(mine and worker['seq'] and nested['seq'])
            combined = mine + worker['seq'] + nested['seq']
            self.assertEqual(sorted(combined), list(range(1, 1501)))
            self.assertEqual(shared.snapshot()['process_output_bytes'], 1500)

    def test_dead_lock_owner_release_and_committed_reservation_not_reclaimed(self):
        code = r"""import fcntl,os,sys
fd=int(sys.argv[1]);fcntl.lockf(fd,fcntl.LOCK_EX|fcntl.LOCK_NB,0,0,os.SEEK_SET)
print('ready',flush=True);sys.stdin.readline()
"""
        with budget() as shared:
            shared.reserve_output(9)
            child = subprocess.Popen([sys.executable, '-B', '-c', code, str(shared.fileno())],
                pass_fds=(shared.fileno(),), stdout=subprocess.PIPE, stdin=subprocess.PIPE, text=True)
            self.assertEqual(child.stdout.readline().strip(), 'ready')
            child.kill(); child.wait(timeout=3)
            child.stdout.close(); child.stdin.close()
            self.assertEqual(shared.snapshot()['process_output_bytes'], 9)
            self.assertEqual(shared.reserve_output(1), 10)

    def test_real_threads_cannot_access_context_or_attach_another_for_same_inode(self):
        with budget() as shared:
            fd, errors = shared.fileno(), []
            def other_thread():
                try: shared.reserve_output(1)
                except B.BudgetError: errors.append('context')
            def attach_from_thread():
                try: B.SharedBudget.attach(fd, expected_request_sha256=REQUEST)
                except B.BudgetError: errors.append('attach')
            for callback in (other_thread, attach_from_thread):
                thread = threading.Thread(target=callback)
                thread.start(); thread.join(timeout=2)
                self.assertFalse(thread.is_alive())
            self.assertEqual(errors, ['context', 'attach'])
            self.assertEqual(shared.snapshot()['process_output_bytes'], 0)


if __name__ == '__main__':
    import owned_contract_receipt as receipt_support
    arguments=receipt_support.arguments()
    raise SystemExit(receipt_support.run(unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__]),
        receipt=arguments.receipt,kind='posix-record-locks'))
