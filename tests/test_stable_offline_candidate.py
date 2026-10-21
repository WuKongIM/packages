"""Input/identity contracts; native signatures are exercised by the Linux drill."""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('stable_candidate_composer', ROOT/'scripts/compose-package-site.py')
C = importlib.util.module_from_spec(spec)
spec.loader.exec_module(C)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()+b'\n'


class CandidateFixture:
    def __init__(self, root):
        self.root = root
        self.control = root/'control'
        for directory in ('manifests', 'keys'):
            shutil.copytree(ROOT/directory, self.control/directory)
        self.source = root/'source'
        (self.source/'assets').mkdir(parents=True)
        self.assets=[]
        for suffix in ('deb', 'rpm'):
            name=f'wukongim_3.0.0_linux_amd64.{suffix}'
            raw=f'TEST ONLY {suffix}'.encode()
            (self.source/'assets'/name).write_bytes(raw)
            self.assets.append({'name': name, 'id': None, 'size': len(raw),
                                'sha256': hashlib.sha256(raw).hexdigest()})
        self.resolution={'schema':'wukongim/test-source-fixture/v1','version':'3.0.0',
                         'source_sha':None,'release_id':None,'assets':self.assets}
        self.write_resolution()

    def write_resolution(self):
        (self.source/'resolution.json').write_bytes(canonical(self.resolution))

    def plan(self):
        return C.build_candidate_plan(self.control, self.source, None, test_only=True)


class StableCandidateContracts(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.f=CandidateFixture(Path(self.temp.name).resolve())

    def test_fixture_plan_preserves_nonpublication_identity(self):
        plan=self.f.plan()
        self.assertEqual(plan['schema'],'wukongim.native_package_publication_plan/v2')
        self.assertEqual(plan['candidate']['stage'],'offline_candidate')
        self.assertEqual(plan['candidate']['channel'],'stable')
        self.assertIs(plan['candidate']['test_only'],True)
        for key in ('audit_release_id','base_audit_release_id','control_sha'):
            self.assertIsNone(plan[key])
        self.assertIsNone(plan['release']['package_release_id'])
        self.assertIsNone(plan['release']['source_sha'])
        self.assertIsNone(plan['release']['source_release_id'])
        self.assertEqual(plan['active_versions'],['3.0.0'])
        self.assertEqual(plan['retained_versions'],[])
        C.validate_candidate_plan(plan,self.f.control,self.f.source,test_only=True)

    def test_fixture_never_accepted_as_production_source(self):
        with self.assertRaisesRegex(C.CompositionError,'fixture|production|TEST ONLY'):
            C.build_candidate_plan(self.f.control,self.f.source,'1'*40,test_only=False)

    def test_false_source_id_or_sha_rejected(self):
        for field,value in [('source_sha','1'*40),('release_id',1),('release_id',True)]:
            with self.subTest(field=field,value=value):
                self.f.resolution[field]=value; self.f.write_resolution()
                with self.assertRaises(C.CompositionError): self.f.plan()
                self.f.resolution[field]=None
        self.f.resolution['assets'][0]['id']=1; self.f.write_resolution()
        with self.assertRaises(C.CompositionError): self.f.plan()

    def test_first_generation_rejects_nonstable_versions(self):
        for version in ['3.0.0-beta.1','3.0.0+build','03.0.0','3.0','v3.0.0']:
            with self.subTest(version=version):
                self.f.resolution['version']=version; self.f.write_resolution()
                with self.assertRaises(C.CompositionError): self.f.plan()

    def test_source_closure_mutation_extra_symlink_hardlink_rejected(self):
        asset=self.f.source/'assets'/self.f.assets[0]['name']; raw=asset.read_bytes()
        asset.write_bytes(raw+b'changed')
        with self.assertRaises(C.CompositionError): self.f.plan()
        asset.write_bytes(raw)
        extra=self.f.source/'unexpected'; extra.write_text('extra')
        with self.assertRaises(C.CompositionError): self.f.plan()
        extra.unlink()
        asset.unlink(); asset.symlink_to(self.f.source/'resolution.json')
        with self.assertRaises(C.CompositionError): self.f.plan()
        asset.unlink(); asset.hardlink_to(self.f.source/'resolution.json')
        with self.assertRaises(C.CompositionError): self.f.plan()

    def test_duplicate_unknown_and_bool_size_rejected(self):
        self.f.resolution['assets'][0]['size']=True; self.f.write_resolution()
        with self.assertRaises(C.CompositionError): self.f.plan()
        self.f.resolution['assets'][0]['size']=len(b'TEST ONLY deb')
        self.f.resolution['unknown']=True; self.f.write_resolution()
        with self.assertRaises(C.CompositionError): self.f.plan()
        (self.f.source/'resolution.json').write_bytes(b'{"schema":1,"schema":2}')
        with self.assertRaises(C.CompositionError): self.f.plan()

    def test_stable_enabled_or_missing_roles_rejected(self):
        path=self.f.control/'manifests/channels.json'; raw=path.read_bytes()
        value=json.loads(raw); value['channels']['stable']['enabled']=True
        path.write_bytes(canonical(value))
        with self.assertRaises(C.CompositionError): self.f.plan()
        path.write_bytes(raw)
        (self.f.control/'manifests/stable-public-keys.json').unlink()
        with self.assertRaises(C.CompositionError): self.f.plan()

    def test_plan_and_external_anchor_changes_rejected(self):
        plan=self.f.plan()
        for field,value in [('audit_release_id',12),('base_audit_release_id',12),
                            ('operation','remove_indexes'),('retained_versions',['2.0.0'])]:
            changed=copy.deepcopy(plan); changed[field]=value
            with self.subTest(field=field),self.assertRaises(C.CompositionError):
                C.validate_candidate_plan(changed,self.f.control,self.f.source,test_only=True)
        for field,value in [('stage','sealed'),('test_only',False),('channel','preview')]:
            changed=copy.deepcopy(plan); changed['candidate'][field]=value
            with self.subTest(field=field),self.assertRaises(C.CompositionError):
                C.validate_candidate_plan(changed,self.f.control,self.f.source,test_only=True)
        path=self.f.control/'manifests/bootstrap-packages.json'
        path.write_bytes(path.read_bytes()+b' ')
        with self.assertRaises(C.CompositionError):
            C.validate_candidate_plan(plan,self.f.control,self.f.source,test_only=True)

    def test_stable_layout_does_not_change_preview_default(self):
        self.assertEqual(C.expected_payload_path('rpm','3.0.0',channel='stable'),
                         'rpm/stable/el/9/x86_64/Packages/wukongim_3.0.0_linux_amd64.rpm')
        self.assertEqual(C.expected_bootstrap_package('rpm','1.1.0',channel='stable')['name'],
                         'wukongim-release-stable')
        self.assertEqual(C.expected_bootstrap_package('rpm','1.1.0')['name'],'wukongim-release')
        with self.assertRaises(C.CompositionError):
            C.validate_plan(self.f.plan(),{'publication':{}})

    def test_production_consumers_require_explicit_opt_in(self):
        plan=self.f.plan(); path=self.f.root/'plan.json'; path.write_bytes(canonical(plan))
        p=subprocess.run([sys.executable,str(ROOT/'scripts/plan-package-publication.py'),
            '--channels',str(self.f.control/'manifests/channels.json'),
            '--control-root',str(self.f.control),'--candidate-source-root',str(self.f.source),
            '--channel','stable','--offline-candidate','--test-only'],capture_output=True,timeout=10)
        self.assertEqual(p.returncode,0,p.stderr.decode())
        self.assertEqual(json.loads(p.stdout),plan)
        p=subprocess.run([sys.executable,str(ROOT/'scripts/plan-package-publication.py'),
            '--channels',str(self.f.control/'manifests/channels.json'),
            '--control-root',str(self.f.control),'--candidate-source-root',str(self.f.source),
            '--channel','stable','--test-only'],capture_output=True,timeout=10)
        self.assertNotEqual(p.returncode,0)


if __name__ == '__main__': unittest.main()
