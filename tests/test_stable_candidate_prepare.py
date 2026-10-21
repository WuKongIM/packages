"""Preparation routing contracts with fake builder I/O, not native package proof."""
from argparse import Namespace
import importlib.util
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest import mock

from test_stable_offline_candidate import CandidateFixture, canonical, C

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('stable_prepare',ROOT/'scripts/prepare-package-site.py')
P=importlib.util.module_from_spec(spec);spec.loader.exec_module(P)

class StablePrepareContracts(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name).resolve();self.f=CandidateFixture(self.root)
        self.builder=self.root/'builder.sh';self.builder.write_bytes(b'#!/bin/sh\nexit 99\n');self.builder.chmod(0o755)
        toolchain_path=self.f.control/'manifests/trusted-toolchain.json'
        toolchain=json.loads(toolchain_path.read_bytes())
        toolchain['files']['scripts/build-native-package-repositories.sh']=C.hash_file(self.builder,'test builder')['sha256']
        toolchain_path.write_bytes(canonical(toolchain))
        self.plan=self.f.plan();(self.root/'plan.json').write_bytes(canonical(self.plan))
        self.args=Namespace(channel='stable',offline_candidate=True,test_only=True,
            control_root=self.f.control,candidate_source_root=self.f.source,
            channels=self.f.control/'manifests/channels.json',plan=self.root/'plan.json',base_root=None,
            source_assets=self.f.source/'assets',bootstrap_manifest=self.f.control/'manifests/bootstrap-packages.json',
            apt_public_cert=self.f.control/'keys/apt-stable.asc',rpm_public_cert=self.f.control/'keys/rpm-stable.asc',
            bootstrap_builder=ROOT/'scripts/build-repository-bootstrap-packages.py',builder=self.builder,
            output=self.root/'output',inventory=self.root/'inventory.json',bootstrap_inventory=self.root/'bootstrap.json')

    def run_fake_builder(self,command,**kwargs):
        args=dict(zip(command[1::2],command[2::2]))
        if Path(command[0])==self.builder:
            self.assertEqual(args['--apt-suite'],'stable');self.assertEqual(args['--rpm-channel'],'stable')
            root=Path(args['--output'])
            for path in Path(args['--packages-dir']).iterdir():
                target=root/('apt/pool/main/w/wukongim' if path.suffix=='.deb' else 'rpm/stable/el/9/x86_64/Packages')/path.name
                target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(path,target)
            return Namespace(returncode=0,stdout=b'',stderr=b'')
        self.assertEqual(args['--channel'],'stable');self.assertEqual(Path(args['--control-root']),self.f.control)
        output=Path(args['--output-dir']);output.mkdir()
        version=json.loads(self.args.bootstrap_manifest.read_bytes())['version'];packages={}
        for family in ('apt','rpm'):
            entry=C.expected_bootstrap_package(family,version,channel='stable');path=output/entry['filename'];path.write_bytes(b'TEST ONLY bootstrap '+family.encode())
            facts=C.hash_file(path,'fixture')
            packages[family]={**entry,'version':version,'source_sha256':facts['sha256'],'source_size':facts['size'],
                              'published_sha256':facts['sha256'],'published_size':facts['size'],'new':True}
        receipt={'schema':'wukongim.stable_bootstrap_preparation/v1','channel':'stable','published':False,'version':version,'packages':packages}
        return Namespace(returncode=0,stdout=canonical(receipt),stderr=b'')

    def test_candidate_uses_pinned_builders_and_stable_paths(self):
        with mock.patch.object(P.subprocess,'run',side_effect=self.run_fake_builder) as runner:
            result=P.prepare(self.args)
        self.assertEqual(runner.call_count,2)
        self.assertEqual(result['schema'],'wukongim.native_package_payload_inventory/v2')
        self.assertIsNone(result['audit_release_id'])
        self.assertEqual(result['payloads']['rpm'][0]['path'],'rpm/stable/el/9/x86_64/Packages/wukongim_3.0.0_linux_amd64.rpm')
        bootstrap=json.loads(self.args.bootstrap_inventory.read_bytes())
        self.assertEqual(bootstrap['schema'],'wukongim.native_package_bootstrap_inventory/v2')
        self.assertEqual(bootstrap['packages']['rpm']['name'],'wukongim-release-stable')

    def test_unpinned_builder_rejected_before_execution(self):
        self.builder.write_bytes(b'#!/bin/sh\nexit 0\n')
        with mock.patch.object(P.subprocess,'run') as runner,self.assertRaisesRegex(ValueError,'builder|SHA'):
            P.prepare(self.args)
        runner.assert_not_called();self.assertFalse(self.args.output.exists())

    def test_candidate_rejects_input_output_overlap(self):
        self.args.output=self.f.source/'nested'
        with mock.patch.object(P.subprocess,'run') as runner,self.assertRaisesRegex(ValueError,'overlap|inside'):
            P.prepare(self.args)
        runner.assert_not_called()

    def test_ancestor_alias_into_inputs_rejected_before_any_builder(self):
        for name,root in (("control",self.f.control),("source",self.f.source)):
            with self.subTest(root=name):
                directory=root/"existing";directory.mkdir(exist_ok=True)
                alias=self.root/(name+"-alias");alias.symlink_to(root,target_is_directory=True)
                self.args.output=alias/"existing"/"new-output"
                self.args.inventory=self.root/(name+"-inventory.json")
                self.args.bootstrap_inventory=self.root/(name+"-bootstrap.json")
                with mock.patch.object(P.subprocess,"run",side_effect=self.run_fake_builder) as runner:
                    with self.assertRaisesRegex(ValueError,"overlap|linked|parent"):
                        P.prepare(self.args)
                    runner.assert_not_called()
                self.assertEqual(list(directory.iterdir()),[])

if __name__=='__main__':unittest.main()
