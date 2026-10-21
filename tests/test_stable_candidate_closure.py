"""Stable layout uses the existing closure engine; these are structural fixtures only."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

from test_compose_package_site import Fixture, canonical, digest

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('stable_closure_composer',ROOT/'scripts/compose-package-site.py')
C=importlib.util.module_from_spec(spec); spec.loader.exec_module(C)

class StableClosureContracts(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.f=Fixture(Path(self.temp.name).resolve())
        self.version='3.0.0'
        self.apt=b'TEST ONLY DEB'; self.rpm=b'TEST ONLY signed RPM'; self.unsigned=b'TEST ONLY unsigned RPM'
        self.f.write_apt({self.version:self.apt},[self.version])
        self.f.write_rpm({self.version:self.rpm},[self.version],[self.version],unsigned_payloads={self.version:self.unsigned})

    def inventory(self,family):
        source=self.apt if family=='apt' else self.unsigned
        return {self.version:{'version':self.version,'path':C.expected_payload_path(family,self.version,channel='stable'),
            'source_sha256':digest(source),'published_sha256':digest(source),'new':True,'indexed':True}}

    def test_stable_apt_closure_and_by_hash_tamper(self):
        (self.f.apt_tree/'dists/preview').rename(self.f.apt_tree/'dists/stable')
        receipt=json.loads(self.f.apt_receipt.read_bytes())
        for entry in receipt['result'].values(): entry['path']=entry['path'].replace('dists/preview/','dists/stable/')
        self.f.apt_receipt.write_bytes(canonical(receipt))
        C.validate_apt_tree(self.f.apt_tree,self.f.apt_receipt,self.inventory('apt'),self.f.bootstrap('apt'),[self.version],[],channel='stable')
        with self.assertRaises(C.CompositionError):
            C.validate_apt_tree(self.f.apt_tree,self.f.apt_receipt,self.inventory('apt'),self.f.bootstrap('apt'),[self.version],[])
        path=next((self.f.apt_tree/'dists/stable/main/binary-amd64/by-hash/SHA256').iterdir()); path.write_bytes(b'tampered')
        with self.assertRaises(C.CompositionError):
            C.validate_apt_tree(self.f.apt_tree,self.f.apt_receipt,self.inventory('apt'),self.f.bootstrap('apt'),[self.version],[],channel='stable')

    def test_stable_rpm_closure_rejects_metadata_tamper(self):
        (self.f.rpm_tree/'preview').rename(self.f.rpm_tree/'stable')
        receipt=json.loads(self.f.rpm_receipt.read_bytes()); receipt['result']['repository']='stable/el/9/x86_64'
        self.f.rpm_receipt.write_bytes(canonical(receipt))
        bootstrap=self.f.bootstrap('rpm'); bootstrap['repository_path']=bootstrap['repository_path'].replace('/preview/','/stable/')
        C.validate_rpm_tree(self.f.rpm_tree,self.f.rpm_receipt,self.inventory('rpm'),bootstrap,[self.version],[],channel='stable')
        with self.assertRaises(C.CompositionError):
            C.validate_rpm_tree(self.f.rpm_tree,self.f.rpm_receipt,self.inventory('rpm'),bootstrap,[self.version],[])
        path=self.f.rpm_tree/'stable/el/9/x86_64/repodata/repomd.xml'; path.write_bytes(path.read_bytes()+b'bad')
        with self.assertRaises(C.CompositionError):
            C.validate_rpm_tree(self.f.rpm_tree,self.f.rpm_receipt,self.inventory('rpm'),bootstrap,[self.version],[],channel='stable')

    def test_stable_bootstrap_inventory_is_not_preview_inventory(self):
        value=json.loads(self.f.bootstrap_inventory.read_bytes())
        value['schema']='wukongim.native_package_bootstrap_inventory/v2'
        for family,item in value['packages'].items():
            item.update(C.expected_bootstrap_package(family,value['version'],channel='stable'))
        C.validate_bootstrap_inventory(value,prepared=True,channel='stable')
        with self.assertRaises(C.CompositionError): C.validate_bootstrap_inventory(value,prepared=True)
        value['packages']['rpm']['name']='wukongim-release'
        with self.assertRaises(C.CompositionError): C.validate_bootstrap_inventory(value,prepared=True,channel='stable')

    def test_stable_entrypoint_is_explicitly_unpublished(self):
        bootstrap=json.loads(self.f.bootstrap_inventory.read_bytes())
        for family,item in bootstrap['packages'].items(): item.update(C.expected_bootstrap_package(family,bootstrap['version'],channel='stable'))
        raw=C.repository_entrypoint_bytes(bootstrap,'a'*64,channel='stable')
        self.assertIn(b'UNPUBLISHED',raw)
        self.assertIn(b'wukongim-release-stable',raw)
        self.assertNotIn(b'Preview repository configured',raw)

if __name__=='__main__': unittest.main()
