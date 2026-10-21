"""Candidate audit opt-in is separate from the sealed preview receipt schema."""
import importlib.util
import tempfile
from pathlib import Path
import unittest

from test_stable_offline_candidate import CandidateFixture, canonical

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('stable_audit',ROOT/'scripts/package-audit-receipt.py')
A=importlib.util.module_from_spec(spec);spec.loader.exec_module(A)

class StableCandidateAuditContracts(unittest.TestCase):
    def test_explicit_candidate_parser_keeps_external_inputs(self):
        args=A._parser().parse_args(['create','--channels','channels','--signing','signing',
            '--signing-toolchain','toolchain','--apt-public-cert','apt','--rpm-public-cert','rpm',
            '--plan','plan','--apt-receipt','apt-receipt','--rpm-receipt','rpm-receipt','--archive','archive',
            '--output','output','--channel','stable','--offline-candidate','--control-root','control',
            '--candidate-source-root','source','--test-only'])
        self.assertTrue(args.offline_candidate);self.assertTrue(args.test_only)
        self.assertEqual(args.control_root,Path('control'));self.assertEqual(args.plan,Path('plan'))

    def test_unsealed_candidate_is_not_a_legacy_external_receipt(self):
        with self.assertRaises(A.AuditReceiptError):
            A.validate_external_receipt({'schema':'wukongim/package-audit-receipt/v3',
                'stage':'offline_candidate','audit_release_id':None})

    def test_malformed_candidate_archive_has_controlled_audit_error(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary).resolve();fixture=CandidateFixture(root)
            plan=root/'plan.json';plan.write_bytes(canonical(fixture.plan()))
            archive=root/'malformed.tar';archive.write_bytes(b'TEST ONLY invalid archive')
            with self.assertRaisesRegex(A.AuditReceiptError, 'package archive validation failed'):
                A.build_audit_receipt(
                    channels_path=fixture.control/'manifests/channels.json',
                    signing_path=fixture.control/'manifests/stable-public-keys.json',
                    signing_toolchain_path=fixture.control/'manifests/signing-toolchain.json',
                    apt_public_cert_path=fixture.control/'keys/apt-stable.asc',
                    rpm_public_cert_path=fixture.control/'keys/rpm-stable.asc',
                    source_attestations_path=None,plan_path=plan,
                    apt_receipt_path=root/'apt.json',rpm_receipt_path=root/'rpm.json',
                    archive_path=archive,channel='stable',offline_candidate=True,
                    control_root=fixture.control,candidate_source_root=fixture.source,test_only=True)

    def test_names_bind_version_snapshot_without_fictitious_release_id(self):
        names=A.candidate_archive_names('3.0.0','a'*64)
        self.assertEqual(names,('wukongim-stable-3.0.0-'+'a'*64+'-candidate-site.tar',
                               'wukongim-stable-3.0.0-'+'a'*64+'-candidate-receipt.json'))
        for version,sha in [('3.0.0-rc.1','a'*64),('../3.0.0','a'*64),('3.0.0','a'*63)]:
            with self.subTest(version=version,sha=sha),self.assertRaises(A.AuditReceiptError):
                A.candidate_archive_names(version,sha)

if __name__=='__main__':unittest.main()
