"""Explicit verifier boundary and existing header engine parameterization."""
from datetime import datetime, timezone
from email.utils import format_datetime
import importlib.util
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('stable_verifier',ROOT/'scripts/verify-production-package-site.py')
V=importlib.util.module_from_spec(spec);spec.loader.exec_module(V)

class StableVerifierContracts(unittest.TestCase):
    def test_stable_release_headers_use_same_strict_allowlist(self):
        data=('Origin: WuKongIM\nLabel: WuKongIM\nSuite: stable\nCodename: stable\nArchitectures: amd64\nComponents: main\nAcquire-By-Hash: yes\nDate: '+format_datetime(datetime.now(timezone.utc).replace(microsecond=0))+'\nMD5Sum:\nSHA1:\nSHA256:\nSHA512:\n').encode()
        V.validate_release_policy_headers(data,channel='stable')
        with self.assertRaises(V.VerificationError):V.validate_release_policy_headers(data)
        for old,new in [(b'Codename: stable',b'Codename: preview'),(b'Acquire-By-Hash: yes',b'Acquire-By-Hash: no')]:
            with self.subTest(old=old),self.assertRaises(V.VerificationError):
                V.validate_release_policy_headers(data.replace(old,new),channel='stable')

    def test_parser_exposes_explicit_candidate_and_external_plan(self):
        args=V.build_parser().parse_args(['--site-root','site','--snapshot','snapshot','--channels','channels',
            '--signing','roles','--apt-public-cert','apt','--rpm-public-cert','rpm','--channel','stable',
            '--offline-candidate','--control-root','control','--candidate-source-root','source','--test-only','--plan','plan'])
        self.assertEqual(args.channel,'stable');self.assertEqual(args.plan,Path('plan'))
        with self.assertRaises((V.VerificationError,V.C.CompositionError,OSError)):
            args.plan=None;V.verify(args)

if __name__=='__main__':unittest.main()
