from __future__ import annotations

import contextlib
import gzip
import hashlib
import importlib.util
import io
import json
import os
import shutil
import tarfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from tests import test_compose_package_site as F
from tests import test_package_audit_receipt as A

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'scripts/plan-object-storage-publication.py'
R = A.receipt_module
C = F.composer


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode() + b'\n'


class InputSnapshot:
    """Create independently receipted TEST ONLY bytes through existing builders."""

    def __init__(self, root, audit_id=10, version='3.1.0-rc.1', deb=b'deb-v1',
                 plain_rpm_metadata=False):
        root.mkdir(parents=True)
        self.root = root
        self.f = F.Fixture(root)
        self.audit_id = audit_id
        self.version = version
        unsigned, signed = b'unsigned-' + deb, b'signed-' + deb
        item = F.release(version, deb, unsigned, source_release_id=100 + audit_id,
                         package_release_id=audit_id)
        self.f.write_control([item], operation='add_release', audit_id=audit_id,
                             base_id=None, target=version, active=[version], retained=[],
                             new=[version], removed=[], not_before=None)
        self.f.write_source_attestations(item)
        self.f.write_inventory({version: item}, {'apt': {version: deb}, 'rpm': {version: unsigned}},
                               audit_id=audit_id, active=[version], retained=[], new=[version])
        self.f.write_apt({version: deb}, [version])
        self.f.write_rpm({version: signed}, [version], [version], unsigned_payloads={version: unsigned})
        repodata = self.f.rpm_tree / 'preview/el/9/x86_64/repodata'
        if plain_rpm_metadata:
            # Match the published beta.24 layout: referenced gzip metadata with
            # plain names, separate compressed/open identities, and no digest prefix.
            xml = ET.fromstring((repodata / 'repomd.xml').read_bytes())
            for entry in xml.findall('data'):
                location = entry.find('location')
                path = self.f.rpm_tree / 'preview/el/9/x86_64' / location.get('href')
                compressed = gzip.compress(path.read_bytes(), mtime=0)
                path.with_name(path.name + '.gz').write_bytes(compressed)
                path.unlink()
                location.set('href', location.get('href') + '.gz')
                entry.find('checksum').text = digest(compressed)
                entry.find('size').text = str(len(compressed))
            (repodata / 'repomd.xml').write_bytes(ET.tostring(xml) + b'\n')
        repomd = (repodata / 'repomd.xml').read_text()
        for path in list(repodata.glob('*.xml')):
            if path.name == 'repomd.xml':
                continue
            name = digest(path.read_bytes()) + '-' + path.name
            repomd = repomd.replace('repodata/' + path.name, 'repodata/' + name)
            path.rename(path.with_name(name))
        (repodata / 'repomd.xml').write_text(repomd)
        rpm_receipt = json.loads(self.f.rpm_receipt.read_text())
        rpm_receipt['result']['repodata'] = [F.artifact(p, 'repodata/' + p.name)
                                            for p in sorted(repodata.iterdir())]
        self.f.rpm_receipt.write_bytes(canonical(rpm_receipt))
        C.compose(self.f.args())
        self.control = root / 'control'
        self.control.mkdir()
        for relative, source in {
            'manifests/channels.json': self.f.channels,
            'manifests/preview-signing.json': self.f.signing,
            'manifests/signing-toolchain.json': self.f.signing_toolchain,
            'keys/apt-preview.asc': self.f.apt_public_cert,
            'keys/rpm-preview.asc': self.f.rpm_public_cert,
        }.items():
            target = self.control / relative
            target.parent.mkdir(exist_ok=True)
            shutil.copyfile(source, target)
        (self.control / 'manifests/bootstrap-packages.json').write_bytes(canonical({
            'schema': 'wukongim.native_package_bootstrap/v1', 'enabled': True, 'version': F.BOOTSTRAP_VERSION,
        }))
        self.archive = root / f'wukongim-preview-r{audit_id}-site.tar'
        self.receipt = root / f'wukongim-preview-r{audit_id}-receipt.json'
        self.seal()

    @property
    def site(self):
        return self.f.output / 'site'

    def seal(self):
        audit = self.f.output / 'audit'
        shutil.copyfile(self.f.plan, audit / 'plan.json')
        apt_receipt = json.loads(self.f.apt_receipt.read_text())
        for key, path in [('inrelease', 'InRelease'), ('release', 'Release'), ('release_gpg', 'Release.gpg')]:
            rel = 'dists/preview/' + path
            apt_receipt['result'][key] = F.artifact(self.site / 'apt' / rel, rel)
        (audit / 'apt-signing.json').write_bytes(canonical(apt_receipt))
        rpm_receipt = json.loads(self.f.rpm_receipt.read_text())
        repodata = self.site / 'rpm/preview/el/9/x86_64/repodata'
        rpm_receipt['result']['repodata'] = [F.artifact(p, 'repodata/' + p.name)
                                            for p in sorted(repodata.iterdir())]
        (audit / 'rpm-signing.json').write_bytes(canonical(rpm_receipt))
        self.archive.unlink(missing_ok=True)
        R.snapshot_archive.create_snapshot(source_dir=self.f.output, archive_path=self.archive)
        self.receipt.unlink(missing_ok=True)
        R.create_audit_receipt(output_path=self.receipt, channels_path=self.control / 'manifests/channels.json',
                              signing_path=self.control / 'manifests/preview-signing.json',
                              signing_toolchain_path=self.control / 'manifests/signing-toolchain.json',
                              apt_public_cert_path=self.control / 'keys/apt-preview.asc',
                              rpm_public_cert_path=self.control / 'keys/rpm-preview.asc',
                              source_attestations_path=audit / 'source-attestations', plan_path=audit / 'plan.json',
                              apt_receipt_path=audit / 'apt-signing.json', rpm_receipt_path=audit / 'rpm-signing.json',
                              archive_path=self.archive)

    def descriptor(self):
        receipt = json.loads(self.receipt.read_text())
        return {
            'archive': str(self.archive), 'receipt': str(self.receipt), 'control_dir': str(self.control),
            'audit_release_id': self.audit_id, 'control_sha': F.CONTROL_SHA,
            'archive_sha256': digest(self.archive.read_bytes()), 'archive_size': self.archive.stat().st_size,
            'receipt_sha256': digest(self.receipt.read_bytes()),
            'snapshot_sha256': receipt['archive']['snapshot_sha256'],
            'source': {key: receipt['source'][key] for key in ['release_id', 'source_sha']}
                      | {'repository': 'WuKongIM/WuKongIM', 'version': self.version},
            'control_files_sha256': {p.relative_to(self.control).as_posix(): digest(p.read_bytes())
                                     for p in sorted(self.control.rglob('*')) if p.is_file()},
        }


class PlanObjectStoragePublicationTest(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.snapshot = InputSnapshot(self.root / 'current')
        self.inputs = {'schema': 'wukongim.object_storage_plan_inputs/v1', 'channel': 'preview',
                       'current': self.snapshot.descriptor(), 'retain': []}
        self.input_path = self.root / 'inputs.json'
        self.output = self.root / 'plan.json'

    def invoke(self, inputs=None, output=None):
        if inputs is not None:
            self.inputs = inputs
        self.input_path.write_bytes(canonical(self.inputs))
        if not SCRIPT.exists():
            return 2, '', 'planner script is missing'
        spec = importlib.util.spec_from_file_location('object_storage_planner_test', SCRIPT)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = module.main(['--inputs', str(self.input_path), '--output', str(output or self.output)])
        return code, stdout.getvalue(), stderr.getvalue()

    def assert_rejected(self, token):
        code, _, error = self.invoke()
        self.assertEqual(1, code, error)
        self.assertIn(token, error)
        self.assertFalse(self.output.exists())

    def refresh(self):
        self.snapshot.seal()
        self.inputs['current'] = self.snapshot.descriptor()

    def test_deterministic_plan_marks_verification_limits_and_preserves_inputs(self):
        before = {p: digest(p.read_bytes()) for p in self.snapshot.root.rglob('*') if p.is_file()}
        code, stdout, error = self.invoke()
        self.assertEqual(0, code, error)
        raw = self.output.read_bytes()
        plan = json.loads(raw)
        self.assertEqual('wukongim.object_storage_publication_plan/v1', plan['schema'])
        self.assertEqual('plan_only', plan['status'])
        self.assertEqual({'archive_and_receipt_consistent': True, 'metadata_closure_checked': True,
                          'signatures_verified': False, 'github_provenance_verified': False,
                          'control_commit_verified': False, 'cloud_verified': False,
                          'activation_authorized': False}, plan['verification'])
        self.assertEqual(digest(raw), json.loads(stdout)['plan_sha256'])
        self.assertEqual([], plan['retention']['delete_objects'])
        self.assertEqual(before, {p: digest(p.read_bytes()) for p in self.snapshot.root.rglob('*') if p.is_file()})
        self.assertEqual(canonical(plan), raw)
        code, _, error = self.invoke(output=self.root / 'second.json')
        self.assertEqual(0, code, error)
        self.assertEqual(raw, (self.root / 'second.json').read_bytes())
        self.assertNotIn(str(self.root), raw.decode())

    def test_current_entrypoints_and_content_addressed_dependencies_are_separate(self):
        code, _, error = self.invoke()
        self.assertEqual(0, code, error)
        plan = json.loads(self.output.read_bytes())
        entries = {x['public_uri']: x for x in plan['entrypoints']}
        shared = {x['public_uri']: x for x in plan['immutable_aliases']}
        for path in ['/apt/dists/preview/main/binary-amd64/Packages.gz',
                     '/rpm/preview/el/9/x86_64/repodata/repomd.xml',
                     '/rpm/preview/el/9/x86_64/repodata/repomd.xml.asc']:
            self.assertEqual('no-store', entries[path]['cache_control'])
            self.assertNotIn(path, shared)
        self.assertTrue(any('/by-hash/SHA256/' in p for p in shared))
        self.assertTrue(any('/Packages/wukongim_' in p for p in shared))
        self.assertTrue(all(x['object_key'].startswith('public/') for x in shared.values()))

    def test_retained_generations_keep_old_by_hash_and_payload_with_no_deletion(self):
        old = InputSnapshot(self.root / 'old', 8, '3.1.0-beta.8', b'deb-old')
        older = InputSnapshot(self.root / 'older', 7, '3.1.0-beta.7', b'deb-older')
        self.inputs['retain'] = [old.descriptor(), older.descriptor()]
        code, _, error = self.invoke()
        self.assertEqual(0, code, error)
        first = self.output.read_bytes()
        plan = json.loads(first)
        self.assertEqual([7, 8], plan['retention']['retained_audit_ids'])
        aliases = {o['public_uri'] for o in plan['immutable_aliases']}
        old_hash = digest((old.site / 'apt/dists/preview/main/binary-amd64/Packages.gz').read_bytes())
        self.assertIn('/apt/dists/preview/main/binary-amd64/by-hash/SHA256/' + old_hash, aliases)
        self.assertTrue(any('beta.8' in path for path in aliases))
        self.inputs['retain'].reverse()
        code, _, error = self.invoke(output=self.root / 'reordered.json')
        self.assertEqual(0, code, error)
        self.assertEqual(first, (self.root / 'reordered.json').read_bytes())

    def test_rejects_duplicate_snapshot_identity(self):
        self.inputs['retain'] = [self.snapshot.descriptor()]
        self.assert_rejected('duplicate audit')

    def test_rejects_same_immutable_uri_with_different_valid_bytes(self):
        old = InputSnapshot(self.root / 'old', 8, self.snapshot.version, b'other-payload')
        self.inputs['retain'] = [old.descriptor()]
        self.assert_rejected('immutable URI conflict')

    def test_rejects_wrong_independent_identity_anchors(self):
        for field, value, message in [
            ('archive_sha256', 'f' * 64, 'archive SHA-256'),
            ('archive_size', 1, 'archive size'),
            ('receipt_sha256', 'f' * 64, 'receipt SHA-256'),
            ('snapshot_sha256', 'f' * 64, 'snapshot identity'),
            ('audit_release_id', 99, 'audit identity'),
            ('control_sha', 'f' * 40, 'control identity'),
        ]:
            with self.subTest(field=field):
                self.inputs['current'] = self.snapshot.descriptor()
                self.inputs['current'][field] = value
                self.assert_rejected(message)
        self.inputs['current'] = self.snapshot.descriptor()
        self.inputs['current']['source']['source_sha'] = 'f' * 40
        self.assert_rejected('source identity')

    def test_rejects_changed_control_despite_unchanged_commit_label(self):
        path = self.snapshot.control / 'manifests/channels.json'
        path.write_bytes(path.read_bytes() + b' ')
        self.assert_rejected('control file SHA-256')

    def test_rejects_enabled_stable_control_even_when_reanchored(self):
        path = self.snapshot.control / 'manifests/channels.json'
        value = json.loads(path.read_text())
        value['channels']['stable']['enabled'] = True
        path.write_bytes(canonical(value))
        self.inputs['current']['control_files_sha256'][path.relative_to(self.snapshot.control).as_posix()] = digest(path.read_bytes())
        self.assert_rejected('stable publishing is forbidden')

    def test_rejects_wrong_channel_and_unknown_fields(self):
        self.inputs['channel'] = 'stable'
        self.assert_rejected('only preview')
        self.inputs['channel'] = 'preview'
        self.inputs['activate'] = True
        self.assert_rejected('fields')

    def test_rejects_non_prerelease_in_preview(self):
        path = self.snapshot.control / 'manifests/channels.json'
        value = json.loads(path.read_text())
        value['channels']['preview']['releases'][0]['version'] = '3.1.0'
        path.write_bytes(canonical(value))
        self.inputs['current']['control_files_sha256'][path.relative_to(self.snapshot.control).as_posix()] = digest(path.read_bytes())
        self.assert_rejected('version is invalid')

    def test_rejects_missing_apt_by_hash_even_with_matching_receipt(self):
        next((self.snapshot.site / 'apt/dists/preview/main/binary-amd64/by-hash/SHA256').iterdir()).unlink()
        self.refresh()
        self.assert_rejected('APT by-hash')

    def test_rejects_rpm_dependency_reference_not_present_in_receipt(self):
        path = self.snapshot.site / 'rpm/preview/el/9/x86_64/repodata/repomd.xml'
        path.write_text(path.read_text().replace('repodata/', 'repodata/missing-', 1))
        self.refresh()
        self.assert_rejected('unreceipted file')

    def test_plain_rpm_metadata_is_current_no_store_and_retained_per_snapshot(self):
        current = InputSnapshot(self.root / 'plain-current', plain_rpm_metadata=True)
        old = InputSnapshot(self.root / 'plain-old', 8, '3.1.0-beta.8', b'deb-old',
                            plain_rpm_metadata=True)
        self.inputs['current'] = current.descriptor()
        self.inputs['retain'] = [old.descriptor()]
        code, _, error = self.invoke()
        self.assertEqual(0, code, error)
        plan = json.loads(self.output.read_bytes())
        entries = {item['public_uri']: item for item in plan['entrypoints']}
        aliases = {item['public_uri'] for item in plan['immutable_aliases']}
        for name in ('primary', 'filelists', 'other'):
            path = 'rpm/preview/el/9/x86_64/repodata/' + name + '.xml.gz'
            self.assertNotIn('/' + path, aliases)
            self.assertEqual('no-store', entries['/' + path]['cache_control'])
            self.assertEqual(digest((current.site / path).read_bytes()), entries['/' + path]['sha256'])
            objects = [item for item in plan['snapshot_objects'] if item['source']['member'] == 'site/' + path]
            self.assertEqual([8, 10], sorted(item['source']['audit_release_id'] for item in objects))
            self.assertEqual(2, len({item['object_key'] for item in objects}))
            self.assertTrue(all(item['cache_control'] == 'no-store' for item in objects))
            if name == 'primary':
                self.assertEqual(2, len({item['sha256'] for item in objects}))
        self.assertEqual([], plan['retention']['delete_objects'])

    def test_plain_rpm_metadata_still_requires_full_reference_and_hash_closure(self):
        for case, token in [('unused', 'exactly cover'), ('compressed', 'identity differs'),
                            ('open', 'open identity differs'), ('unsafe', 'unsafe path')]:
            with self.subTest(case=case):
                self.snapshot = InputSnapshot(self.root / case, plain_rpm_metadata=True)
                base = self.snapshot.site / 'rpm/preview/el/9/x86_64/repodata'
                path = base / 'repomd.xml'
                if case == 'unused':
                    (base / 'unused.xml.gz').write_bytes(gzip.compress(b'<unused/>', mtime=0))
                elif case == 'compressed':
                    (base / 'primary.xml.gz').write_bytes(gzip.compress(b'<changed/>', mtime=0))
                elif case == 'open':
                    xml = ET.fromstring(path.read_bytes())
                    xml.find('data/open-checksum').text = 'f' * 64
                    path.write_bytes(ET.tostring(xml))
                else:
                    path.write_text(path.read_text().replace('repodata/primary.xml.gz', '../primary.xml.gz'))
                self.refresh()
                self.assert_rejected(token)

    def test_rejects_ambiguous_or_unknown_public_object(self):
        for name, token in [('bad%2fpath', 'unsafe public path'), ('unexpected.txt', 'unexpected site object')]:
            with self.subTest(name=name):
                p = self.snapshot.site / name
                p.write_bytes(b'not-reviewed')
                self.refresh()
                self.assert_rejected(token)
                p.unlink()

    def test_rejects_unsupported_operation_before_archive_plan_reinterpretation(self):
        value = json.loads(self.snapshot.receipt.read_text())
        value['plan']['operation'] = 'update_bootstrap'
        self.snapshot.receipt.write_bytes(canonical(value))
        self.inputs['current']['receipt_sha256'] = digest(self.snapshot.receipt.read_bytes())
        self.assert_rejected('only add_release')

    def test_rejects_missing_indexed_payload(self):
        path = next((self.snapshot.site / 'apt/pool/main/w/wukongim').glob('wukongim_*.deb'))
        path.unlink()
        self.snapshot.archive.unlink()
        R.snapshot_archive.create_snapshot(source_dir=self.snapshot.f.output, archive_path=self.snapshot.archive)
        self.inputs['current']['archive_sha256'] = digest(self.snapshot.archive.read_bytes())
        self.inputs['current']['archive_size'] = self.snapshot.archive.stat().st_size
        self.assert_rejected('payload')

    def test_rejects_zstd_before_any_native_decoder(self):
        base = self.snapshot.site / 'rpm/preview/el/9/x86_64/repodata'
        path = next(base.glob('*-primary.xml'))
        old_name = path.name
        name = digest(path.read_bytes()) + '-primary.xml.zst'
        path.rename(base / name)
        repomd = base / 'repomd.xml'
        repomd.write_text(repomd.read_text().replace(old_name, name))
        self.refresh()
        self.assert_rejected('unsupported RPM metadata compression')

    def test_rejects_wrong_open_digest_and_escaping_rpm_reference(self):
        path = self.snapshot.site / 'rpm/preview/el/9/x86_64/repodata/repomd.xml'
        original = path.read_text()
        path.write_text(original.replace('<open-checksum type="sha256">', '<open-checksum type="sha256">0', 1))
        self.refresh()
        self.assert_rejected('open checksum')
        path.write_text(original.replace('repodata/', '../outside/', 1))
        self.refresh()
        self.assert_rejected('unsafe path')

    def test_rejects_wrong_bootstrap_or_status_content_even_when_receipted(self):
        path = self.snapshot.site / 'bootstrap/manifest.json'
        original = path.read_bytes()
        value = json.loads(original)
        value['version'] = '2.0.0'
        path.write_bytes(canonical(value))
        self.refresh()
        self.assert_rejected('bootstrap')
        path.write_bytes(original)
        status = self.snapshot.site / 'status.json'
        value = json.loads(status.read_bytes())
        value['control_sha'] = 'f' * 40
        status.write_bytes(canonical(value))
        self.refresh()
        self.assert_rejected('status')

    def test_rejects_boolean_identity(self):
        self.inputs['current']['audit_release_id'] = True
        self.assert_rejected('positive integer')

    def test_rejects_control_root_symlink(self):
        link = self.root / 'control-link'
        link.symlink_to(self.snapshot.control, target_is_directory=True)
        self.inputs['current']['control_dir'] = str(link)
        self.assert_rejected('control directory')

    def test_rejects_duplicate_json_keys(self):
        self.input_path.write_text('{"schema":1,"schema":2}')
        if not SCRIPT.exists():
            self.fail('planner script is missing')
        spec = importlib.util.spec_from_file_location('planner_duplicate', SCRIPT)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            code = module.main(['--inputs', str(self.input_path), '--output', str(self.output)])
        self.assertEqual(1, code)
        self.assertIn('duplicate JSON', stderr.getvalue())
        self.assertFalse(self.output.exists())

    def test_rejects_excess_snapshots_before_reading_archives(self):
        self.inputs['retain'] = [self.snapshot.descriptor()] * 8
        self.assert_rejected('at most 8 snapshots')

    def test_rejects_cumulative_archive_budget_before_reading_archives(self):
        self.inputs['current']['archive_size'] = 800 * 1024 * 1024
        old = self.snapshot.descriptor()
        old['audit_release_id'] = 8
        old['archive_size'] = 800 * 1024 * 1024
        self.inputs['retain'] = [old, dict(old, audit_release_id=7)]
        self.assert_rejected('total archive byte limit')

    def assert_rejected_before_content_open(self, path, token):
        original_open = os.open

        def bounded_open(filename, *args, **kwargs):
            if Path(filename) == path:
                self.fail('out-of-budget input was opened before its size was rejected')
            return original_open(filename, *args, **kwargs)

        with patch('os.open', side_effect=bounded_open):
            self.assert_rejected(token)

    def test_rejects_actual_archive_size_mismatch_before_content_open(self):
        actual_size = self.snapshot.archive.stat().st_size
        for declared in (1, actual_size + 1):
            with self.subTest(declared=declared):
                self.inputs['current']['archive_size'] = declared
                self.assert_rejected_before_content_open(self.snapshot.archive, 'archive size')

    def test_rejects_oversized_receipt_before_content_open(self):
        with self.snapshot.receipt.open('r+b') as handle:
            handle.truncate(R.MAX_JSON_BYTES + 1)
        self.assert_rejected_before_content_open(self.snapshot.receipt, 'receipt exceeds its size limit')

    def test_rejects_oversized_control_before_content_open(self):
        for relative in self.inputs['current']['control_files_sha256']:
            with self.subTest(relative=relative):
                path = self.snapshot.control / relative
                original = path.read_bytes()
                limit = (1024 * 1024 if relative.startswith('keys/')
                         or relative == 'manifests/signing-toolchain.json' else R.MAX_JSON_BYTES)
                try:
                    with path.open('r+b') as handle:
                        handle.truncate(limit + 1)
                    self.assert_rejected_before_content_open(path, 'exceeds its size limit')
                finally:
                    path.write_bytes(original)

    def test_rejects_symlink_archive_and_existing_output(self):
        link = self.snapshot.archive.with_name('linked.tar')
        link.symlink_to(self.snapshot.archive)
        self.inputs['current']['archive'] = str(link)
        self.assert_rejected('single-link regular file')
        self.inputs['current'] = self.snapshot.descriptor()
        self.output.write_bytes(b'keep-me')
        code, _, error = self.invoke()
        self.assertEqual(1, code)
        self.assertIn('output already exists', error)
        self.assertEqual(b'keep-me', self.output.read_bytes())

    def test_rejects_symlink_output_parent(self):
        link = self.root / 'linked-directory'
        link.symlink_to(self.root, target_is_directory=True)
        code, _, error = self.invoke(output=link / 'via-link.json')
        self.assertEqual(1, code)
        self.assertIn('output parent', error)
        self.assertFalse((self.root / 'via-link.json').exists())

    def test_rejects_noncanonical_tar_member_types_paths_and_duplicates(self):
        original = self.snapshot.archive.read_bytes()
        for name, kind in [('../escape', tarfile.REGTYPE), ('site/link', tarfile.SYMTYPE),
                           ('site/hardlink', tarfile.LNKTYPE), ('site/', tarfile.DIRTYPE)]:
            with self.subTest(name=name):
                # Valid independent SHA anchors do not make a noncanonical tar acceptable.
                raw = io.BytesIO()
                with tarfile.open(fileobj=raw, mode='w', format=tarfile.USTAR_FORMAT) as tar:
                    for entry_name in ['site/', name]:
                        info = tarfile.TarInfo(entry_name)
                        info.type = tarfile.DIRTYPE if entry_name == 'site/' else kind
                        info.mode = 0o755 if info.type == tarfile.DIRTYPE else 0o644
                        info.uid = info.gid = info.mtime = 0
                        info.linkname = 'site/target' if info.type in [tarfile.SYMTYPE, tarfile.LNKTYPE] else ''
                        tar.addfile(info)
                # Python tarfile leaves device fields empty; normalize those
                # fields so each case reaches its intended path/type/duplicate check.
                payload = bytearray(raw.getvalue()[:1024])
                for offset in (0, 512):
                    payload[offset + 329:offset + 337] = b'0000000\0'
                    payload[offset + 337:offset + 345] = b'0000000\0'
                    payload[offset + 148:offset + 156] = b'        '
                    checksum = sum(payload[offset:offset + 512])
                    payload[offset + 148:offset + 156] = f'{checksum:06o}'.encode() + b'\0 '
                payload.extend(b'\0' * 1024)
                self.snapshot.archive.write_bytes(payload)
                self.inputs['current']['archive_sha256'] = digest(payload)
                self.inputs['current']['archive_size'] = len(payload)
                self.assert_rejected('archive')
        self.snapshot.archive.write_bytes(original)


if __name__ == '__main__':
    unittest.main()
