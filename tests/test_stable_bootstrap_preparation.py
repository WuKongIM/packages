"""CLI contracts for unpublished stable bootstrap preparation, with fake RPM I/O.

Actual native build and package-database installation is a separate TEST ONLY
CI drill; these tests do not claim native RPM acceptance.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

import test_build_repository_bootstrap_packages as preview_tests
MODULE = preview_tests.MODULE

ROOT = Path(__file__).resolve().parents[1]
BUILDER = ROOT / 'scripts/build-repository-bootstrap-packages.py'


class StableBootstrapPreparationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='stable-bootstrap-TEST-ONLY-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.control = self.root / 'control'
        shutil.copytree(ROOT / 'keys', self.control / 'keys')
        (self.control / 'manifests').mkdir()
        for name in ('channels.json', 'bootstrap-packages.json', 'preview-signing.json', 'stable-public-keys.json'):
            shutil.copyfile(ROOT / 'manifests' / name, self.control / 'manifests' / name)

    def toolchain(self, channel):
        fixture = preview_tests.BootstrapPackageBuilderTests()
        fixture.root = self.root
        fixture.rpm_certificate = self.control / f'keys/rpm-{channel}.asc'
        binary = fixture.fake_toolchain()
        if channel == 'stable':
            # Independent fake native output; actual installation is covered by CI.
            old_repo_sha = hashlib.sha256(MODULE.RPM_REPOSITORY).hexdigest()
            stable_repo = (
                '[wukongim-stable]\nname=WuKongIM stable\n'
                'mirrorlist=https://packages.githubim.com/rpm/stable/el/9/x86_64/mirrorlist\n'
                'enabled=1\nincludepkgs=wukongim,wukongim-release-stable\n'
                'gpgcheck=1\nrepo_gpgcheck=1\ngpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-wukongim-stable\n'
                'sslverify=1\nmetadata_expire=0\nskip_if_unavailable=0\n'
            )
            for tool in binary.iterdir():
                text = tool.read_text().replace('wukongim-release', 'wukongim-release-stable').replace('preview', 'stable')
                text = text.replace('baseurl=https://packages.githubim.com/rpm/stable/el/9/x86_64',
                                    'mirrorlist=https://packages.githubim.com/rpm/stable/el/9/x86_64/mirrorlist')
                text = text.replace("('baseurl=',", "('mirrorlist=',")
                text = text.replace(old_repo_sha, hashlib.sha256(stable_repo.encode()).hexdigest())
                tool.write_text(text)
        return binary

    def invoke(self, *, channel='stable', extra=(), tools=False, output='output'):
        command = [sys.executable, '-B', str(BUILDER), '--output-dir', str(self.root / output)]
        if channel == 'stable':
            command += ['--channel', channel, '--control-root', str(self.control)]
        else:
            if channel is not None:
                command += ['--channel', channel]
            command += ['--manifest', str(self.control / 'manifests/bootstrap-packages.json'),
                        '--apt-public-cert', str(self.control / 'keys/apt-preview.asc'),
                        '--rpm-public-cert', str(self.control / 'keys/rpm-preview.asc')]
        environment = dict(os.environ)
        if tools:
            environment['PATH'] = str(self.toolchain(channel or 'preview')) + os.pathsep + environment['PATH']
        return subprocess.run(command + list(extra), capture_output=True, env=environment, timeout=30)

    def test_stable_build_has_distinct_data_only_packages_and_preparation_inventory(self):
        result = self.invoke(tools=True)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        inventory = json.loads(result.stdout)
        self.assertEqual(inventory['schema'], 'wukongim.stable_bootstrap_preparation/v1')
        self.assertEqual(inventory['channel'], 'stable')
        self.assertIs(inventory['published'], False)
        self.assertEqual(inventory['version'], '1.1.0')
        apt, rpm = inventory['packages']['apt'], inventory['packages']['rpm']
        self.assertEqual(apt['name'], 'wukongim-archive-keyring-stable')
        self.assertEqual(rpm['name'], 'wukongim-release-stable')
        self.assertEqual(rpm['repository_path'], 'rpm/stable/el/9/x86_64/Packages/wukongim-release-stable-1.1.0-1.noarch.rpm')
        package = self.root / 'output' / apt['filename']
        members = MODULE._parse_ar(package.read_bytes())
        control = MODULE._inspect_tar_gzip(members['control.tar.gz'], 'control')
        self.assertEqual(set(control), {'./control', './conffiles'})
        self.assertIn(b'Package: wukongim-archive-keyring-stable\n', control['./control'][1])
        data = MODULE._inspect_tar_gzip(members['data.tar.gz'], 'data')
        files = {name: content for name, (item, content) in data.items() if item.isfile()}
        self.assertEqual(set(files), {'./etc/apt/sources.list.d/wukongim-stable.sources',
                                     './usr/share/keyrings/wukongim-archive-keyring-stable.pgp'})
        self.assertEqual(files['./etc/apt/sources.list.d/wukongim-stable.sources'],
                         b'Types: deb\nURIs: https://packages.githubim.com/apt\nSuites: stable\nComponents: main\nArchitectures: amd64\nSigned-By: /usr/share/keyrings/wukongim-archive-keyring-stable.pgp\nEnabled: yes\n')
        self.assertEqual(files['./usr/share/keyrings/wukongim-archive-keyring-stable.pgp'],
                         MODULE.dearmor_public_certificate((self.control / 'keys/apt-stable.asc').read_bytes(), 'stable'))
        composer_spec = importlib.util.spec_from_file_location('stable_test_composer', ROOT / 'scripts/compose-package-site.py')
        composer = importlib.util.module_from_spec(composer_spec)
        composer_spec.loader.exec_module(composer)
        with self.assertRaises(composer.CompositionError):
            composer.validate_bootstrap_inventory(inventory, prepared=True)

    def test_explicit_preview_remains_byte_identical_to_default_and_frozen_deb(self):
        first = self.invoke(channel=None, tools=True, output='default')
        # Reuse the exact fake toolchain for the explicit call.
        env = dict(os.environ, PATH=str(self.root / 'bin') + os.pathsep + os.environ['PATH'])
        command = [sys.executable, '-B', str(BUILDER), '--channel', 'preview', '--manifest', str(self.control / 'manifests/bootstrap-packages.json'),
                   '--apt-public-cert', str(self.control / 'keys/apt-preview.asc'), '--rpm-public-cert', str(self.control / 'keys/rpm-preview.asc'),
                   '--output-dir', str(self.root / 'explicit')]
        second = subprocess.run(command, capture_output=True, env=env, timeout=30)
        self.assertEqual(first.returncode, 0, first.stderr.decode())
        self.assertEqual(second.returncode, 0, second.stderr.decode())
        self.assertEqual(first.stdout, second.stdout)
        inventory = json.loads(first.stdout)
        self.assertEqual(inventory['schema'], 'wukongim.native_package_bootstrap_inventory/v1')
        self.assertEqual(set(inventory), {'schema', 'version', 'packages'})
        apt = inventory['packages']['apt']['filename']
        self.assertEqual(hashlib.sha256((self.root / 'default' / apt).read_bytes()).hexdigest(),
                         '159f2897ce4fb402049424407a4c347fb5cadcd65c5db1015b7e5e817cd96622')
        self.assertEqual(hashlib.sha256(MODULE.RPM_SPEC_TEMPLATE.replace('@VERSION@', '1.1.0').encode()).hexdigest(),
                         'cb383ce6ba7c3526c61f4f5ed80c1dbd41609de5e286eaa30e8d7b29490456d4')
        for filename in (inventory['packages'][family]['filename'] for family in ('apt', 'rpm')):
            self.assertEqual((self.root / 'default' / filename).read_bytes(), (self.root / 'explicit' / filename).read_bytes())

    def test_stable_forbids_unreviewed_manifest_and_certificate_overrides(self):
        for flag, value in (('--manifest', self.control / 'manifests/bootstrap-packages.json'),
                            ('--apt-public-cert', self.control / 'keys/apt-stable.asc'),
                            ('--rpm-public-cert', self.control / 'keys/rpm-stable.asc')):
            with self.subTest(flag=flag):
                result = self.invoke(extra=(flag, str(value)))
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(b'stable derives manifest and certificates from --control-root', result.stderr)
                self.assertFalse((self.root / 'output').exists())

    def test_stable_requires_complete_matching_public_roles_and_disabled_channel(self):
        role_path = self.control / 'manifests/stable-public-keys.json'
        original = role_path.read_bytes()
        roles = json.loads(original)
        scenarios = ['missing', 'partial', 'wrong_fingerprint', 'swapped', 'enabled']
        for scenario in scenarios:
            with self.subTest(scenario=scenario):
                role_path.write_bytes(original)
                shutil.copyfile(ROOT / 'keys/apt-stable.asc', self.control / 'keys/apt-stable.asc')
                channels_path = self.control / 'manifests/channels.json'
                shutil.copyfile(ROOT / 'manifests/channels.json', channels_path)
                if scenario == 'missing':
                    role_path.unlink()
                elif scenario == 'partial':
                    role_path.write_text(json.dumps({'schema': roles['schema'], 'apt': roles['apt']}))
                elif scenario == 'wrong_fingerprint':
                    changed = json.loads(original); changed['apt']['primary_fingerprint'] = 'A' * 40
                    role_path.write_text(json.dumps(changed))
                elif scenario == 'swapped':
                    shutil.copyfile(ROOT / 'keys/rpm-stable.asc', self.control / 'keys/apt-stable.asc')
                else:
                    changed = json.loads(channels_path.read_bytes()); changed['channels']['stable']['enabled'] = True
                    channels_path.write_text(json.dumps(changed))
                result = self.invoke()
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn(b'unrecognized arguments', result.stderr)
                self.assertFalse((self.root / 'output').exists())

    def test_stable_rejects_certificate_changed_after_native_public_validation(self):
        binary = self.toolchain('stable')
        real_gpg = shutil.which('gpg')
        self.assertIsNotNone(real_gpg)
        shim = binary / 'gpg'
        shim.write_text(f"""#!{sys.executable}
import pathlib, shutil, subprocess, sys
result = subprocess.run([{real_gpg!r}, *sys.argv[1:]], capture_output=True)
if sys.argv[-1] == {str(self.control / 'keys/apt-stable.asc')!r}:
    shutil.copyfile({str(self.control / 'keys/apt-preview.asc')!r}, sys.argv[-1])
sys.stdout.buffer.write(result.stdout)
sys.stderr.buffer.write(result.stderr)
raise SystemExit(result.returncode)
""")
        shim.chmod(0o755)
        command = [sys.executable, '-B', str(BUILDER), '--channel', 'stable',
                   '--control-root', str(self.control), '--output-dir', str(self.root / 'output')]
        result = subprocess.run(command, capture_output=True, timeout=30,
                                env=dict(os.environ, PATH=str(binary) + os.pathsep + os.environ['PATH']))
        self.assertNotEqual(result.returncode, 0, 'changed certificate must never become a bootstrap payload')
        self.assertIn(b'certificate changed during public validation', result.stderr)
        self.assertFalse((self.root / 'output').exists())

    def test_stable_build_failure_rolls_back_and_existing_output_is_preserved(self):
        result = self.invoke(extra=('--control-root', str(self.root / 'absent')))
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn(b'unrecognized arguments', result.stderr)
        output = self.root / 'output'; output.mkdir(); (output / 'sentinel').write_text('keep')
        result = self.invoke()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b'output directory must not already exist', result.stderr)
        self.assertEqual((output / 'sentinel').read_text(), 'keep')
        self.assertFalse(any(p.name.startswith('.output.') for p in self.root.iterdir()))
