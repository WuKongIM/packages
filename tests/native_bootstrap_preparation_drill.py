#!/usr/bin/env python3
"""TEST ONLY native bootstrap preparation and scratch package-database installs.

Run inside the existing pinned, network-disabled toolchain. Only public inputs
and data-only packages are used. This does not sign packages, validate the live
mirrorlist, publish a channel or install a product executable.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
BUILDER = ROOT / 'scripts/build-repository-bootstrap-packages.py'


def facts(path: Path) -> dict:
    return {'sha256': hashlib.sha256(path.read_bytes()).hexdigest(), 'size': path.stat().st_size}


def run(command: list[str], evidence: dict, environment: dict) -> bytes:
    result = subprocess.run(command, stdin=subprocess.DEVNULL, capture_output=True,
                            env=environment, timeout=90)
    item = {'command': command, 'exit_code': result.returncode,
            'stdout_tail': result.stdout[-2048:].decode('utf-8', 'replace'),
            'stderr_tail': result.stderr[-2048:].decode('utf-8', 'replace')}
    evidence['commands'].append(item)
    if len(result.stdout) > 1024 * 1024 or len(result.stderr) > 1024 * 1024:
        raise RuntimeError(f'native command exceeded output bound: {command[0]}')
    if result.returncode:
        raise RuntimeError(f'native command failed: {command[0]}: {item["stderr_tail"]}')
    return result.stdout


def check(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def prepare(scratch: Path, evidence: dict, environment: dict) -> dict:
    """Build both channels twice with actual native tools and compare exact bytes."""
    builds = {}
    for channel in ('preview', 'stable'):
        item = {'case': f'{channel}-reproducible-build', 'passed': False}
        evidence['cases'].append(item)
        previous = None
        for index in (1, 2):
            output = scratch / f'{channel}-{index}'
            command = [sys.executable, '-B', str(BUILDER), '--output-dir', str(output)]
            if channel == 'stable':
                command += ['--channel', 'stable', '--control-root', str(ROOT)]
            else:
                # Default and explicit preview must produce the exact same bytes.
                if index == 2:
                    command += ['--channel', 'preview']
                command += ['--manifest', str(ROOT / 'manifests/bootstrap-packages.json'),
                            '--apt-public-cert', str(ROOT / 'keys/apt-preview.asc'),
                            '--rpm-public-cert', str(ROOT / 'keys/rpm-preview.asc')]
            inventory = json.loads(run(command, evidence, environment))
            if channel == 'stable':
                check(inventory['schema'] == 'wukongim.stable_bootstrap_preparation/v1'
                      and inventory['channel'] == 'stable' and inventory['published'] is False,
                      'stable output is not an unpublished preparation')
            else:
                check(inventory['schema'] == 'wukongim.native_package_bootstrap_inventory/v1'
                      and set(inventory) == {'schema', 'version', 'packages'},
                      'preview inventory changed schema')
            for family in ('apt', 'rpm'):
                package = inventory['packages'][family]
                check(facts(output / package['filename']) ==
                      {'sha256': package['source_sha256'], 'size': package['source_size']},
                      'native package bytes do not match inventory')
            if previous is not None:
                check(inventory == previous, f'{channel} native build is not byte reproducible')
            previous = inventory
            builds[channel] = (output, inventory)
        item.update(passed=True, inventory=previous)
    return builds


def installed_files(root: Path, channel: str, family: str, apt_keyrings: dict) -> dict:
    suffix = '-stable' if channel == 'stable' else ''
    if family == 'apt':
        paths = (f'etc/apt/sources.list.d/wukongim-{channel}.sources',
                 f'usr/share/keyrings/wukongim-archive-keyring{suffix}.pgp')
    else:
        paths = (f'etc/pki/rpm-gpg/RPM-GPG-KEY-wukongim-{channel}',
                 f'etc/yum.repos.d/wukongim-{channel}.repo')
    result = {}
    for relative in paths:
        path = root / relative
        info = path.lstat()
        check(stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o644,
              f'installed file type or permissions differ: {relative}')
        check(info.st_uid == 0 and info.st_gid == 0, f'installed ownership differs: {relative}')
        result[relative] = facts(path)
    if family == 'rpm':
        check((root / paths[0]).read_bytes() == (ROOT / f'keys/rpm-{channel}.asc').read_bytes(),
              'installed RPM certificate differs from reviewed public bytes')
        config = (root / paths[1]).read_text()
        for line in ('enabled=1', 'gpgcheck=1', 'repo_gpgcheck=1', 'sslverify=1', 'skip_if_unavailable=0'):
            check(line in config.splitlines(), f'RPM policy missing {line}')
        if channel == 'stable':
            check('mirrorlist=https://packages.githubim.com/rpm/stable/el/9/x86_64/mirrorlist'
                  in config.splitlines() and 'baseurl=' not in config, 'stable RPM transport changed')
    else:
        check((root / paths[1]).read_bytes() == apt_keyrings[channel],
              'installed APT keyring differs from independently dearmored certificate')
        config = (root / paths[0]).read_text()
        check(f'Suites: {channel}' in config.splitlines() and 'Enabled: yes' in config.splitlines(),
              'installed APT source selects the wrong channel')
    return result


def install_cases(scratch: Path, builds: dict, evidence: dict, environment: dict) -> None:
    """Use unmodified package metadata in real dpkg/rpm databases, in both orders."""
    apt_keyrings = {channel: run(['gpg', '--batch', '--no-options', '--no-auto-key-retrieve',
                                 '--output', '-', '--dearmor', str(ROOT / f'keys/apt-{channel}.asc')],
                                evidence, environment) for channel in ('preview', 'stable')}
    for family in ('apt', 'rpm'):
        for order in (('preview', 'stable'), ('stable', 'preview')):
            case = f'{family}-{"-then-".join(order)}-and-reinstall'
            item = {'case': case, 'passed': False}
            evidence['cases'].append(item)
            install_root = scratch / case
            install_root.mkdir()
            if family == 'rpm':
                base = ['rpm', '--root', str(install_root), '--dbpath', '/var/lib/rpm']
                run([*base, '--initdb'], evidence, environment)
            retained = {}
            # Reinstall each package after both channels coexist.
            for index, channel in enumerate((*order, *order)):
                directory, inventory = builds[channel]
                package = inventory['packages'][family]
                filename = directory / package['filename']
                if family == 'apt':
                    command = ['dpkg', '--root', str(install_root), '--install', str(filename)]
                else:
                    command = [*base, '--reinstall' if index >= 2 else '--install', str(filename)]
                run(command, evidence, environment)
                retained.setdefault(channel, installed_files(install_root, channel, family, apt_keyrings))
                for known, expected in retained.items():
                    check(installed_files(install_root, known, family, apt_keyrings) == expected,
                          f'{case} overwrote another channel or changed package data')
            if family == 'apt':
                result = run(['dpkg-query', '--admindir', str(install_root / 'var/lib/dpkg'),
                              '--show', '--showformat=${Package}\t${Version}\t${Status}\n'], evidence, environment)
                expected = {f'{builds[c][1]["packages"][family]["name"]}\t{builds[c][1]["version"]}\tinstall ok installed'
                            for c in order}
                check(set(result.decode().splitlines()) == expected, 'unexpected package or install status in DEB database')
            else:
                result = run([*base, '--query', '--all', '--queryformat', '%{NAME}\t%{VERSION}\t%{RELEASE}\n'], evidence, environment)
                expected = {f'{builds[c][1]["packages"][family]["name"]}\t{builds[c][1]["version"]}\t1' for c in order}
                check(set(result.decode().splitlines()) == expected, 'unexpected package in RPM database')
                run([*base, '--verify', '--all'], evidence, environment)
            check(not (install_root / 'usr/bin/wukongim').exists(), 'bootstrap installed a product executable')
            item.update(passed=True, installed_files=retained, package_database=result.decode().splitlines())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-dir', required=True, type=Path)
    parser.add_argument('--source-sha', required=True)
    args = parser.parse_args(argv)
    if not re.fullmatch('[0-9a-f]{40}', args.source_sha):
        parser.error('--source-sha must be a full lowercase Git commit')
    output = args.output_dir / 'native-bootstrap-preparation.json'
    # Reserve the evidence file before doing work; never replace a first result.
    with output.open('x') as stream:
        evidence = {'schema': 'wukongim.native_bootstrap_preparation_drill/v1',
                    'test_only': True, 'source_sha': args.source_sha,
                    'passed': False, 'scratch_removed': False, 'cases': [], 'commands': [],
                    'failure': None, 'started_at_unix': int(time.time())}
        scratch = None
        try:
            with tempfile.TemporaryDirectory(prefix='wukongim-bootstrap-TEST-ONLY-') as tmp:
                scratch = Path(tmp)
                check(sys.platform.startswith('linux') and os.geteuid() == 0,
                      'native scratch installs require the isolated Linux test container')
                for tool in ('gpg', 'rpmbuild', 'rpm', 'dpkg', 'dpkg-query'):
                    check(shutil.which(tool) is not None, f'required native tool unavailable: {tool}')
                home = scratch / 'home'; home.mkdir()
                environment = {'PATH': os.environ['PATH'], 'HOME': str(home), 'LANG': 'C.UTF-8',
                               'LC_ALL': 'C.UTF-8', 'TZ': 'UTC'}
                builds = prepare(scratch, evidence, environment)
                install_cases(scratch, builds, evidence, environment)
                check(len(evidence['cases']) == 6 and all(c['passed'] for c in evidence['cases']),
                      'native case inventory is incomplete')
                evidence['passed'] = True
        except Exception as error:
            evidence['failure'] = str(error)[:4096]
        finally:
            evidence['scratch_removed'] = scratch is not None and not scratch.exists()
            evidence['finished_at_unix'] = int(time.time())
            evidence['passed'] = evidence['passed'] and evidence['scratch_removed']
            json.dump(evidence, stream, sort_keys=True, indent=2)
            stream.write('\n')
        print(json.dumps({'passed': evidence['passed'], 'cases': len(evidence['cases']),
                          'failure': evidence['failure'], 'scratch_removed': evidence['scratch_removed']}))
        return 0 if evidence['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
