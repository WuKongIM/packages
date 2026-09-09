#!/usr/bin/env python3
"""Exercise installed release binaries on bounded, private offline fixtures."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import tarfile
import tempfile


class AcceptanceError(Exception):
    pass


def require(condition, message):
    if not condition:
        raise AcceptanceError(message)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def unpack(archive, target):
    """Accept only small regular-file fixtures; never extract links or paths outside scratch."""
    target.mkdir()
    with tarfile.open(archive) as tar:
        members = tar.getmembers()
        require(len(members) <= 200 and sum(m.size for m in members) <= 16 << 20,
                "fixture archive exceeds bounds")
        seen = set()
        for member in members:
            path = PurePosixPath(member.name)
            require(not path.is_absolute() and '..' not in path.parts and
                    member.name not in seen and (member.isfile() or member.isdir()),
                    "unsafe fixture archive entry")
            seen.add(member.name)
            destination = target.joinpath(*path.parts)
            if member.isdir():
                destination.mkdir(parents=True, exist_ok=True)
            else:
                destination.parent.mkdir(parents=True, exist_ok=True)
                with tar.extractfile(member) as source:
                    destination.write_bytes(source.read())


def inventory(root):
    return {p.relative_to(root).as_posix(): sha256(p.read_bytes())
            for p in sorted(root.rglob('*')) if p.is_file()}


def run(command, cwd, env, expected=0):
    """Bound each command and keep diagnostic bytes out of the JSON receipt."""
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        try:
            result = subprocess.run(command, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                                    stdout=stdout, stderr=stderr, timeout=30)
        except subprocess.TimeoutExpired as error:
            raise AcceptanceError('CLI command exceeded 30 seconds') from error
        require(stdout.tell() <= 1 << 20 and stderr.tell() <= 1 << 20,
                'CLI output exceeds 1 MiB')
        stdout.seek(0)
        stderr.seek(0)
        output = stdout.read()
        diagnostic = stderr.read().decode('utf-8', errors='replace')
        require(result.returncode == expected,
                f'CLI exit {result.returncode}, expected {expected}: {diagnostic[-2000:]}')
        return output


def validate(wkcli, server, version, commit, fixtures, execute=run):
    require(re.fullmatch(r'[0-9a-f]{40}', commit) is not None, 'expected commit must be full SHA')
    require(re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?', version) is not None,
            'expected version must be a release version')
    for binary in (wkcli, server):
        require(binary.is_file() and os.access(binary, os.X_OK), f'missing executable: {binary}')
    names = {'target.yaml', 'workers.yaml', 'scenario.yaml', 'native-v3.tar.gz',
             'original-v2-empty.tar.gz'}
    digests = json.loads((fixtures / 'sha256.json').read_text())
    require(set(digests) == names, 'fixture inventory mismatch')
    for name in names:
        require(sha256((fixtures / name).read_bytes()) == digests[name], f'fixture digest mismatch: {name}')
    identity = dict(version=version, commit=commit, build_source='release')
    with tempfile.TemporaryDirectory(prefix='wkcli-acceptance-') as temporary:
        root = Path(temporary)
        # No caller WK_* configuration, credentials or user contexts enter these commands.
        env = {'PATH': os.defpath, 'HOME': str(root), 'TMPDIR': str(root), 'LANG': 'C',
               'WK_BENCH_API_TOKEN': 'synthetic-acceptance',
               'WK_BENCH_WORKER_TOKEN': 'synthetic-acceptance',
               'WK_BENCH_RUN_ID': 'cli-acceptance'}
        for binary in (server, wkcli):
            actual = json.loads(execute([str(binary), 'version', '--output', 'json'], root, env))
            require(actual == identity, 'installed binary identity differs from reviewed release')
        for family in ('bench', 'db', 'migrate'):
            execute([str(wkcli), family, '--help'], root, env)
        benchmark = [str(wkcli), 'bench', 'validate', '--target', str(fixtures / 'target.yaml'),
                     '--workers', str(fixtures / 'workers.yaml'), '--scenario', str(fixtures / 'scenario.yaml')]
        execute(benchmark, root, env)
        invalid = root / 'invalid.yaml'
        invalid.write_text('version: invalid-acceptance-schema\n')
        execute(benchmark[:-1] + [str(invalid)], root, env, expected=1)
        unpack(fixtures / 'native-v3.tar.gz', root / 'native')
        before = inventory(root / 'native')
        query = [str(wkcli), 'db', '--data-dir', str(root / 'native'),
                 '--hash-slot-count', '256', '--format', 'json', 'query',
                 "select uid from meta.user where uid='emptyalice' limit 2"]
        result = json.loads(execute(query, root, env))
        require(result['rows'] == [{'uid': 'emptyalice'}] and
                result['stats']['returned_rows'] == 1 and result['stats']['has_more'] is False,
                'offline query did not return the exact fixture user')
        execute(query[:-1] + ['select * from acceptance_unknown_table limit 1'], root, env, expected=2)
        require(inventory(root / 'native') == before, 'read-only query changed native data')
        unpack(fixtures / 'original-v2-empty.tar.gz', root / 'source')
        before = inventory(root / 'source')
        plan = {'version': 1, 'source_commit': 'a888f89533d0e7d1b2030e06504ca97f1ad891d4',
                'sources': [{'node_id': 1, 'data_dir': str(root / 'source'), 'shard_count': 2}],
                'target': {'cluster_id': 'cli-acceptance', 'created_at': '2026-09-09T00:00:00Z',
                           'slot_count': 4, 'hash_slot_count': 256, 'replicas': 1, 'channel_replicas': 1,
                           'nodes': [{'node_id': 101, 'addr': '127.0.0.1:57881',
                                      'data_dir': str(root / 'target')}]}}
        (root / 'plan.json').write_text(json.dumps(plan))
        diagnose = [str(wkcli), 'migrate', 'diagnose', '--plan', str(root / 'plan.json'),
                    '--workspace', str(root / 'diagnostic')]
        result = json.loads(execute(diagnose, root, env))
        require(result['status'] == 'no_findings_in_checked_scope' and result['scan_complete'] is True
                and result['cutover_ready'] is False and result['findings'] == 0
                and len(result['nodes']) == 1 and result['nodes'][0]['rows_checked'] > 0
                and result['nodes'][0]['primary_rows_by_table']['User'] == 1,
                'migration diagnosis did not complete the expected source scan')
        findings = Path(result['findings_file'])
        require(findings.parent == root / 'diagnostic' and findings.is_file(), 'unexpected findings path')
        require(sha256(findings.read_bytes()) == result['findings_sha256'], 'diagnostic findings digest mismatch')
        require(not (root / 'target').exists() and inventory(root / 'source') == before,
                'diagnosis wrote a target or changed source data')
        (root / 'plan.json').write_text('{}')
        execute(diagnose[:-1] + [str(root / 'invalid-diagnostic')], root, env, expected=1)
    return {'schema': 'wukongim/installed-cli-acceptance/v1', 'identity': identity,
            'checks': ['version', 'help', 'bench_validate', 'db_query', 'migrate_diagnose',
                       'invalid_inputs', 'read_only_data'], 'fixtures': digests, 'verified': True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--wkcli', type=Path, default=Path('/usr/bin/wkcli'))
    parser.add_argument('--server', type=Path, default=Path('/usr/bin/wukongim'))
    parser.add_argument('--version', required=True)
    parser.add_argument('--commit', required=True)
    parser.add_argument('--fixtures', type=Path, default=Path(__file__).resolve().parent.parent / 'tests/fixtures/wkcli-acceptance')
    args = parser.parse_args()
    try:
        receipt = validate(args.wkcli.resolve(), args.server.resolve(), args.version, args.commit, args.fixtures.resolve())
    except (AcceptanceError, OSError, ValueError, KeyError, TypeError, tarfile.TarError) as error:
        print(f'installed CLI acceptance failed: {error}', file=sys.stderr)
        return 1
    print(json.dumps(receipt, sort_keys=True, separators=(',', ':')))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
