#!/usr/bin/env python3
"""Plan offline transport of preview audit snapshots; never upload or activate."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import stat
import sys
import tempfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]


def _load(name: str, filename: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts' / filename)
    if spec is None or spec.loader is None:
        raise RuntimeError(f'cannot load reviewed helper: {filename}')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


R = _load('storage_plan_audit_receipt', 'package-audit-receipt.py')
C = _load('storage_plan_composer', 'compose-package-site.py')
INPUT_SCHEMA = 'wukongim.object_storage_plan_inputs/v1'
PLAN_SCHEMA = 'wukongim.object_storage_publication_plan/v1'
MAX_SNAPSHOTS = 8
MAX_TOTAL_ARCHIVE_BYTES = 2 * 1024 * 1024 * 1024
CONTROL_FILES = {
    'manifests/channels.json', 'manifests/preview-signing.json',
    'manifests/signing-toolchain.json', 'manifests/bootstrap-packages.json',
    'keys/apt-preview.asc', 'keys/rpm-preview.asc',
}
DESCRIPTOR_FIELDS = {
    'archive', 'receipt', 'control_dir', 'audit_release_id', 'control_sha',
    'archive_sha256', 'archive_size', 'receipt_sha256', 'snapshot_sha256',
    'source', 'control_files_sha256',
}
SOURCE_FIELDS = {'repository', 'version', 'release_id', 'source_sha'}
PUBLIC_PATH = re.compile(r'^[A-Za-z0-9_./+~-]+$')
RPM_REPO = 'rpm/preview/el/9/x86_64/'
IMMUTABLE_CACHE = 'public, max-age=31536000, immutable'


class PlanningError(ValueError):
    """The offline inputs cannot produce a consistent, bounded transport plan."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise PlanningError(message)


def local_path(value: Any, base: Path, label: str) -> Path:
    require(isinstance(value, str) and value and '\x00' not in value
            and '://' not in value, f'{label} must be a local path')
    path = Path(value)
    return path if path.is_absolute() else base / path


def real_directory(path: Path, label: str) -> None:
    mode = path.lstat().st_mode
    require(stat.S_ISDIR(mode) and not stat.S_ISLNK(mode), f'{label} must be a real directory')


def checked_file(path: Path, label: str, *, maximum_bytes: int,
                 expected_size: int | None = None) -> dict[str, Any]:
    """Reject size mismatches before opening a single-link regular input."""
    metadata = path.lstat()
    require(stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1,
            f'{label} must be a single-link regular file')
    if expected_size is not None:
        require(metadata.st_size == expected_size, f'{label} size differs from independent anchor')
    return C.hash_file(path, label, maximum_bytes=maximum_bytes)


def control_size_limit(relative: str) -> int:
    return (1024 * 1024 if relative.startswith('keys/')
            or relative == 'manifests/signing-toolchain.json' else R.MAX_JSON_BYTES)


def descriptor_identity(raw: Any) -> dict[str, Any]:
    item = C.exact(raw, DESCRIPTOR_FIELDS, 'snapshot descriptor')
    C.positive_integer(item['audit_release_id'], 'audit_release_id')
    C.positive_integer(item['archive_size'], 'archive_size')
    require(isinstance(item['control_sha'], str) and R.LOWER_SHA.fullmatch(item['control_sha']),
            'expected control identity must be a lowercase commit SHA')
    for field in ('archive_sha256', 'receipt_sha256', 'snapshot_sha256'):
        R.sha256_string(item[field], field)
    source = C.exact(item['source'], SOURCE_FIELDS, 'expected source identity')
    require(source['repository'] == R.SOURCE_REPOSITORY, 'source identity repository is unsupported')
    C.positive_integer(source['release_id'], 'source release ID')
    require(isinstance(source['source_sha'], str) and R.LOWER_SHA.fullmatch(source['source_sha']),
            'source identity commit is invalid')
    require(isinstance(source['version'], str) and C.VERSION_RE.fullmatch(source['version']),
            'source identity must be a strict preview version')
    hashes = C.exact(item['control_files_sha256'], CONTROL_FILES, 'control file SHA-256 inventory')
    for path, value in hashes.items():
        R.sha256_string(value, f'control file SHA-256 {path}')
    return item


def _public_path(path: str) -> None:
    require(PUBLIC_PATH.fullmatch(path) is not None, f'unsafe public path: {path}')
    C.safe_relative(path, 'public path')


def _metadata_closure(root: Path, control: Path, receipt: dict[str, Any]) -> tuple[dict, set[str]]:
    """Check reference bytes and safe paths, without running signatures or payloads."""
    site = root / 'site'
    files, directories = C.collect_tree(site, 'snapshot site')
    for path in files:
        _public_path(path)
    snapshot = C.load_json(root / 'audit/snapshot.json', 'snapshot', canonical=True)
    plan = C.load_json(root / 'audit/plan.json', 'publication plan', canonical=True)
    bootstrap = C.validate_bootstrap_inventory(
        C.load_json(site / 'bootstrap/manifest.json', 'bootstrap manifest', canonical=True),
        prepared=False,
    )
    bootstrap_control = C.exact(
        C.load_json(control / 'manifests/bootstrap-packages.json', 'bootstrap control'),
        {'schema', 'enabled', 'version'}, 'bootstrap control',
    )
    require(bootstrap_control == {'schema': 'wukongim.native_package_bootstrap/v1',
                                  'enabled': True, 'version': bootstrap['version']},
            'bootstrap control does not match the snapshot')
    for item in bootstrap['packages'].values():
        facts = {'sha256': item['published_sha256'], 'size': item['published_size']}
        for field in ('repository_path', 'download_path'):
            require(files.get(item[field]) == facts, f'bootstrap {field} bytes differ from manifest')
    rpm_key = snapshot['public_keys']['rpm']['sha256']
    require(C.read_checked(site / 'repo', 'repository entrypoint', maximum_bytes=C.MAX_METADATA_BYTES)
            == C.repository_entrypoint_bytes(bootstrap, rpm_key),
            'repository entrypoint differs from bootstrap identity')
    require(C.load_json(site / 'status.json', 'site status', canonical=True) == {
        'schema': C.STATUS_SCHEMA, 'apt': True, 'rpm': True, 'reason': 'ready',
        'audit_release_id': receipt['audit_release_id'], 'control_sha': receipt['control_sha'],
        'snapshot_sha256': receipt['archive']['snapshot_sha256'],
        'operation': receipt['plan']['operation'], 'target_version': receipt['plan']['target_version'],
    }, 'site status differs from the reviewed audit')
    inventory = {
        family: {entry['version']: dict(entry, new=entry['version'] in plan['new_versions'])
                 for entry in snapshot['payloads'][family]}
        for family in ('apt', 'rpm')
    }
    # Native zstd is deliberately outside this pure-Python planner's boundary.
    rpm_receipt = C.load_json(root / 'audit/rpm-signing.json', 'RPM signing receipt', canonical=True)
    repodata = rpm_receipt['result']['repodata']
    for item in repodata:
        relative = item['path']
        _public_path(relative)
        if relative in {'repodata/repomd.xml', 'repodata/repomd.xml.asc'}:
            continue
        require(Path(relative).suffix not in {'.zst', '.zstd'},
                'unsupported RPM metadata compression: zstd requires native verification')
    apt_files, _, _ = C.validate_apt_tree(
        site / 'apt', root / 'audit/apt-signing.json', inventory['apt'],
        bootstrap['packages']['apt'], plan['active_versions'], plan['retained_versions'],
    )
    rpm_files, _, _ = C.validate_rpm_tree(
        site / 'rpm', root / 'audit/rpm-signing.json', inventory['rpm'],
        bootstrap['packages']['rpm'], plan['active_versions'], plan['retained_versions'],
    )
    root_files = {'index.html', 'repo', 'status.json', 'signing-manifest.txt',
                  'keys/apt-preview.asc', 'keys/rpm-preview.asc', 'bootstrap/manifest.json'}
    bootstrap_downloads = {item['download_path'] for item in bootstrap['packages'].values()}
    expected = root_files | bootstrap_downloads | {'apt/' + p for p in apt_files} | {'rpm/' + p for p in rpm_files}
    require(set(files) == expected, 'unexpected site object or missing site closure')
    C.require_tree_closure(files, directories, expected, 'snapshot site')
    immutable = bootstrap_downloads | {
        path for path in files
        if path.startswith('apt/pool/') or '/by-hash/SHA256/' in path
        or path.startswith(RPM_REPO + 'Packages/')
    } | {RPM_REPO + item['path'] for item in repodata
         if item['path'] not in {'repodata/repomd.xml', 'repodata/repomd.xml.asc'}
         and Path(item['path']).name.startswith(item['sha256'] + '-')}
    return files, immutable


def _snapshot(item: dict[str, Any], base: Path) -> dict[str, Any]:
    archive = local_path(item['archive'], base, 'archive')
    receipt_path = local_path(item['receipt'], base, 'receipt')
    control = local_path(item['control_dir'], base, 'control directory')
    real_directory(control, 'control directory')
    initial_control = {}
    for relative, expected in sorted(item['control_files_sha256'].items()):
        initial_control[relative] = checked_file(control / relative, f'control file {relative}',
                                                 maximum_bytes=control_size_limit(relative))
        require(initial_control[relative]['sha256'] == expected,
                f'control file SHA-256 differs from independent anchor: {relative}')
    # The receipt helper checks byte relationships. Composer adds the explicit
    # preview-only version/capacity and disabled-stable scope restrictions.
    C.validate_channels(C.load_json(control / 'manifests/channels.json', 'channels control'))
    archive_facts = checked_file(archive, 'archive', maximum_bytes=item['archive_size'],
                                 expected_size=item['archive_size'])
    require(archive_facts['sha256'] == item['archive_sha256'], 'archive SHA-256 differs from independent anchor')
    receipt_facts = checked_file(receipt_path, 'receipt', maximum_bytes=R.MAX_JSON_BYTES)
    require(receipt_facts['sha256'] == item['receipt_sha256'], 'receipt SHA-256 differs from independent anchor')
    receipt, _ = R.load_json(receipt_path, 'external receipt', canonical=True)
    require(receipt.get('audit_release_id') == item['audit_release_id'], 'audit identity differs from independent anchor')
    require(receipt.get('control_sha') == item['control_sha'], 'control identity differs from independent anchor')
    require(receipt.get('archive', {}).get('snapshot_sha256') == item['snapshot_sha256'],
            'snapshot identity differs from independent anchor')
    require(receipt.get('plan', {}).get('operation') == 'add_release',
            'only add_release audit snapshots are supported by this planner')
    source = receipt.get('source')
    require(isinstance(source, dict) and {
        'repository': R.SOURCE_REPOSITORY, 'version': receipt['plan']['target_version'],
        'release_id': source.get('release_id'), 'source_sha': source.get('source_sha'),
    } == item['source'], 'source identity differs from independent anchor')
    with tempfile.TemporaryDirectory(prefix='wk-object-storage-plan-') as temporary:
        root = Path(temporary) / 'snapshot'
        summary = R.snapshot_archive.extract_snapshot(
            archive_path=archive, output_dir=root,
            max_members=R.snapshot_archive.DEFAULT_MAX_MEMBERS,
            max_total_size=R.ARCHIVE_MAX_TOTAL_BYTES,
        )
        require(summary['sha256'] == archive_facts['sha256'] and summary['size'] == archive_facts['size'],
                'archive changed before extraction')
        for member in summary['members']:
            if member['type'] == 'file' and member['name'].startswith('site/'):
                _public_path(member['name'][5:])
        verified = R.verify_audit_receipt(
            receipt_path=receipt_path, archive_path=archive,
            channels_path=control / 'manifests/channels.json',
            signing_path=control / 'manifests/preview-signing.json',
            signing_toolchain_path=control / 'manifests/signing-toolchain.json',
            apt_public_cert_path=control / 'keys/apt-preview.asc',
            rpm_public_cert_path=control / 'keys/rpm-preview.asc',
            plan_path=root / 'audit/plan.json', apt_receipt_path=root / 'audit/apt-signing.json',
            rpm_receipt_path=root / 'audit/rpm-signing.json',
            source_attestations_path=root / 'audit/source-attestations',
        )
        require(verified == receipt, 'receipt changed while validating snapshot')
        files, immutable = _metadata_closure(root, control, verified)
        prefix = f"snapshots/preview/r{item['audit_release_id']}-{item['snapshot_sha256']}"
        objects = []
        for member in summary['members']:
            if member['type'] != 'file':
                continue
            path = member['name']
            _public_path(path)
            facts = C.hash_file(root / path, 'snapshot object')
            objects.append({'object_key': prefix + '/' + path, 'sha256': facts['sha256'],
                            'size': facts['size'],
                            'cache_control': ('no-store' if path.startswith('site/')
                                              and path[5:] not in immutable else IMMUTABLE_CACHE),
                            'source': {'audit_release_id': item['audit_release_id'], 'member': path}})
        identity = {key: item[key] for key in (
            'audit_release_id', 'control_sha', 'archive_sha256', 'archive_size',
            'receipt_sha256', 'snapshot_sha256', 'source', 'control_files_sha256',
        )}
        result = {'identity': identity, 'prefix': prefix, 'objects': objects,
                  'files': files, 'immutable': immutable}
    require(checked_file(archive, 'archive', maximum_bytes=item['archive_size'],
                         expected_size=item['archive_size']) == archive_facts, 'archive changed while planning')
    require(checked_file(receipt_path, 'receipt', maximum_bytes=R.MAX_JSON_BYTES,
                         expected_size=receipt_facts['size']) == receipt_facts, 'receipt changed while planning')
    for relative, facts in initial_control.items():
        require(checked_file(control / relative, 'control file', maximum_bytes=control_size_limit(relative),
                             expected_size=facts['size']) == facts,
                'control file changed while planning')
    return result


def make_plan(input_path: Path) -> dict[str, Any]:
    """Build a deterministic plan, retaining every explicitly supplied generation."""
    inputs = C.exact(C.load_json(input_path, 'planner inputs'),
                     {'schema', 'channel', 'current', 'retain'}, 'planner inputs')
    require(inputs['schema'] == INPUT_SCHEMA, f'planner input schema must be {INPUT_SCHEMA}')
    require(inputs['channel'] == 'preview', 'only preview offline transport planning is supported')
    require(isinstance(inputs['retain'], list), 'retain must be an array')
    descriptors = [inputs['current'], *inputs['retain']]
    require(len(descriptors) <= MAX_SNAPSHOTS, 'planner accepts at most 8 snapshots')
    descriptors = [descriptor_identity(item) for item in descriptors]
    require(sum(item['archive_size'] for item in descriptors) <= MAX_TOTAL_ARCHIVE_BYTES,
            'planner total archive byte limit is 2 GiB')
    audit_ids = [item['audit_release_id'] for item in descriptors]
    require(len(set(audit_ids)) == len(audit_ids), 'duplicate audit identity in planner inputs')
    snapshots = [_snapshot(item, input_path.parent) for item in descriptors]
    current = snapshots[0]
    snapshots.sort(key=lambda snapshot: snapshot['identity']['audit_release_id'])
    aliases: dict[str, dict[str, Any]] = {}
    for snapshot in snapshots:
        for path in sorted(snapshot['immutable']):
            facts = snapshot['files'][path]
            uri = '/' + path
            item = {'public_uri': uri, 'object_key': 'public/' + path,
                    'sha256': facts['sha256'], 'size': facts['size'], 'cache_control': IMMUTABLE_CACHE,
                    'source': {'audit_release_id': snapshot['identity']['audit_release_id'], 'member': 'site/' + path}}
            if uri in aliases:
                require(all(aliases[uri][field] == item[field]
                            for field in ('object_key', 'sha256', 'size', 'cache_control')),
                        f'immutable URI conflict across snapshots: {uri}')
            else:
                aliases[uri] = item
    entrypoints = [
        {'public_uri': '/' + path, 'object_key': current['prefix'] + '/site/' + path,
         'sha256': facts['sha256'], 'size': facts['size'], 'cache_control': 'no-store'}
        for path, facts in sorted(current['files'].items()) if path not in current['immutable']
    ]
    return {
        'schema': PLAN_SCHEMA, 'status': 'plan_only', 'plan_only': True, 'channel': 'preview',
        'current_audit_release_id': current['identity']['audit_release_id'],
        'verification': {'archive_and_receipt_consistent': True, 'metadata_closure_checked': True,
                         'signatures_verified': False, 'github_provenance_verified': False,
                         'control_commit_verified': False, 'cloud_verified': False,
                         'activation_authorized': False},
        'snapshots': [snapshot['identity'] for snapshot in snapshots],
        'snapshot_objects': sorted((obj for snapshot in snapshots for obj in snapshot['objects']),
                                   key=lambda item: item['object_key']),
        'immutable_aliases': [aliases[key] for key in sorted(aliases)],
        'entrypoints': entrypoints,
        'retention': {'policy': 'retain_all_supplied_snapshots_no_gc',
                      'retained_audit_ids': sorted(audit_ids[1:]), 'delete_objects': []},
        'limitations': ['External anchors are caller-reviewed claims, not authenticated by this command.',
                        'Only preview add_release snapshots are supported; no stable or multi-channel activation.',
                        'No CDN atomicity, signature freshness, rollback eligibility or cloud state is established.',
                        'No upload, activation, signing, credential access or deletion is performed.'],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inputs', required=True, type=Path, help='Local descriptor with independently reviewed identities')
    parser.add_argument('--output', required=True, type=Path, help='New canonical JSON plan; existing paths are rejected')
    args = parser.parse_args(argv)
    try:
        require(not os.path.lexists(args.output), 'planner output already exists')
        real_directory(args.output.parent, 'output parent')
        plan = make_plan(args.inputs)
        raw = C.canonical_json(plan)
        R._write_exclusive(args.output, plan)
    except (PlanningError, C.CompositionError, R.AuditReceiptError,
            R.snapshot_archive.ArchiveError, OSError, ValueError, TypeError, KeyError) as error:
        print(f'object-storage planning failed: {error}', file=sys.stderr)
        return 1
    print(C.canonical_json({'schema': 'wukongim.object_storage_plan_receipt/v1', 'status': 'plan_only',
                            'plan_sha256': hashlib.sha256(raw).hexdigest(), 'plan_size': len(raw),
                            'snapshot_count': len(plan['snapshots'])}).decode(), end='')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
