"""Read-only fresh input binding for the SDK library; no writer or executable CLI.

Historical inputs remain data. Only helpers in this executing checkout run.
A successful observation is not publication authority and must be fenced again.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import tempfile

ROOT=Path(__file__).resolve().parent


def module(name):
    spec=importlib.util.spec_from_file_location('fresh_'+name.replace('-','_'),ROOT/name)
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value


D=module('prepare-object-storage-delivery.py')
S=module('verify-stable-seal-inputs.py')
A=module('resolve-audit-release.py')
C=D.C


class InputError(ValueError):
    """Fresh remote facts or independently anchored local inputs differ."""


def require(condition, message):
    if not condition:raise InputError(message)


def verify_stable_control(*, reader, plan_path, control_root, executor_sha, seal_control_sha):
    """Keep historical seal identity separate from the legacy helper's current SHA."""
    value=S.verify_control(reader=reader,plan_path=plan_path,control_root=control_root,
                           expected_control_sha=executor_sha,test_only=False)
    S.require_ancestor(reader,seal_control_sha,executor_sha)
    return {**value,'executor_sha':executor_sha,'seal_control_sha':seal_control_sha}


def audit_identity(value):
    require(value.get('classification')=='immutable_complete' and value.get('draft') is False
            and value.get('immutable') is True and value.get('tag_commit_verified') is True
            and value.get('id_bound_downloads') is True and value.get('release_revalidated') is True,
            'fresh immutable audit verification incomplete')
    assets=value.get('assets')
    require(isinstance(assets,list) and len(assets)==2 and len({x['id'] for x in assets})==2
            and len({x['name'] for x in assets})==2,'audit asset identity incomplete')
    return {**{k:value[k] for k in ('repository','release_id','tag_name','control_sha','published_at')},
            'assets':sorted(({k:x[k] for k in ('id','name','size','sha256')} for x in assets),key=lambda x:x['name'])}


def require_same_anchors(previous, current):
    """Recomputed immutable facts, not observation timestamps, fence each new write phase."""
    fields=('executor_sha','inputs_sha256','plan_sha256','audits','sources')
    require(all(previous[k]==current[k] for k in fields),'fresh delivery anchors drifted')


def _preview_control(reader, item, base, current):
    """Authenticate the six existing preview control files as historical Git data."""
    historical=item['control_sha'];S.require_ancestor(reader,historical,current)
    commit=reader.api_json(S.PACKAGE_API+'git/commits/'+historical)
    tree_sha=commit.get('tree',{}).get('sha')
    require(commit.get('sha')==historical and isinstance(tree_sha,str) and re.fullmatch('[0-9a-f]{40}',tree_sha),'historical preview commit differs')
    tree=reader.api_json(S.PACKAGE_API+'git/trees/'+tree_sha+'?recursive=1')
    require(tree.get('sha')==tree_sha and tree.get('truncated') is False and isinstance(tree.get('tree'),list),'historical preview tree incomplete')
    rows=tree['tree'];require(len({x['path'] for x in rows})==len(rows),'duplicate Git tree path')
    entries={x['path']:x for x in rows}
    for name,expected in item['control_files_sha256'].items():
        local=D.P.local_path(item['control_dir'],base,'preview controls')/name
        raw=C.read_checked(local,'preview control',maximum_bytes=1024*1024)
        require(hashlib.sha256(raw).hexdigest()==expected,'preview control changed')
        blob_sha=hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
        entry=entries.get(name,{})
        require(entry.get('type')=='blob' and entry.get('mode') in ('100644','100755')
                and entry.get('sha')==blob_sha and entry.get('size')==len(raw),'historical preview control blob differs')
        blob=reader.api_json(S.PACKAGE_API+'git/blobs/'+blob_sha)
        require(blob.get('sha')==blob_sha and blob.get('size')==len(raw) and blob.get('encoding')=='base64'
                and len(blob.get('content',''))<=2*1024*1024,'historical preview blob response differs')
        require(base64.b64decode(blob['content'].replace('\n',''),validate=True)==raw,'historical preview control bytes differ')


def _preview_source(item, base, source_token, scratch, budget=None):
    """Use the original preview resolver and both real preflight commands on seven assets."""
    archive=D.P.local_path(item['archive'],base,'preview archive')
    extracted=scratch/'snapshot'
    summary=D.P.R.snapshot_archive.extract_snapshot(archive_path=archive,output_dir=extracted,
        max_members=D.P.R.snapshot_archive.DEFAULT_MAX_MEMBERS,max_total_size=D.P.R.ARCHIVE_MAX_TOTAL_BYTES)
    require(summary['sha256']==item['archive_sha256'] and summary['size']==item['archive_size'],'preview archive drifted')
    original=C.load_json(extracted/'audit/source-attestations/source-attestations.json','source attestation summary',canonical=True)
    fresh=S.SOURCE.resolve_source_release(release_id=item['source']['release_id'],output_dir=scratch/'assets',
        api_base_url='https://api.github.com',download_base_url='https://api.github.com',token=source_token,channel='preview',budget=budget)
    require({k:fresh[k] for k in ('repository','version','release_id','source_sha')}==item['source'], 'fresh preview source differs')
    require({x['name']:x['sha256'] for x in fresh['assets']}=={x['asset']:x['asset_sha256'] for x in original['assets']},
            'fresh seven-asset source closure differs from archived attestations')
    receipt=scratch/'resolution.json';receipt.write_bytes(C.canonical_json(fresh))
    S.run_checked_helper('verify-source-attestations.py',['--channel', 'preview','--receipt',str(receipt),
        '--asset-dir',str(scratch/'assets'),'--evidence-dir',str(scratch/'attestations')],home=scratch,source_token=source_token,budget=budget)
    S.run_checked_helper('verify-source-package-metadata.py',['--channel', 'preview','--receipt',str(receipt),
        '--asset-dir',str(scratch/'assets')],home=scratch,budget=budget)
    return S.source_identity(fresh)


def _executor_clean(executor_sha, budget=None):
    """Bind clean executing bytes and clamp each Git read to remaining time."""
    for arguments in (['git','rev-parse','HEAD'], ['git','status','--porcelain','--untracked-files=all']):
        if budget is not None: budget.check()
        result=subprocess.run(arguments,cwd=ROOT.parent,capture_output=True,text=True,check=False,
            timeout=min(10,budget.remaining()) if budget is not None else 10)
        if budget is not None: budget.check()
        expected=executor_sha if arguments[1]=='rev-parse' else ''
        require(result.returncode==0 and result.stdout.strip()==expected,'executing checkout or clean state differs')


def verify_delivery_inputs(*, inputs, expected_plan_sha256, executor_sha, source_token=None, package_token=None,
                           previous=None, budget=None):
    """Run original local, fresh GitHub and source checks; re-run to fence before CDN.

    The first v1 observation anchors asset IDs absent from the original descriptor.
    v2 additionally compares IDs to its historical seal resolution. Neither path
    changes the original input or plan, nor upgrades original false receipt fields.
    """
    try:
        inputs=Path(inputs)
        value=json.loads(D._read(inputs,'delivery inputs'),object_pairs_hook=C.reject_duplicate_pairs)
        require(value.get('test_only',False) is False,'TEST ONLY inputs cannot enter fresh production authentication')
        composite=value.get('schema')=='wukongim.object_storage_plan_inputs/v2'
        plan,raw,value=D._load_plan(inputs,expected_plan_sha256,composite,False)
        require(isinstance(executor_sha,str) and re.fullmatch('[0-9a-f]{40}',executor_sha),'executor SHA invalid')
        _executor_clean(executor_sha,budget)
        reader=A.GitHubReader('https://api.github.com','https://api.github.com',package_token,budget=budget)
        S.current_control(reader,executor_sha)
        audits=[];sources=[];controls=[]
        for channel,item in D._descriptors(value,composite):
            path=lambda field:D.P.local_path(item[field],inputs.parent,field)
            seal=item['seal_control_sha'] if channel=='stable' else item['control_sha']
            with tempfile.TemporaryDirectory(prefix='wk-provider-inputs-') as tmp:
                scratch=Path(tmp)
                if channel=='stable':
                    controls.append(verify_stable_control(reader=reader,plan_path=path('plan'),control_root=path('control_dir'),
                        executor_sha=executor_sha,seal_control_sha=seal))
                    fresh=S.verify_seal_inputs(reader=reader,expected_control_sha=executor_sha,archive_path=path('archive'),
                        receipt_path=path('receipt'),plan_path=path('plan'),control_root=path('control_dir'),source_root=path('source_dir'),
                        apt_receipt=path('apt_receipt'),rpm_receipt=path('rpm_receipt'),source_token=source_token,test_only=False,budget=budget)
                    source=fresh['source']
                else:
                    _preview_control(reader,item,inputs.parent,executor_sha)
                    source=_preview_source(item,inputs.parent,source_token,scratch,budget)
                require(source['source_sha']!=D.V.TEST_PRODUCT_SHA,'TEST ONLY source identity refused')
                sources.append({'channel':channel,'audit_release_id':item['audit_release_id'],'identity':source})
                fresh=A.resolve_audit_release(release_id=item['audit_release_id'],expected_control_sha=seal,
                    output_dir=scratch/'audit',api_base_url='https://api.github.com',download_base_url='https://api.github.com',
                    token=package_token,expected_tag_state='exact',channel=channel,test_only=False,
                    candidate_plan=path('plan') if channel=='stable' else None,candidate_receipt=path('receipt') if channel=='stable' else None,budget=budget)
                identity=audit_identity(fresh)
                if channel=='stable':
                    original=C.load_json(path('resolution'),'historical seal resolution',canonical=True)
                    require(identity==audit_identity(original),'fresh seal immutable identity differs')
                else:
                    expected={path('archive').name:{'size':item['archive_size'],'sha256':item['archive_sha256']},
                              path('receipt').name:C.hash_file(path('receipt'),'preview receipt',maximum_bytes=D.MAX_JSON_BYTES)}
                    require({x['name']:{k:x[k] for k in ('size','sha256')} for x in identity['assets']}==expected,
                            'fresh preview audit bytes differ')
                audits.append({'channel':channel,**identity})
        _,final_raw,_=D._load_plan(inputs,expected_plan_sha256,composite,False)
        require(final_raw==raw,'local input bytes changed during fresh verification')
        S.current_control(reader,executor_sha)
        _executor_clean(executor_sha,budget)
        result={'executor_sha':executor_sha,'inputs_sha256':hashlib.sha256(raw).hexdigest(),'plan_sha256':expected_plan_sha256,
                'audits':audits,'sources':sources,'controls':controls,'production_enabled':False,'publication_verified':False,
                'cloud_verified':False,'original_verification':copy.deepcopy(plan['verification'])}
        if previous is not None:require_same_anchors(previous,result)
        return result
    except Exception:
        raise InputError('fresh delivery input authentication failed') from None


def revalidate_delivery_anchors(*, inputs, expected_plan_sha256, previous,
                                source_token=None, package_token=None, budget=None):
    """Fence immutable API metadata without downloading payloads per object.

    The preceding complete verification binds local bytes, attestations and native
    metadata. This observation rechecks numeric releases, tags, asset IDs/digests,
    source ancestry, current control and clean execution before the next write.
    Complete verification still runs again at the end of the staging phase.
    """
    try:
        inputs=Path(inputs)
        raw=D._read(inputs,'delivery metadata fence inputs')
        require(hashlib.sha256(raw).hexdigest()==previous['inputs_sha256']
                and expected_plan_sha256==previous['plan_sha256'],'delivery input/plan anchor changed')
        value=json.loads(raw,object_pairs_hook=C.reject_duplicate_pairs)
        composite=value.get('schema')=='wukongim.object_storage_plan_inputs/v2'
        descriptors={(channel,item['audit_release_id']):item for channel,item in D._descriptors(value,composite)}
        executor=previous['executor_sha'];_executor_clean(executor,budget)
        reader=A.GitHubReader('https://api.github.com','https://api.github.com',package_token,budget=budget)
        S.current_control(reader,executor)
        sources=[]
        for item in previous['sources']:
            original=item['identity'];channel=item['channel']
            source_reader=S.SOURCE.GitHubReader('https://api.github.com','https://api.github.com',source_token,budget=budget)
            snapshot=S.SOURCE._release_snapshot(source_reader.api_json(
                'repos/'+S.SOURCE.SOURCE_REPOSITORY+'/releases/'+str(original['release_id'])),
                original['release_id'],channel)
            observed={'repository':S.SOURCE.SOURCE_REPOSITORY,'release_id':original['release_id'],
                'tag':snapshot['tag'],'version':snapshot['version'],'prerelease':snapshot['prerelease'],
                'published_at':snapshot['published_at'],'source_sha':S.SOURCE._peel_tag(source_reader,snapshot['tag']),
                'assets':list(snapshot['assets'].values()),'checksum_asset':snapshot['checksum_name'],
                'checksum_entries':original['checksum_entries']}
            require(S.source_identity(observed)==original,'source immutable metadata changed')
            S.SOURCE._verify_main_ancestry(source_reader,original['source_sha'])
            sources.append(copy.deepcopy(item))
        audits=[]
        for original in previous['audits']:
            channel=original['channel'];item=descriptors[(channel,original['release_id'])]
            candidate=item['candidate'] if channel=='stable' else None
            snapshot=A._release_snapshot(reader.api_json('repos/'+A.AUDIT_REPOSITORY+'/releases/'+str(original['release_id'])),
                original['release_id'],original['control_sha'],channel,candidate)
            require(snapshot['classification']==A.IMMUTABLE_COMPLETE and snapshot['draft'] is False
                    and snapshot['immutable'] is True,'audit immutable metadata changed')
            A._tag_snapshot(reader,snapshot['tag_name'],original['control_sha'])
            S.require_ancestor(reader,original['control_sha'],executor)
            observed={'channel':channel,'repository':A.AUDIT_REPOSITORY,'release_id':snapshot['id'],
                'tag_name':snapshot['tag_name'],'control_sha':snapshot['target_commitish'],
                'published_at':snapshot['published_at'],
                'assets':sorted(snapshot['assets'].values(),key=lambda x:x['name'])}
            require(observed==original,'audit numeric asset identity changed')
            audits.append(observed)
        S.current_control(reader,executor);_executor_clean(executor,budget)
        require(D._read(inputs,'delivery metadata fence inputs')==raw,'delivery inputs changed during metadata fence')
        return {'schema':'wukongim.object_storage_delivery_metadata_fence/v1','executor_sha':executor,
            'inputs_sha256':previous['inputs_sha256'],'plan_sha256':expected_plan_sha256,
            'sources':sources,'audits':audits,'asset_bytes_downloaded':False,'native_helpers_run':False,
            'production_enabled':False,'publication_verified':False,'cloud_verified':False}
    except Exception:
        raise InputError('fresh delivery metadata fence failed') from None
