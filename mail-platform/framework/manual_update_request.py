"""Bind manual authorization to one signed release and preserve its receipt."""
from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
import re

from host_transaction import regular
from release import require, version
from updater import UpdateBusy, save

PENDING = 'manual-request.json'


@contextmanager
def locked(root):
    with (root/'update.lock').open('a+b') as descriptor:
        try:
            fcntl.flock(descriptor,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:
            raise UpdateBusy(descriptor) from None
        yield


def record(path):
    if not os.path.lexists(path):
        return None
    raw, attrs = regular(path, 2*1024*1024)
    require(attrs['uid']==os.geteuid() and attrs['mode']==0o600, 'manual_update_record_permissions')
    return json.loads(raw)


def bound(value):
    return (isinstance(value,dict)
            and set(value)=={'format','request_id','actor','version','release_sha256'}
            and type(value['format']) is int and value['format']==1 and isinstance(value['request_id'],str)
            and re.fullmatch('[a-f0-9]{32}',value['request_id']) is not None
            and isinstance(value['actor'],str) and re.fullmatch('[1-9][0-9]{0,19}',value['actor']) is not None
            and isinstance(value['version'],str)
            and isinstance(value['release_sha256'],str)
            and re.fullmatch('[a-f0-9]{64}',value['release_sha256']) is not None)


def reconcile(root):
    """Called with update.lock held. Unknown and rolled-back requests remain pending."""
    path = root/PENDING
    pending = record(path)
    if not bound(pending):
        return pending
    tx = record(root/'transaction.json')
    if (not tx or tx.get('phase')!='complete' or tx.get('manual_request')!=pending
            or tx.get('version')!=pending['version'] or tx.get('archive_sha256')!=pending['release_sha256']):
        return pending
    identifier = tx.get('id')
    require(isinstance(identifier,str) and re.fullmatch('[0-9]{1,30}',identifier), 'manual_update_transaction_id')
    directory = root/('transaction-'+identifier)
    require(not directory.is_symlink(), 'manual_update_transaction_path')
    journal = record(directory/'journal.json')
    # The commit pointer is saved first. A crash before the final journal write
    # leaves the same proven events with only the earlier health phase.
    require(journal in (tx,dict(tx,phase='health_started')), 'manual_update_journal_mismatch')
    require([event.get('action') for event in tx.get('events',[])]==['plan','stage','activate','health'],
            'manual_update_completion_events')
    installed = record(root/'installed.json')
    require(installed=={'version':tx['version'],'release':tx['release'],'previous':tx['old']['release']},
            'manual_update_installed_mismatch')
    receipt_path = root/('completed-request-'+pending['request_id']+'.json')
    receipt = {'format':1,'phase':'complete','request':pending,'transaction_id':identifier}
    existing = record(receipt_path)
    require(existing is None or existing==receipt,'manual_update_completion_receipt_conflict')
    if existing is None:
        save(receipt_path,receipt)
    require(record(path)==pending,'manual_update_request_changed')
    path.unlink()
    descriptor = os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return None


def pending_for_worker(root):
    with locked(root):
        result = reconcile(root)
        require(result is None or bound(result),'manual_update_legacy_request_requires_review')
        return result


def reserve(root, request_id, actor, expected_version):
    with locked(root):
        require(reconcile(root) is None,'request_pending')
        available = record(root/'available.json') or {}
        installed = record(root/'installed.json') or {'version':'0.0.0'}
        require(available.get('verified') is True,'manual_update_verified_candidate_required')
        request = {'format':1,'request_id':request_id,'actor':actor,'version':available.get('version'),
                   'release_sha256':available.get('cache_sha256',{}).get('mail-platform.tar.gz')}
        require(bound(request) and request['version']==expected_version
                and version(request['version'])>version(installed['version']),
                'manual_update_verified_candidate_required')
        save(root/PENDING,request)
        return request
