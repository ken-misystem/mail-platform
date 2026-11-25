"""Rebind package executables and recover services after MariaDB changes invocation."""
from contextlib import ExitStack, contextmanager
import json
import os
from pathlib import Path
import re
import stat
import time
import uuid

from certificate_state import certificate_lock, failure, private_directory, require, require_settled, trusted
from host_transaction import Commands, CommandFailure, Files, durable_json
from os_package_proof import EXECUTABLES, LIMIT, command, prove
from release import sha


STATE = Path('/var/lib/mail-platform-os-reconcile')
BOOT = Path('/proc/sys/kernel/random/boot_id')
PUBLISHED = '/etc/mail-client-certificates-v1/activation-approved.json'
SETUP = '/var/lib/mail-platform-setup/state.json'
RECEIPT = '/var/lib/mail-platform-update/installed-code.json'
LIB = '/usr/local/lib/mail-client-certificates-v1/'
MANIFEST = LIB+'runtime-manifest.json'
CONFIG = '/etc/mail-client-certificates-v1/'
ACTORS = ('issuer','verifier','lifecycle','gate','owner')
CERT = tuple('mail-client-cert-'+name+'.service' for name in ACTORS)
ISSUER, VERIFIER, LIFECYCLE, GATE, OWNER = CERT
SOCKET = 'mail-client-cert-gate.socket'
CERTIFICATES = (*CERT,SOCKET)
FEATURE = 'mail-feature-config-v1.service'
DB = 'mariadb.service'
PREREQUISITES = ('mail-client-cert-network.service','mail-client-cert-coordination.service',
                 'mail-client-cert-postfix-backend.service','mail-client-cert-dovecot-backend.service','rspamd.service')
UNITS = (DB,*CERTIFICATES,FEATURE,*PREREQUISITES)
START = ((ISSUER,), (VERIFIER,LIFECYCLE), (SOCKET,GATE), (OWNER,))
STOP = (OWNER,SOCKET,GATE,LIFECYCLE,VERIFIER,ISSUER)
HEARTBEAT = '/run/mail-client-certificates-v1/gate/health.json'
PENDING = 'in-flight.json'


class Deferred(Exception):
    pass


@contextmanager
def package_locks():
    import fcntl
    with ExitStack() as stack:
        for name in ('lock-frontend','lock'):
            descriptor = os.open('/var/lib/dpkg/'+name,os.O_RDWR|os.O_NOFOLLOW|os.O_CLOEXEC)
            stack.callback(os.close,descriptor)
            info = os.fstat(descriptor)
            require(stat.S_ISREG(info.st_mode) and info.st_uid==0 and info.st_nlink==1 and not info.st_mode&0o022,
                    'os_dpkg_lock_attributes')
            try:
                fcntl.lockf(descriptor,fcntl.LOCK_EX|fcntl.LOCK_NB)
            except BlockingIOError:
                raise Deferred('os_package_transaction_active') from None
        yield


def allow_published():
    if not os.path.lexists(PUBLISHED):
        return False
    trusted(PUBLISHED)
    return not os.path.lexists(SETUP) or document(SETUP, private=True)['phase']=='published'


def document(path, *, private=False):
    return json.loads(trusted(path,private=private,limit=16*1024**2)[0])


def metadata(raw, before):
    return dict(before,sha256=sha(raw))


def staged(entry, document):
    raw = (json.dumps(document,sort_keys=True,indent=2)+'\n').encode()
    return {'raw':raw,'before':entry,'after':metadata(raw,entry)}


def prepared_files(accepted):
    raw, old = trusted(MANIFEST)
    manifest = json.loads(raw)
    receipt_raw, receipt = trusted(RECEIPT,private=True,limit=16*1024**2)
    registry = json.loads(receipt_raw)
    require(registry['format']==2 and registry['code'].get(MANIFEST)==old, 'os_manifest_registration_drift')
    changes = {}
    for key,item in accepted.items():
        require(key in EXECUTABLES,'os_manifest_executable_scope')
        manifest[key] = item['executable_sha256']
    changes[MANIFEST] = staged(old,manifest)
    new = changes[MANIFEST]['after']['sha256']
    for actor in ACTORS:
        path = CONFIG+actor+'.json'
        cfg_raw, cfg_meta = trusted(path)
        value = json.loads(cfg_raw)
        require(value['actor']==actor and value['profile']=='production' and value['release']==LIB.rstrip('/')
                and value['manifest_sha256']==old['sha256'], 'os_actor_manifest_drift:'+actor)
        for field,(_,path_exe) in EXECUTABLES.items():
            require(value['executables'][field.removesuffix('_pin')]==path_exe,'os_actor_executable_path:'+actor)
        value['manifest_sha256'] = new
        changes[path] = staged(cfg_meta,value)
    registry['code'][MANIFEST] = changes[MANIFEST]['after']
    changes[RECEIPT] = staged(receipt,registry)
    # Existing registered files have explicit, simple ownership and modes. Do
    # not drop site-added ACLs or labels on an automatic replacement.
    require(not any(os.listxattr(path) for path in changes), 'os_extended_attributes_require_review')
    return changes


def read_units():
    raw = command(['/usr/bin/systemctl','show','--no-pager','-p',
        'Id,ActiveState,SubState,MainPID,LoadState,UnitFileState,Job,InvocationID,BindReadOnlyPaths',*UNITS]).decode()
    states = {}
    for block in raw.strip().split('\n\n'):
        row = dict(line.split('=',1) for line in block.splitlines())
        states[row['Id']] = row
    require(set(states)==set(UNITS), 'os_unit_inventory')
    if any(st['Job'] not in ('','0') or st['ActiveState'] in ('activating','deactivating','reloading') for st in states.values()):
        raise Deferred('os_pending_service_job')
    return states


def running(snapshot, names):
    return all(snapshot[name]['ActiveState']=='active' for name in names)


def choose(previous, current, boot, binary_change):
    invocation = current[DB]['InvocationID']
    require(re.fullmatch('[a-f0-9]{32}',invocation) and int(invocation,16)>0,'os_db_invocation_id')
    cert_live = running(current,CERTIFICATES)
    feature_live = running(current,(FEATURE,))
    if not previous or previous['boot']!=boot:
        return {'certificates':cert_live,'feature':feature_live,'restore_certificates':False,
                'restore_feature':False,'rebind_live':bool(binary_change and cert_live)}
    db_restarted = previous['database']!=invocation
    eligible_cert = cert_live or (db_restarted and previous['certificates'])
    eligible_feature = feature_live or (db_restarted and previous['feature'])
    return {'certificates':eligible_cert,'feature':eligible_feature,
            'restore_certificates':eligible_cert and not cert_live,
            'restore_feature':eligible_feature and not feature_live,
            'rebind_live':bool(eligible_cert and binary_change)}


def observe_database(before):
    now = read_units()
    require(running(now,(DB,*PREREQUISITES)) and all(now[name]['InvocationID']==before[name]['InvocationID']
            for name in (DB,*PREREQUISITES)), 'os_protected_service_changed')
    return now


def observe_gate(start):
    addresses = document(CONFIG+'gate.json')['public_addresses']
    require(type(addresses) is list and addresses, 'os_gate_public_addresses')
    required = {(address, str(port)) for address in addresses for port in (587,993,995)}
    deadline = time.monotonic()+35
    while time.monotonic()<deadline:
        try:
            # The public heartbeat is owned by mailcert-gate rather than root.
            from host_transaction import regular
            raw,attrs = regular(HEARTBEAT,65536)
            import pwd
            require(attrs['uid']==pwd.getpwnam('mailcert-gate').pw_uid and not attrs['mode']&0o022,'os_gate_observation_owner')
            value = json.loads(raw)
        except FileNotFoundError:
            time.sleep(0.5)
            continue
        expires = value['crl_expires']
        if value['threads_healthy'] is True and start-1<=value['observed_at']<=time.time()+1 and expires>time.time():
            from ipaddress import ip_address
            listeners = command(['/usr/bin/ss','-H','-lnt','( sport = :587 or sport = :993 or sport = :995 )']).decode()
            present = set()
            for line in listeners.splitlines():
                address, _, port = line.split()[3].rpartition(':')
                if address not in ('*',''):
                    present.add((str(ip_address(address.strip('[]').split('%',1)[0])),port))
            if not {(str(ip_address(address)),port) for address,port in required} <= present:
                time.sleep(0.5)
                continue
            require(type(value['crl_number']) is int and value['crl_number']>=0,'os_gate_crl_number')
            return {key:value[key] for key in ('observed_at','crl_number','crl_expires')}
        time.sleep(0.5)
    raise ValueError('os_certificate_gate_observation_missing')


def operation(commands, label, action, names):
    commands.run(label,['/usr/bin/systemctl','--job-mode=fail',action,'--quiet',*names],timeout=90)


def transact(state, before, replacements, packages, actions):
    evidence = state/('run-'+uuid.uuid4().hex)
    evidence.mkdir(mode=0o700)
    durable_json(state/PENDING,{'evidence':evidence.name,'phase':'started'})
    commands, files = Commands(evidence), Files('/',evidence)
    start = time.time()
    attempted = []
    commit_ready = False
    try:
        restart = actions['restore_certificates'] or actions['rebind_live']
        scope = (*CERTIFICATES,FEATURE) if restart and actions['restore_feature'] else (
            CERTIFICATES if restart else (FEATURE,) if actions['restore_feature'] else ())
        require(all(before[n]['LoadState']=='loaded' and before[n]['UnitFileState'] not in ('masked','masked-runtime')
                    for n in scope),'os_service_intentionally_masked')
        require(not any(before[n].get('BindReadOnlyPaths') for n in CERT) or not replacements,
                'os_alternate_certificate_view_requires_review')
        durable_json(evidence/'before.json',{'database':before[DB]['InvocationID'],'actions':actions,
                                            'packages':packages,'files':{n:v['before'] for n,v in replacements.items()}})
        live = tuple(name for name in STOP if before[name]['ActiveState']=='active')
        if restart and live:
            operation(commands,'stop_certificates','stop',live)
        if restart or replacements:
            stopped = observe_database(before)
            require(all(stopped[n]['ActiveState'] in ('inactive','failed') for n in CERTIFICATES),
                    'os_certificate_services_not_quiet')
        for path,item in replacements.items():
            attributes = item['before']
            files.write(path,item['raw'],attributes['mode'],attributes['uid'],attributes['gid'],expected_before=attributes)
        if restart:
            # A socket that reached its trigger limit is rearmed only after
            # the matching executable evidence and bindings have been written.
            for n in (ISSUER,SOCKET):
                if before[n]['ActiveState']=='failed':
                    commands.run('clear_'+n.split('.')[-1],['/usr/bin/systemctl','reset-failed',n],timeout=10)
            for index,names in enumerate(START):
                attempted.extend(names)
                operation(commands,'start_certificates_'+str(index),'start',names)
            result = {'gate':observe_gate(start)}
            require(running(observe_database(before),CERTIFICATES),'os_certificate_service_inactive')
        else:
            result = {}
        # The certificate group has passed its own checks. A separate feature
        # publisher failure should not reopen the certificate outage.
        commit_ready = True
        if actions['restore_feature']:
            operation(commands,'restore_feature_config','start',(FEATURE,))
            require(running(observe_database(before),(FEATURE,)),'os_feature_service_inactive')
        require(all(trusted(n,limit=16*1024**2)[1]==item['after'] for n,item in replacements.items()),'os_pin_readback_drift')
        result.update(status='reconciled',evidence=evidence.name,files=len(replacements),
                      restored_feature=actions['restore_feature'],packages=packages)
        durable_json(evidence/'result.json',result)
        return result
    except Exception as exc:
        disposition = {'status':'held'}
        try:
            uncertain = isinstance(exc,CommandFailure) and (exc.record.get('timed_out') or exc.record.get('spawn_error'))
            if not commit_ready and not uncertain:
                current = observe_database(before)
                started = [n for n in STOP if n in attempted and current[n]['ActiveState']=='active']
                if started:
                    operation(commands,'stop_confined_failure','stop',started)
                current = observe_database(before)
                if all(current[n]['ActiveState'] in ('inactive','failed') for n in CERTIFICATES):
                    disposition = files.restore()
        finally:
            failure(evidence,exc,'os_reconciliation',disposition)
            durable_json(state/PENDING,{'evidence':evidence.name,'phase':'held'})
        raise


def reconcile(state):
    if not allow_published():
        return {'status':'unpublished'}
    require_settled()
    by_boot = BOOT.read_text().strip()
    before = read_units()
    if not running(before,(DB,*PREREQUISITES)):
        raise Deferred('os_dependencies_not_ready')
    previous = document(state/'baseline.json',private=True) if (state/'baseline.json').exists() else None
    marker = state/PENDING
    if marker.exists():
        raise ValueError('os_pending_transaction_requires_review')
    manifest = document(MANIFEST)
    native = {field:trusted(binary,limit=LIMIT)[1] for field,(_,binary) in EXECUTABLES.items()}
    drift = {field:meta for field,meta in native.items() if manifest[field]!=meta['sha256']}
    actions = choose(previous,before,by_boot,drift)
    result = {'status':'observed'}
    packages = {}
    if actions['restore_feature'] and drift and actions['restore_certificates']:
        # This worker can restore the DB-dependent publisher independently if
        # certificate executable proof is temporarily unavailable.
        feature = {**actions,'restore_certificates':False,'rebind_live':False}
        transact(state,before,{}, {},feature)
        marker.unlink()
        actions['restore_feature'] = False
    if drift:
        packages = {field:prove(field,meta) for field,meta in drift.items()}
        ready = observe_database(before)
        require(all(trusted(EXECUTABLES[field][1],limit=LIMIT)[1]==meta for field,meta in native.items()),'os_executable_readback_drift')
        if not (actions['rebind_live'] or actions['restore_certificates']):
            if not all(ready[n]['ActiveState'] in ('inactive','failed') for n in CERTIFICATES):
                raise Deferred('os_certificate_stack_partially_active')
        replacements = prepared_files(packages)
    else:
        replacements = {}
    if replacements or actions['restore_certificates'] or actions['restore_feature']:
        result = transact(state,before,replacements,packages,actions)
    after = observe_database(before)
    baseline = {'boot':by_boot,'database':after[DB]['InvocationID'],
                'certificates':running(after,CERTIFICATES),'feature':running(after,(FEATURE,))}
    if previous!=baseline:
        durable_json(state/'baseline.json',baseline)
    if marker.exists():
        marker.unlink()
    return result


def run():
    require(os.geteuid()==0,'os_reconcile_root')
    os.umask(0o077)
    state = private_directory(STATE)
    try:
        with certificate_lock(), package_locks():
            return reconcile(state)
    except BlockingIOError:
        return {'status':'deferred','reason':'os_platform_transaction_active'}
    except Deferred as exc:
        return {'status':'deferred','reason':str(exc)}


def main():
    try:
        print(json.dumps(run(),sort_keys=True))
    except Exception as exc:
        print(json.dumps({'status':'failed','reason':str(exc) if type(exc) is ValueError else type(exc).__name__,
                          'diagnostic':getattr(exc,'diagnostic',None)},sort_keys=True))
        raise SystemExit(1)
