"""Fixed aggregate reads for an operations dashboard; no deployment or repair."""
import datetime as dt
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import threading
import time

OPERATION = 'management-operations-read-v1'
COMPILER = 'mail-management-operations-read-v1'
UNITS = tuple(x + '.service' for x in (
    'postfix', 'dovecot', 'mariadb', 'rspamd', 'redis-server', 'nginx',
    'php8.4-fpm', 'fail2ban', 'postsrsd', 'ufw', 'mail-pop-general-dispatch',
    'mail-junk-digest-general',
)) + ('mail-pop-general-dispatch.timer', 'mail-junk-digest-general.timer') + ('mail-client-cert-network.service', 'mail-client-cert-milter.service', 'mail-client-cert-coordination.service', 'mail-client-cert-postfix-backend.service', 'mail-client-cert-dovecot-backend.service', 'mail-client-cert-issuer.service', 'mail-client-cert-lifecycle.service', 'mail-client-cert-verifier.service', 'mail-client-cert-gate.service', 'mail-client-cert-owner.service', 'mail-client-cert-gate.socket', 'mail-client-cert-health.service', 'mail-client-cert-health.timer') + ('mail-legacy-smtp-auth.service', 'mail-quota-collect-v1.service', 'mail-management-log-viewer.service', 'mail-management-log-viewer.timer', 'mail-domain-routing.service', 'mail-domain-routing.socket', 'mail-domain-routing-collect.service', 'mail-domain-routing-collect.timer')
UNITS += ('mail-management-alerts-v1.service', 'mail-management-alerts-v1.timer')
UNITS += ('mail-access-admin-v1.service', 'mail-access-admin-v1.socket')
UNITS += ('mail-send-limits-v1.service', 'mail-send-limits-v1.socket', 'mail-feature-admin-v1.service', 'mail-feature-admin-v1.socket', 'mail-feature-access-v1.service', 'mail-feature-access-v1.socket', 'mail-feature-config-v1.service', 'mail-feature-observer-v1.service', 'mail-feature-observer-v1.timer')
UNITS += ('mail-feature-rspamd-native-v1.service', 'mail-feature-rspamd-native-v1.socket')
SOURCE_UNIT = re.compile(r'mail-pop-source@([1-9][0-9]{0,19})\.service\Z')
ONESHOTS = ('mail-pop-general-dispatch.service', 'mail-junk-digest-general.service', 'mail-client-cert-health.service', 'mail-management-log-viewer.service', 'mail-domain-routing-collect.service')

ONESHOTS += ('mail-management-alerts-v1.service', 'mail-access-admin-v1.service')
ONESHOTS += ('mail-feature-observer-v1.service',)


def source_unit(name):
    match = SOURCE_UNIT.fullmatch(name)
    return match is not None and int(match[1]) <= 18446744073709551615
PROPERTIES = ('Id', 'LoadState', 'ActiveState', 'SubState', 'Result',
              'ExecMainStatus', 'UnitFileState')
UNITS += ('mail-protection-clamav-v1.service', 'mail-protection-definitions-v1.service', 'mail-protection-definitions-v1.timer', 'mail-protection-publish-v1.service', 'mail-protection-publish-v1.timer')
ONESHOTS += ('mail-protection-definitions-v1.service', 'mail-protection-publish-v1.service')
UNITS += ('mail-reputation-dns-v1.service',)
COMMANDS = {
    'units': ('/usr/bin/systemctl', 'show', '--no-pager', '--all',
              '--property=' + ','.join(PROPERTIES), *UNITS, 'mail-pop-source@*.service'),
    'queue': (),
    'certificate': (),
}
LIMITS = {'units': 65536, 'queue': 8 * 1024 * 1024, 'certificate': 4096}
BACKUP_CONFIG = '/var/lib/mail-backup-mx-v1/primary/config'
BACKUP_UNIT = '/etc/systemd/system/mail-backup-primary-postfix.service'
BACKUP_QUEUE = '/var/lib/mail-backup-mx-v1/primary/queue'
BACKUP_READER = '/usr/local/lib/mail-management-operations-v1/backup-queue-reader'
BACKUP_READER_SHA = '95b3b76e9419b20572d394dfe6fb63c649852732bac259b1b6c497bb7a65c5de'
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C', 'LC_ALL': 'C'}
REASONS = ('permission', 'missing', 'unsupported', 'native_exit', 'stderr',
           'timeout', 'output_bound', 'shape', 'io', 'internal')


class Guard(Exception):
    def __init__(self, reason='shape'):
        self.reason = reason


def need(ok):
    if not ok:
        raise Guard()


def number(v, low=0, high=2**63-1):
    need(type(v) is int and low <= v <= high)
    return v


def pairs(items):
    result = {}
    for key, value in items:
        need(key not in result)
        result[key] = value
    return result


def decode(raw):
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(Guard()))


def capture(argv, limit, timeout=20):
    """Bound both pipes in memory. Never expose raw streams, including on error."""
    p = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, env=ENV)
    buffers = [bytearray(), bytearray()]
    overflow = threading.Event()
    reader_error = threading.Event()

    def drain(index, stream, bound):
        try:
            while True:
                chunk = stream.read(8192)
                if not chunk:
                    break
                room = bound - len(buffers[index])
                buffers[index].extend(chunk[:max(0, room)])
                if len(chunk) > room:
                    overflow.set()
                    p.kill()
                    break
        except (OSError, ValueError):
            reader_error.set()

    threads = [threading.Thread(target=drain, args=(i, stream, bound), daemon=True)
               for i, (stream, bound) in enumerate(((p.stdout, limit), (p.stderr, 8192)))]
    for thread in threads:
        thread.start()
    timed_out = False
    try:
        p.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        p.kill()
        p.wait(timeout=5)
    finally:
        for thread in threads:
            thread.join(timeout=5)
    if any(t.is_alive() for t in threads):
        reader_error.set()
    else:
        p.stdout.close()
        p.stderr.close()
    stdout, stderr = map(bytes, buffers)
    reason = None
    if timed_out:
        reason = 'timeout'
    elif overflow.is_set():
        reason = 'output_bound'
    elif reader_error.is_set():
        reason = 'io'
    elif p.returncode != 0 or stderr:
        # Finite classifications, never an excerpt of stderr.
        lowered = stderr.lower()
        reason = next((name for token, name in (
            (b'permission denied', 'permission'), (b'no such file', 'missing'),
            (b'unknown option', 'unsupported'), (b'unrecognized option', 'unsupported'),
        ) if token in lowered), 'native_exit' if p.returncode != 0 else 'stderr')
    meta = dict(exit=p.returncode, stdout_bytes=len(stdout), stderr_bytes=len(stderr),
                timed_out=timed_out, bounded=not overflow.is_set(), reason=reason)
    return stdout if reason is None else b'', meta


def enum(value, allowed):
    return value if value in allowed else 'other'


def unit_summary(raw):
    need(len(raw) <= LIMITS['units'])
    blocks = raw.decode('utf-8', 'strict').strip().split('\n\n')
    found = {}
    for block in blocks:
        fields = {}
        for line in block.splitlines():
            key, sep, value = line.partition('=')
            need(sep and key in PROPERTIES and key not in fields)
            fields[key] = value
        need('Id' in fields)
        name = fields['Id']
        need((name in UNITS or source_unit(name)) and name not in found and len(found) < len(UNITS)+200)
        required = set(PROPERTIES) - ({'Result', 'ExecMainStatus'} if name.endswith('.timer') else {'ExecMainStatus'} if name.endswith('.socket') else set())
        need(required <= set(fields) <= set(PROPERTIES))
        exit_value = fields.get('ExecMainStatus', '')
        need(exit_value == '' or re.fullmatch(r'[0-9]{1,10}', exit_value))
        found[name] = dict(
            load=enum(fields['LoadState'], ('loaded', 'not-found', 'error', 'bad-setting', 'masked', 'stub', 'merged')),
            active=enum(fields['ActiveState'], ('active', 'inactive', 'failed', 'activating', 'deactivating', 'reloading', 'maintenance', 'refreshing')),
            sub=enum(fields['SubState'], ('running', 'exited', 'dead', 'waiting', 'failed', 'start', 'stop', 'auto-restart', 'listening', 'elapsed')),
            result=enum(fields.get('Result', ''), ('', 'success', 'exit-code', 'signal', 'core-dump', 'timeout', 'resources', 'start-limit-hit', 'watchdog', 'protocol', 'condition', 'assert')),
            main_exit=None if exit_value == '' else number(int(exit_value), 0, 2**32-1),
            enabled=enum(fields['UnitFileState'], ('', 'enabled', 'enabled-runtime', 'disabled', 'static', 'indirect', 'alias', 'masked', 'masked-runtime', 'generated', 'transient', 'linked', 'linked-runtime', 'not-found', 'bad')),
        )
    need(set(UNITS) <= set(found))
    return {name: found[name] for name in (*UNITS, *sorted(set(found) - set(UNITS)))}


def queue_summary(raw, now):
    need(len(raw) <= LIMITS['queue'])
    counts = dict.fromkeys(('active', 'deferred', 'hold', 'incoming', 'maildrop', 'corrupt', 'other'), 0)
    seen = set()
    records = duplicates = total_bytes = oldest = future = 0
    for line in raw.splitlines():
        need(0 < len(line) <= 65536)
        records += 1
        need(records <= 20000)
        item = decode(line)
        need(isinstance(item, dict) and isinstance(item.get('queue_id'), str))
        need(re.fullmatch(r'[A-Za-z0-9]{1,128}', item['queue_id']))
        need(isinstance(item.get('queue_name'), str))
        arrived = number(item.get('arrival_time'), 0, 2**40)
        size = number(item.get('message_size'))
        identity = item['queue_id'], arrived
        if identity in seen:
            duplicates += 1
            continue
        seen.add(identity)
        counts[enum(item['queue_name'], counts)] += 1
        total_bytes += size
        number(total_bytes)
        oldest = max(oldest, max(0, now - arrived))
        future += int(arrived > now)
    return dict(records=records, unique_observed_entries=len(seen), duplicate_observations=duplicates,
                by_queue=counts, total_message_bytes=total_bytes, oldest_age_seconds=oldest,
                future_arrival_observations=future, atomic_snapshot=False,
                addresses_output=False, queue_ids_output=False)


def backup_main_cf():
    directory = monitor_directory(BACKUP_CONFIG)
    try:
        return monitor_regular(directory, 'main.cf', 1048576, contents=True)
    finally:
        os.close(directory)


def backup_ingress_summary(native, now):
    if not (os.path.lexists(BACKUP_UNIT) or os.path.lexists(BACKUP_CONFIG)):
        return {'status':'not_configured', 'held':0, 'deferred':0}
    try:
        before = backup_main_cf()
        expected = BACKUP_QUEUE.encode()
        need(re.findall(rb'(?m)^queue_directory[ \t]*=[ \t]*(\S+)[ \t]*$', before)==[expected])
        directory = monitor_directory(BACKUP_READER)
        try:
            reader = monitor_regular(directory, 'main.cf', 4096, contents=True)
            need(hashlib.sha256(reader).hexdigest() == BACKUP_READER_SHA)
            raw, meta = native(('/usr/sbin/postqueue','-c',BACKUP_READER,'-j'), LIMITS['queue'], timeout=8)
            need(monitor_regular(directory, 'main.cf', 4096, contents=True) == reader)
        finally:
            os.close(directory)
        need(meta['reason'] is None and backup_main_cf()==before)
        counts = queue_summary(raw, now)['by_queue']
        need(not (counts['corrupt'] or counts['other']))
    except (Guard, OSError, ValueError, UnicodeError):
        return {'status':'unavailable', 'held':0, 'deferred':0}
    return {'status':'ok', 'held':counts['hold'], 'deferred':counts['deferred']}


def certificate_summary(raw, now):
    text = raw.decode('ascii', 'strict').strip()
    need(len(raw) <= LIMITS['certificate'] and text.startswith('notAfter='))
    expiry = dt.datetime.strptime(text[9:], '%b %d %H:%M:%S %Y GMT').replace(tzinfo=dt.timezone.utc)
    remaining = int(expiry.timestamp()) - now
    return dict(expires_utc=expiry.isoformat(), seconds_remaining=remaining, expired=remaining <= 0,
                served_certificate_verified=False)


def filesystem_summary(path):
    """Stat filesystem only; never enumerate or open a message."""
    descriptor = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for component in path.strip('/').split('/') if path != '/' else ():
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        info = os.fstat(descriptor)
        need(stat.S_ISDIR(info.st_mode) and not info.st_mode & 0o022)
        value = os.fstatvfs(descriptor)
        total = number(value.f_blocks * value.f_frsize)
        available = number(max(0, value.f_bavail) * value.f_frsize)
        free_inodes = number(value.f_favail)
        return dict(total_bytes=total, available_bytes=available, available_inodes=free_inodes,
                    same_filesystem_key=info.st_dev)
    finally:
        os.close(descriptor)


"""Site-owned monitoring references. No hostname rewriting, writes, or shell calls."""
import json as _mon_json
import os as _mon_os
import re as _mon_re
import stat as _mon_stat

MONITOR_CONFIG = '/etc/mail-management-operations-v1/environment.json'


def monitor_need(value, reason):
    if not value:
        raise ValueError('monitor_environment_' + reason)


def monitor_validate(value):
    monitor_need(type(value) is dict and set(value) == {
        'format', 'queue_config_directory', 'certificate_lineage'}, 'fields')
    monitor_need(type(value['format']) is int and value['format'] == 1, 'format')
    path = value['queue_config_directory']
    monitor_need(type(path) is str and len(path) <= 512 and
                 _mon_re.fullmatch(r'/etc/(?:[A-Za-z0-9_.-]+/)*[A-Za-z0-9_.-]+', path)
                 and all(part not in ('.', '..') for part in path.split('/')), 'queue_path')
    name = value['certificate_lineage']
    monitor_need(type(name) is str and len(name) <= 128 and
                 _mon_re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]*', name), 'lineage')
    return dict(value)


def monitor_decode(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            monitor_need(key not in result, 'duplicate_key')
            result[key] = value
        return result
    monitor_need(len(raw) <= 4096, 'size')
    return monitor_validate(_mon_json.loads(raw, object_pairs_hook=pairs))


def monitor_encode(value):
    return (_mon_json.dumps(monitor_validate(value), sort_keys=True, indent=2) + '\n').encode()


def monitor_directory(path, root='/'):
    """Open each directory without following links; never trust writable parents."""
    fd = _mon_os.open(root, _mon_os.O_RDONLY | _mon_os.O_DIRECTORY | _mon_os.O_NOFOLLOW)
    try:
        for part in path.strip('/').split('/'):
            monitor_need(part not in ('', '.', '..'), 'directory_component')
            child = _mon_os.open(part, _mon_os.O_RDONLY | _mon_os.O_DIRECTORY | _mon_os.O_NOFOLLOW, dir_fd=fd)
            _mon_os.close(fd); fd = child
            info = _mon_os.fstat(fd)
            monitor_need(info.st_uid == 0 and not info.st_mode & 0o022, 'directory_trust')
        return fd
    except BaseException:
        _mon_os.close(fd)
        raise


def monitor_regular(directory, name, limit, *, contents=False):
    fd = _mon_os.open(name, _mon_os.O_RDONLY | _mon_os.O_NOFOLLOW | _mon_os.O_NONBLOCK, dir_fd=directory)
    try:
        info = _mon_os.fstat(fd)
        monitor_need(_mon_stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and
                     info.st_uid == 0 and not info.st_mode & 0o022 and 0 < info.st_size <= limit, 'file_trust')
        raw = _mon_os.read(fd, limit + 1) if contents else None
        after = _mon_os.fstat(fd)
        identity = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns, s.st_uid, s.st_gid, s.st_mode)
        monitor_need(identity(info) == identity(after) == identity(_mon_os.stat(name, dir_fd=directory, follow_symlinks=False)), 'file_race')
        if contents: monitor_need(len(raw) == info.st_size, 'file_size')
        return raw if contents else identity(info)
    finally:
        _mon_os.close(fd)


def monitor_load(root='/'):
    directory = monitor_directory('/etc/mail-management-operations-v1', root)
    try:
        return monitor_decode(monitor_regular(directory, 'environment.json', 4096, contents=True))
    finally:
        _mon_os.close(directory)


def monitor_queue_guard(value, root='/'):
    directory = monitor_directory(monitor_validate(value)['queue_config_directory'], root)
    try:
        return monitor_regular(directory, 'main.cf', 1048576)
    finally:
        _mon_os.close(directory)


def monitor_certificate_guard(value, root='/'):
    name = monitor_validate(value)['certificate_lineage']
    live = monitor_directory('/etc/letsencrypt/live/' + name, root)
    archive = None
    try:
        link = _mon_os.stat('fullchain.pem', dir_fd=live, follow_symlinks=False)
        monitor_need(link.st_uid == 0 and _mon_stat.S_ISLNK(link.st_mode), 'certificate_link')
        target = _mon_os.readlink('fullchain.pem', dir_fd=live)
        match = _mon_re.fullmatch(r'\.\./\.\./archive/' + _mon_re.escape(name) + r'/(fullchain[1-9][0-9]{0,6}\.pem)', target)
        monitor_need(match is not None, 'certificate_target')
        archive = monitor_directory('/etc/letsencrypt/archive/' + name, root)
        identity = monitor_regular(archive, match[1], 65536)
        again = _mon_os.stat('fullchain.pem', dir_fd=live, follow_symlinks=False)
        monitor_need((link.st_ino, link.st_mtime_ns, link.st_ctime_ns) ==
                     (again.st_ino, again.st_mtime_ns, again.st_ctime_ns) and
                     _mon_os.readlink('fullchain.pem', dir_fd=live) == target, 'certificate_race')
        return (link.st_dev, link.st_ino, link.st_mtime_ns, target, *identity)
    finally:
        _mon_os.close(live)
        if archive is not None: _mon_os.close(archive)


def monitor_commands(value):
    value = monitor_validate(value)
    return {
        'queue': ('/usr/sbin/postqueue', '-c', value['queue_config_directory'], '-j'),
        'certificate': ('/usr/bin/openssl', 'x509', '-in', '/etc/letsencrypt/live/' +
                        value['certificate_lineage'] + '/fullchain.pem', '-noout', '-enddate'),
    }


def monitor_targets(value, root='/'):
    monitor_queue_guard(value, root)
    monitor_certificate_guard(value, root)
    return monitor_validate(value)



"""Inserted into the existing read-only collector; contains no actions."""
CLIENT_CERT_CODES = ('private_unit_not_active','gate_observation_missing','gate_observation_stale','gate_threads_failed','crl_expiring','crl_expired',
    'tls_expiring','tls_expired','root_ca_expiring','root_ca_expired','issuer_ca_expiring','issuer_ca_expired','tls_reload_unverified','tls_source_invalid',
    'tls_refresh_failed','health_collection_failed','health_snapshot_stale')

def client_certificate_summary(now):
    path='/var/lib/mail-client-cert-public-v1/status.json';fds=[os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)]
    try:
        for name in ('var','lib','mail-client-cert-public-v1'):
            fd=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fds[-1]);fds.append(fd);s=os.fstat(fd)
            need(s.st_uid==0 and not s.st_mode&0o022)
        fd=os.open('status.json',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=fds[-1]);fds.append(fd);s=os.fstat(fd)
        need(stat.S_ISREG(s.st_mode)and s.st_uid==0 and s.st_nlink==1 and not s.st_mode&0o022 and 0<s.st_size<=32768)
        raw=os.pread(fd,s.st_size+1,0);end=os.stat('status.json',dir_fd=fds[-2],follow_symlinks=False)
        need(len(raw)==s.st_size and(s.st_dev,s.st_ino,s.st_mtime_ns,s.st_size)==(end.st_dev,end.st_ino,end.st_mtime_ns,end.st_size))
    finally:
        for fd in reversed(fds):os.close(fd)
    v=decode(raw);need(v.get('version')==1 and v.get('status')in('ok','warning','failed'))
    observed=number(v.get('observed_at'),0,2**40);need(observed<=now)
    codes=v.get('finding_codes');need(type(codes)is list and len(codes)<=len(CLIENT_CERT_CODES)and len(codes)==len(set(codes))and all(c in CLIENT_CERT_CODES for c in codes))
    remaining=v.get('seconds_remaining');need(type(remaining)is dict and set(remaining)=={'server_tls','root_ca','issuer_ca','crl'})
    for n in remaining.values():number(n,-2**40,2**40)
    action=v.get('renewal_action');need(action in('none','prepared','gate_restarted','refresh_refused','restart_unverified'))
    status=v['status']
    if now-observed>900:
        if 'health_snapshot_stale'not in codes:codes.append('health_snapshot_stale')
        status='failed'
    need((status=='ok')==(not codes))
    return dict(observed_utc=dt.datetime.fromtimestamp(observed,dt.timezone.utc).isoformat(),status=status,seconds_remaining=remaining,finding_codes=codes,renewal_action=action)


def evaluate(checks):
    incomplete = [name for name, item in checks.items() if item['status'] != 'ok']
    findings = []
    if checks['units']['status'] == 'ok':
        data = checks['units']['data']
        for name in (*UNITS, *sorted(set(data) - set(UNITS))):
            unit = data[name]
            if unit['active'] == 'failed':
                findings.append(dict(check='units', item=name, reason='unit_failed'))
            elif unit['load'] != 'loaded':
                findings.append(dict(check='units', item=name, reason='unit_not_loaded'))
            elif name.endswith('.timer') and unit['active'] != 'active':
                findings.append(dict(check='units', item=name, reason='timer_not_active'))
            elif not name.endswith('.timer') and (unit['result'] not in ('', 'success') or unit['main_exit'] not in (None, 0)):
                findings.append(dict(check='units', item=name, reason='last_run_failed'))
            elif name not in ONESHOTS and not source_unit(name) and not name.endswith('.timer') and unit['active'] != 'active':
                findings.append(dict(check='units', item=name, reason='unit_not_active'))
    if checks['queue']['status'] == 'ok':
        for queue in ('deferred', 'hold', 'corrupt', 'other'):
            if checks['queue']['data']['by_queue'][queue]:
                findings.append(dict(check='queue', item=queue, reason='queue_entries_observed'))
        backup = checks['queue']['data']['backup_ingress']
        if backup['status'] == 'unavailable':
            findings.append(dict(check='queue', item='backup_ingress', reason='backup_queue_unavailable'))
        for state in ('held', 'deferred'):
            if backup[state]:
                findings.append(dict(check='queue', item='backup_'+state, reason='queue_entries_observed'))
    for name in ('system_storage', 'mail_storage'):
        if checks[name]['status'] == 'ok':
            data = checks[name]['data']
            if data['available_bytes'] == 0 or data['available_inodes'] == 0:
                findings.append(dict(check=name, item='filesystem', reason='no_available_capacity'))
    if checks['certificate']['status'] == 'ok' and checks['certificate']['data']['expired']:
        findings.append(dict(check='certificate', item='local_certificate', reason='expired'))
    if checks['client_certificates']['status'] == 'ok':
        for code in checks['client_certificates']['data']['finding_codes']:
            findings.append(dict(check='client_certificates', item='certificate_gate', reason=code))
    return dict(collection='incomplete' if incomplete else 'complete', incomplete_checks=incomplete,
                findings=findings, thresholds_configured=False, notification_configured=False,
                delivery_health_proven=False, deployment_authorized=False)


def collect(native=capture, filesystem=filesystem_summary, now=None, certificate=None, environment=None):
    now = int(time.time()) if now is None else number(now)
    checks = {}
    for name in ('units', 'queue', 'system_storage', 'mail_storage', 'certificate', 'client_certificates'):
        meta = None
        try:
            if name in COMMANDS:
                guard = None
                command = COMMANDS[name]
                if name in ('queue', 'certificate'):
                    settings = monitor_load() if environment is None else monitor_validate(environment)
                    command = monitor_commands(settings)[name]
                    guard = (certificate or (lambda: monitor_certificate_guard(settings))) if name == 'certificate' else (lambda: monitor_queue_guard(settings))
                before = guard() if guard else None
                raw, meta = native(command, LIMITS[name])
                if guard: need(guard() == before)
                if meta['reason'] is not None:
                    raise Guard(meta['reason'])
                data = unit_summary(raw) if name == 'units' else (
                    queue_summary(raw, now) if name == 'queue' else certificate_summary(raw, now))
            elif name == 'client_certificates':
                data = client_certificate_summary(now)
            else:
                data = filesystem('/' if name == 'system_storage' else '/var/vmail')
            if name == 'queue':
                data['backup_ingress'] = backup_ingress_summary(native, now)
            checks[name] = dict(status='ok', data=data, native=meta, failure=None)
        except Exception as error:
            line = None
            tb = error.__traceback__
            while tb:
                if tb.tb_frame.f_code.co_filename in (__file__, COMPILER):
                    line = tb.tb_lineno
                tb = tb.tb_next
            reason = error.reason if isinstance(error, Guard) and error.reason in REASONS else (
                'io' if isinstance(error, OSError) else 'shape' if isinstance(error, (ValueError, UnicodeError)) else 'internal')
            kind = type(error).__name__
            checks[name] = dict(status='fail', data=None, native=meta,
                                failure=dict(reason=reason, error_class=kind if kind in (
                                    'Guard', 'OSError', 'PermissionError', 'FileNotFoundError', 'ValueError',
                                    'UnicodeDecodeError', 'JSONDecodeError', 'TypeError') else 'other',
                                    errno=error.errno if isinstance(error, OSError) else None, source_line=line))
    source_sha = globals().get('SOURCE_SHA')
    if source_sha is None:
        with open(__file__, 'rb') as source:
            source_sha = hashlib.sha256(source.read().replace(b'\r\n', b'\n')).hexdigest()
    return dict(operation=OPERATION, source_sha256=source_sha, observed_utc=dt.datetime.fromtimestamp(now, dt.timezone.utc).isoformat(),
                status='ok' if all(c['status'] == 'ok' for c in checks.values()) else 'fail',
                checks=checks, evaluation=evaluate(checks), server_write=False, service_action=False,
                database_query=False, manual_pop=False, mail_content_read=False, uidl_read=False,
                raw_output_saved=False, atomic_snapshot=False)


def main():
    if os.geteuid() != 0:
        raise SystemExit(2)
    result = collect()
    print('MAIL_MANAGEMENT_OPERATIONS=' + json.dumps(result, separators=(',', ':')))
    raise SystemExit(0 if result['status'] == 'ok' else 1)


if __name__ == '__main__':
    main()
