"""Future collector entry: root publishes aggregates, web caller only reads them."""
from datetime import datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import uuid

DIRECTORY = Path('/var/lib/mail-management-operations-v1')
SOURCE_SHA = 'fa793434ffe8f5d947e6b2f21af25f0f6706a58ed96cc12802e1b3080c06bb9e'
GROUP = 113  # Existing verified mailadmin group; no identity/grant creation.
UPDATE_UNIT = 'mail-platform-update.service'
UPDATE_MARKER = 'MAIL_PLATFORM_PERIODIC_LOOKUP_FAILED=1'
MARKERS = {UPDATE_MARKER:'lookup', 'MAIL_PLATFORM_PRE_APPLY_BUSY=unknown':'busy',
           'MAIL_PLATFORM_PRE_APPLY_BUSY=os_reconcile':'busy_os'}


def need(ok):
    if not ok:
        raise ValueError('collector_guard')


def identity(s):
    return None if s is None else (s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)


def runtime():
    source = Path(__file__).with_name('read_runtime.py')
    raw = source.read_bytes()
    need(hashlib.sha256(raw).hexdigest() == SOURCE_SHA)
    scope = dict(__name__='bound_runtime_library', __file__=str(source), SOURCE_SHA=SOURCE_SHA)
    exec(compile(raw, 'bound-runtime-collector', 'exec'), scope)
    return scope


def periodic_update_failure(snapshot, capture):
    """Accept only a journal marker from the exact failed service invocation."""
    units = snapshot['checks']['units']
    if units['status'] != 'ok':
        return None
    service = units['data'].get(UPDATE_UNIT, {})
    timer = units['data'].get('mail-platform-update.timer', {})
    if (service.get('load'), service.get('active'), service.get('result'), service.get('main_exit')) != (
            'loaded', 'failed', 'exit-code', 1) or (timer.get('load'), timer.get('active')) != ('loaded', 'active'):
        return None
    command = ('/usr/bin/systemctl', 'show', '--no-pager',
               '--property=InvocationID,ActiveState,Result,ExecMainStatus', UPDATE_UNIT)
    try:
        before, meta = capture(command, 4096, timeout=3)
        if meta['reason'] is not None:
            return None
        fields = dict(line.split('=', 1) for line in before.decode().splitlines())
        invocation = fields.pop('InvocationID', '')
        if fields != {'ActiveState':'failed', 'Result':'exit-code', 'ExecMainStatus':'1'} or not (
                re.fullmatch('[0-9a-f]{32}', invocation) and int(invocation, 16)):
            return None
        query = ('/usr/bin/journalctl', '--boot', '--no-pager', '--output=json', '--lines=2',
                 '--output-fields=MESSAGE,_SYSTEMD_UNIT,_SYSTEMD_INVOCATION_ID,_UID', '--grep=^('+'|'.join(MARKERS)+')$',
                 '_SYSTEMD_UNIT='+UPDATE_UNIT, '_SYSTEMD_INVOCATION_ID='+invocation, '_UID=0')
        raw, meta = capture(query, 4096, timeout=3)
        if meta['reason'] is not None or len(raw.splitlines()) != 1:
            return None
        row = json.loads(raw)
        reason = MARKERS.get(row.get('MESSAGE'))
        if not reason or (row.get('_SYSTEMD_UNIT'), row.get('_SYSTEMD_INVOCATION_ID'), row.get('_UID')) != (
                UPDATE_UNIT, invocation, '0'):
            return None
        stamp = row.get('__REALTIME_TIMESTAMP')
        if not isinstance(stamp, str) or not re.fullmatch('[0-9]{1,19}', stamp):
            return None
        run_epoch = int(stamp) // 1000000
        if not 0 < run_epoch <= int(datetime.fromisoformat(snapshot['observed_utc']).timestamp()):
            return None
        after, meta = capture(command, 4096, timeout=3)
        if meta['reason'] is None and before == after:
            result = {'invocation': invocation, 'run_epoch': run_epoch, 'reason': reason}
            # The next activation already includes the timer's random delay.
            try:
                timers, meta = capture(('/usr/bin/systemctl','list-timers','--all','--no-pager',
                                        '--output=json','mail-platform-update.timer'), 4096, timeout=3)
                timer, = json.loads(timers)
                due = timer.get('next')
                if (meta['reason'] is None and timer.get('unit') == 'mail-platform-update.timer'
                        and type(due) is int and run_epoch < due//1000000 <= run_epoch+86400):
                    result['next_epoch'] = due//1000000
            except (OSError, ValueError, TypeError, AttributeError):
                pass
            return result
    except (OSError, ValueError, TypeError, KeyError, AttributeError):
        return None  # Absence of proof retains the existing severity.
    return None


def write_snapshot(directory_fd, result, periodic=None):
    need(result['source_sha256'] == SOURCE_SHA and result['operation'] == 'management-operations-read-v1')
    raw = (json.dumps(result, separators=(',', ':'), ensure_ascii=True) + '\n').encode('ascii')
    need(0 < len(raw) <= 65536)
    if periodic is not None:
        proof = dict(periodic, snapshot_sha256=hashlib.sha256(raw).hexdigest())
        encoded = json.dumps(proof, separators=(',', ':')).encode('ascii')
        try:
            write_public(directory_fd, 'periodic-update-proof.json', encoded)
        except (OSError, ValueError):
            pass  # Publish the normal snapshot even if the optional proof is unavailable.
    write_public(directory_fd, 'snapshot.json', raw)


def write_public(directory_fd, filename, raw):
    try:
        old = os.stat(filename, dir_fd=directory_fd, follow_symlinks=False)
        need(stat.S_ISREG(old.st_mode) and old.st_uid == 0 and old.st_gid == GROUP
             and stat.S_IMODE(old.st_mode) == 0o640 and old.st_nlink == 1)
    except FileNotFoundError:
        old = None
    name = '.snapshot-' + uuid.uuid4().hex + '.tmp'
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory_fd)
    try:
        os.fchown(fd, 0, GROUP)
        with os.fdopen(fd, 'wb', closefd=False) as output:
            output.write(raw); output.flush(); os.fsync(fd)
        os.fchmod(fd, 0o640)
    finally:
        os.close(fd)
    try:
        current = os.stat(filename, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        current = None
    need(identity(current) == identity(old))
    os.rename(name, filename, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
    os.fsync(directory_fd)


def run():
    need(os.geteuid() == 0 and sys.argv[1:] == ['--collect'])
    # No directory creation here. A separately approved activation must provision it.
    parent = os.open('/var/lib', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    directory = lock = None
    try:
        parent_info = os.fstat(parent)
        need(parent_info.st_uid == 0 and not parent_info.st_mode & 0o022)
        directory = os.open(DIRECTORY.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        info = os.fstat(directory)
        need(info.st_uid == 0 and info.st_gid == GROUP and stat.S_IMODE(info.st_mode) == 0o750)
        lock = os.open('collector.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600, dir_fd=directory)
        info = os.fstat(lock)
        need(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o600)
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        library = runtime()
        result = library['collect']()
        periodic = periodic_update_failure(result, library['capture'])
        write_snapshot(directory, result, periodic)
        return 0 if result['status'] == 'ok' else 1
    finally:
        for fd in (lock, directory, parent):
            if fd is not None: os.close(fd)


if __name__ == '__main__':
    try:
        code = run()
        print('OPERATIONS_COLLECTOR=' + json.dumps(dict(status='ok' if code == 0 else 'partial', snapshot_written=True)))
        raise SystemExit(code)
    except Exception as error:
        kind = type(error).__name__
        print('OPERATIONS_COLLECTOR=' + json.dumps(dict(status='fail', snapshot_written=False,
              error_class=kind if kind in ('ValueError','OSError','FileNotFoundError','PermissionError','BlockingIOError') else 'other',
              errno=error.errno if isinstance(error,OSError) else None)))
        raise SystemExit(2)
