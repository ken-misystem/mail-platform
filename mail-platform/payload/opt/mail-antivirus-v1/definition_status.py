"""Publish verified official definition metadata after successful FreshClam."""
import json
import os
import pathlib
import pwd
import re
import socket
import stat
import struct
import time
import uuid

ROOT = pathlib.Path('/var/lib/mail-antivirus-v1')
SOCKET = '/run/clamav/clamd.ctl'
FRESHNESS_LIMIT = 172800
VERSION = re.compile(rb'ClamAV [A-Za-z0-9.+_-]+/([1-9][0-9]{0,9})/[ -~]+')


def need(condition, reason):
    if not condition:
        raise ValueError(reason)


def attributes(info):
    return (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns)


def read_definitions(root, uid):
    records, identities = {}, {}
    for name in ('main', 'daily', 'bytecode'):
        paths = [root / 'definitions' / (name + suffix) for suffix in ('.cvd', '.cld')]
        paths = [path for path in paths if os.path.lexists(path)]
        need(len(paths) == 1, 'official_database_inventory')
        path = paths[0]
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            before = os.fstat(fd)
            need(stat.S_ISREG(before.st_mode) and before.st_uid == uid and
                 before.st_nlink == 1 and 512 <= before.st_size <= 268435456, 'database_attributes')
            header = os.read(fd, 512)
            parts = header.decode('ascii').strip().split(':')
            need(len(header) == 512 and len(parts) == 9 and parts[0] == 'ClamAV-VDB', 'official_header')
            version, signatures, built = (int(parts[i]) for i in (2, 3, 8))
            need(0 < version <= 4294967295 and signatures > 0 and built > 0, 'official_header')
            records[name] = {'version': version, 'signatures': signatures,
                             'build_epoch': built, 'bytes': before.st_size}
            key = attributes(before)
            need(key == attributes(os.fstat(fd)) == attributes(path.lstat()), 'database_changed')
            identities[name] = key
        finally:
            os.close(fd)
    return records, identities


def exchange(path, uid, command):
    deadline = time.monotonic() + 2
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(2)
        client.connect(path)
        _, peer_uid, _ = struct.unpack('3i', client.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        need(peer_uid == uid, 'official_clamd_peer')
        client.sendall(b'z' + command + b'\0')
        response = bytearray()
        while len(response) < 256:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError('official_clamd_reply')
            client.settimeout(remaining)
            piece = client.recv(256 - len(response))
            if not piece:
                break
            response.extend(piece)
            if b'\0' in response:
                need(response.endswith(b'\0') and response.count(0) == 1, 'official_clamd_reply')
                return bytes(response[:-1])
    raise ValueError('official_clamd_reply')


def loaded_version(query):
    try:
        reply = query(b'VERSION')
    except OSError:
        return None
    match = VERSION.fullmatch(reply)
    need(match is not None, 'official_clamd_reply')
    return int(match[1])


def confirm_loaded(target, query, unchanged, *, clock=time.monotonic, pause=time.sleep):
    start = clock()
    reload_requested = False
    while clock() - start < 90:
        loaded = loaded_version(query)
        if loaded is not None:
            if loaded == target:
                return
            need(loaded < target, 'official_database_version_reversed')
            if clock() - start >= 45 and not reload_requested:
                unchanged()
                try:
                    need(query(b'RELOAD') == b'RELOADING', 'official_database_reload_unverified')
                except OSError as exc:
                    raise ValueError('official_database_reload_unverified') from exc
                reload_requested = True
        pause(2)
    raise ValueError('official_database_not_loaded')


def write_status(root, records):
    value = {'status': 'pass', 'observed_at': time.time(), 'databases': records, 'real_mail_sent': False}
    temporary = root / ('.' + uuid.uuid4().hex)
    with temporary.open('xb') as stream:
        try:
            os.fchmod(stream.fileno(), 0o640)
            stream.write((json.dumps(value, sort_keys=True) + '\n').encode())
            stream.flush()
            os.fsync(stream.fileno())
            os.replace(temporary, root / 'definitions-status.json')
        finally:
            temporary.unlink(missing_ok=True)
    directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def verify_and_publish(root, uid, query):
    records, identities = read_definitions(root, uid)
    daily = records['daily']
    age = time.time() - daily['build_epoch']
    need(age >= -3600, 'official_daily_future')
    if age > FRESHNESS_LIMIT:
        try:
            if loaded_version(query) == daily['version']:
                print('MAIL_PLATFORM_AV_DAILY_STALE_VERSION=' + str(daily['version']), flush=True)
        except ValueError:
            pass  # Keep the stale finding even if the live version cannot be proved.
        raise ValueError('official_daily_stale')

    def unchanged():
        need(read_definitions(root, uid) == (records, identities), 'database_changed')
        need(-3600 <= time.time() - daily['build_epoch'] <= FRESHNESS_LIMIT, 'official_daily_stale')

    confirm_loaded(daily['version'], query, unchanged)
    unchanged()
    write_status(root, records)
    print('MAIL_PLATFORM_AV_DAILY_LOAD_CONFIRMED=1', flush=True)


def main():
    uid = pwd.getpwnam('mailantivirus').pw_uid
    # The package identity binder substitutes the established _rspamd GID.
    need(os.geteuid() == uid and os.getegid()==111, 'status_owner')
    verify_and_publish(ROOT, uid, lambda command: exchange(SOCKET, uid, command))


if __name__ == '__main__':
    main()
