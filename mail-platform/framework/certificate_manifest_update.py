"""Keep installed certificate launch configurations in the code transaction."""
import json
import os
from pathlib import PurePosixPath
import re
import shlex
import time

from host_transaction import regular
from release import sha

RUNTIME = '/usr/local/lib/mail-client-certificates-v1/'
MANIFEST = RUNTIME+'runtime-manifest.json'
CONFIG = '/etc/mail-client-certificates-v1/'
ACTORS = ('owner', 'gate', 'lifecycle', 'verifier', 'issuer')
CONFIGS = {CONFIG+actor+'.json': actor for actor in ACTORS}
TARGET = 'mail-client-certificates.target'
SOCKET = 'mail-client-cert-gate.socket'
GATE = 'mail-client-cert-gate.service'
TIMER = 'mail-client-cert-health.timer'
HEALTH = 'mail-client-cert-health.service'
STOP = ('mail-client-cert-owner.service', SOCKET, GATE,
        'mail-client-cert-lifecycle.service', 'mail-client-cert-verifier.service',
        'mail-client-cert-issuer.service')


def unique(pairs):
    document = {}
    for key, value in pairs:
        if key in document:
            raise ValueError('certificate_update_duplicate_JSON_key')
        document[key] = value
    return document


def binding(raw, actor):
    cfg = json.loads(raw, object_pairs_hook=unique)
    if (cfg.get('actor') != actor or cfg.get('version') != 1
            or cfg.get('release') != RUNTIME.rstrip('/') or cfg.get('profile') != 'production'):
        raise ValueError('certificate_update_actor_binding:'+actor)
    return cfg


def plan_files(engine, bound, receipt):
    new = bound.get(MANIFEST.lstrip('/'))
    if new is None:
        return None, {}
    old, before = engine.live(MANIFEST)
    if new == old:
        return None, {}
    if before != receipt['code'].get(MANIFEST) or before['uid'] != 0 or before['mode'] & 0o022:
        raise ValueError('certificate_update_manifest_registration')
    transition = {'before': sha(old), 'after': sha(new)}
    entries = json.loads(new, object_pairs_hook=unique)['pins']
    for name, expected in entries.items():
        path = PurePosixPath(name)
        if (path.is_absolute() or '..' in path.parts or not path.parts or str(path) != name
                or '\\' in name or sha(bound[(RUNTIME+name).lstrip('/')]) != expected):
            raise ValueError('certificate_update_runtime_source_pin:'+name)
    candidates = {}
    for path, actor in CONFIGS.items():
        raw, attrs = engine.live(path)
        if path in receipt['code'] or attrs['uid'] != 0 or attrs['mode'] not in (0o600, 0o640):
            raise ValueError('certificate_update_configuration_attributes:'+actor)
        # Files.write carries ownership and mode. Do not discard a site ACL or label.
        if os.listxattr(engine.files.target(path), follow_symlinks=False):
            raise ValueError('certificate_update_configuration_xattrs:'+actor)
        cfg = binding(raw, actor)
        if cfg.get('manifest_sha256') != transition['before']:
            raise ValueError('certificate_update_old_actor_pin:'+actor)
        pattern = rb'("manifest_sha256"\s*:\s*")'+transition['before'].encode()+rb'(")'
        candidate, occurrences = re.subn(pattern, lambda m:m[1]+transition['after'].encode()+m[2], raw)
        if occurrences != 1 or binding(candidate, actor) != dict(cfg, manifest_sha256=transition['after']):
            raise ValueError('certificate_update_actor_candidate:'+actor)
        name = path.lstrip('/')
        bound[name] = candidate
        candidates[path] = {'before':attrs,'after':dict(attrs,sha256=sha(candidate)),'source':name}
    return transition, candidates


def extend_contract(engine, checked, registered):
    required = (TARGET,*STOP) if TARGET in registered else STOP
    if set((*required,TIMER)) - set(registered):
        raise ValueError('certificate_update_units_not_registered')
    # The installed parent stops exactly the signed timer list before plan().
    if TIMER not in checked['pause']:
        raise ValueError('certificate_update_health_timer_missing_from_signed_pause')
    # Older enrollments may give the gate an alternate config and runtime tree.
    # They must complete the dedicated enrollment migration first.
    mounts = engine.commands.run('certificate_gate_view',
        ['/usr/bin/systemctl','show',GATE,'-p','BindReadOnlyPaths','--value']).decode()
    for mount in shlex.split(mounts):
        target = mount.lstrip('-').split(':',2)
        destination = (target[1] if len(target)>1 else target[0]).rstrip('/')
        if (destination in (RUNTIME.rstrip('/'),CONFIG.rstrip('/'))
                or destination.startswith((RUNTIME,CONFIG))):
            raise ValueError('certificate_update_active_enrollment_view')
    if set(required) & set(checked['reload']):
        raise ValueError('certificate_update_cannot_reload_actors')
    checked = dict(checked)
    for phase, order in (('stop',required),('start',tuple(reversed(required)))):
        present = [name for name in checked[phase] if name in order]
        if present and tuple(present)!=order:
            raise ValueError('certificate_update_lifecycle_order:'+phase)
        if not present:
            existing = checked[phase]
            checked[phase] = list(order)+existing if phase=='stop' else existing+list(order)
    checked['health'] = list(dict.fromkeys([*checked['health'],*required]))
    return checked


def verify_pins(engine, key):
    transition = engine.record.get('certificate_manifest_update')
    if not transition:
        return
    expected = transition[key]
    if sha(engine.live(MANIFEST)[0]) != expected:
        raise ValueError('certificate_update_manifest_readback')
    for path, actor in CONFIGS.items():
        if os.listxattr(engine.files.target(path), follow_symlinks=False):
            raise ValueError('certificate_update_configuration_xattrs:'+actor)
        if binding(engine.live(path)[0],actor).get('manifest_sha256') != expected:
            raise ValueError('certificate_update_actor_readback:'+actor)


def before_activation(engine):
    if not engine.record.get('certificate_manifest_update'):
        return
    from certificate_state import require_settled
    require_settled()
    verify_pins(engine,'before')


def wait_for_health(engine, unit):
    if unit != TIMER or not engine.record.get('certificate_manifest_update'):
        return
    deadline = time.monotonic()+100
    while True:
        raw = engine.commands.run('certificate_health_drain',
            ['/usr/bin/systemctl','show',HEALTH,'-p','ActiveState,MainPID,Job'], timeout=10)
        state = dict(line.split('=',1) for line in raw.decode().splitlines())
        if (state.get('ActiveState') in ('inactive','failed') and state.get('MainPID')=='0'
                and state.get('Job') in ('','0')):
            return
        if time.monotonic() >= deadline:
            raise ValueError('certificate_update_health_worker_busy')
        time.sleep(2)


def recover_write(engine, entry, candidate):
    """Recognize a published write interrupted before the final journal fsync."""
    path = entry['path']
    if (not engine.record.get('certificate_manifest_update') or not candidate
            or entry['phase']!='write_started'
            or (path not in CONFIGS and not path.startswith(RUNTIME))
            or entry['before']!=candidate['before']
            or entry['after']!=candidate['after']
            or engine.live(path)[1]!=entry['after']):
        return
    if entry['before'] is not None:
        original = regular(engine.directory/entry['backup'])[0]
        if sha(original)!=entry['before']['sha256']:
            raise ValueError('certificate_update_backup_drift')
    entry['phase'] = 'written'
    engine.files.save_entry(entry)
