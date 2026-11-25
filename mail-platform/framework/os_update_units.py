"""The two reconciliation units are managed with the existing update timer."""
import os

from code_attributes import attributes
from release import sha

PARENT = 'mail-platform-update.timer'
COMPANION = ('mail-platform-os-reconcile.timer','mail-platform-os-reconcile.service')
MANAGED = (PARENT,*COMPANION)


def additions(receipt, bound):
    available = {name for name in COMPANION if 'blueprint/systemd/'+name in bound}
    existing = set(COMPANION) & receipt['unit_files'].keys()
    if (available and available!=set(COMPANION)) or (existing and existing!=set(COMPANION)):
        raise ValueError('os_update_unit_pair_incomplete')
    if existing and existing!=available:
        raise ValueError('os_update_unit_removal')
    return available - existing


def changes(engine, receipt, bound, pause):
    new = additions(receipt,bound)
    if not any('blueprint/systemd/'+name in bound for name in COMPANION):
        return {}
    result = {}
    for name in MANAGED:
        path,source = '/etc/systemd/system/'+name,'blueprint/systemd/'+name
        before = receipt['unit_files'].get(name)
        if before is None and (name not in new or os.path.lexists(engine.files.target(path))):
            raise ValueError('os_update_unit_collision:'+name)
        if before is not None and engine.live(path)[1]!=before:
            raise ValueError('os_update_unit_drift:'+name)
        after = {'sha256':sha(bound[source]),**attributes(path,receipt['identities'],before,receipt['version'])}
        if after!=before:
            result[path] = {'before':before,'after':after,'source':source}
    if result and PARENT not in pause:
        raise ValueError('os_update_units_require_parent_timer_pause')
    return result
