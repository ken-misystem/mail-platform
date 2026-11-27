"""Bind the normal update worker to the signed timer-maintenance contract."""
import json
import os
from pathlib import Path
import re
import subprocess

from host_transaction import durable_json, regular
from release import require
from update_coordination import coordinated_hooks, stopped


UPDATE_SERVICE = 'mail-platform-update.service'
RESIDUAL_SERVICE = 'mail-residual-pop-v1.service'
CONTRACT = 'payload/blueprint/update-contract.json'
NO_JOB = ('', '0')
SYSTEMCTL = '/usr/bin/systemctl'
FIELDS = ('Id,ActiveState,SubState,MainPID,Job,InvocationID,ActiveEnterTimestampMonotonic,'
          'Result,ExecMainCode,ExecMainStatus')
RESIDUAL_HOLD_EVENT = {'status': 'held', 'reason': 'previous_cycle_not_verified'}


def command(argv, timeout=25):
    result = subprocess.run(argv, capture_output=True, timeout=timeout)
    require(result.returncode == 0 and not result.stderr, 'timer_coordinator_command_failed')
    return result.stdout


def properties(units, fields=FIELDS):
    raw = command([SYSTEMCTL, 'show', *units, '-p', fields]).decode().strip()
    rows = {}
    for section in raw.split('\n\n'):
        row = dict(line.split('=', 1) for line in section.splitlines())
        require(row['Id'] not in rows, 'timer_coordinator_duplicate_unit')
        rows[row['Id']] = row
    require(rows.keys() == set(units), 'timer_coordinator_unit_inventory')
    return rows


def self_worker():
    row = properties((UPDATE_SERVICE,), 'Id,MainPID,ControlGroup,InvocationID')[UPDATE_SERVICE]
    groups = [line[3:] for line in Path('/proc/self/cgroup').read_text().splitlines() if line.startswith('0::')]
    require(len(groups) == 1, 'update_worker_cgroup_v2_required')
    same_group = bool(row.get('ControlGroup')) and groups[0] == row['ControlGroup']
    same_pid = row.get('MainPID') == str(os.getpid())
    if not same_group and not same_pid:
        return None
    invocation = row.get('InvocationID', '')
    require(same_group and same_pid and invocation == os.environ.get('INVOCATION_ID')
            and re.fullmatch('[a-f0-9]{32}', invocation) and invocation.strip('0'), 'update_worker_identity_drift')
    return invocation


def residual_hold(row):
    """Accept the collector's single hold record for this failed invocation."""
    invocation = row.get('InvocationID', '')
    if not (row['Id'] == RESIDUAL_SERVICE and row['ActiveState'] == 'failed' and row['SubState'] == 'failed'
            and row['MainPID'] == '0' and row['Job'] in NO_JOB
            and row['Result'] == 'exit-code' and row['ExecMainCode'] == '1' and row['ExecMainStatus'] == '1'
            and re.fullmatch('[a-f0-9]{32}', invocation) and invocation.strip('0')):
        return False
    raw = command(['/usr/bin/journalctl', '--quiet', '--no-pager', '-o', 'cat', '-n', '2',
                   '_SYSTEMD_UNIT='+RESIDUAL_SERVICE, '_SYSTEMD_INVOCATION_ID='+invocation])
    lines = raw.splitlines()
    if len(lines) != 1:
        return False
    try:
        return json.loads(lines[0]) == RESIDUAL_HOLD_EVENT
    except ValueError:
        return False


def check_worker_failure(name, row):
    if row['ActiveState'] != 'failed':
        return False
    require(name == RESIDUAL_SERVICE and residual_hold(row), 'scheduled_worker_failed:'+name)
    return True


def hooks_for_release(root, files, hook):
    from code_update import contract

    offered = json.loads(files[CONTRACT][0])
    if offered.get('format') == 2:
        # Native generation contracts have their own lifecycle and no maintenance timer list.
        require('pause' not in offered, 'unexpected_generation_timer_contract')
        return hook
    receipt = json.loads(regular(root/'installed-code.json')[0])
    selected = contract(offered, receipt, {'php8.4-fpm.service'})
    timers = tuple(selected['pause'])
    if not timers:
        return hook
    raw_triggers = properties(timers, 'Id,Triggers')
    bindings = {name:row['Triggers'].split() for name, row in raw_triggers.items()}
    expected = {name:[name.removesuffix('.timer')+'.service'] for name in timers}
    require(bindings == expected, 'signed_timer_worker_binding_drift')
    workers = tuple(expected[name][0] for name in timers)
    own = self_worker() if UPDATE_SERVICE in workers else None
    if own is not None:
        require(all(UPDATE_SERVICE not in selected[phase] for phase in ('stop', 'start', 'reload', 'health')),
                'signed_contract_operates_on_current_update_worker')

    # This factory runs under the update lock, before extraction and timer changes.
    for name, row in properties(workers).items():
        check_worker_failure(name, row)

    evidence = None

    def record(name, data):
        durable_json(evidence/(name+'.json'), data)

    def ready(name, row):
        if name == UPDATE_SERVICE and own is not None:
            require(row['MainPID'] == str(os.getpid()) and row['InvocationID'] == own
                    and row['ActiveState'] == 'activating' and row['SubState'] == 'start',
                    'current_update_worker_replaced')
            return True
        return check_worker_failure(name, row) or stopped(row)

    def verify_plan(transaction):
        code_plan = transaction/'code-update.json'
        if code_plan.is_file():
            plan = json.loads(regular(code_plan)[0])
            actual = plan['contract']
        else:
            plan = json.loads(regular(transaction/'generation-update.json')[0])
            actual = plan['maintenance']
        require(tuple(actual['pause']) == timers and all(stopped(plan['before_units'][name]) for name in timers),
                'signed_plan_timer_boundary_drift')

    def verified(_):
        # The signed hook and timer window already enforce health and known restoration.
        pass

    coordinated = coordinated_hooks(hook, timers=timers, workers=workers, observe=properties, command=command,
        worker_ready=ready, save_observation=record, validate_plan=verify_plan, validate_activation=verified,
        validate_health=verified, validate_resume=verified, validate_restored=verified)

    def invoke(stage, action, transaction):
        nonlocal evidence
        if action == 'plan':
            evidence = transaction/'timer-coordination'
            evidence.mkdir(mode=0o700)
            record('bindings', {'timers':list(timers), 'workers':list(workers), 'self_worker': own is not None})
        return coordinated(stage, action, transaction)

    return invoke
