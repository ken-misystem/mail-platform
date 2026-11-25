
"""Common timer coordination for an approved signed-update continuation."""
import re
import time


TIMER_CYCLE = frozenset(('running', 'waiting'))
NO_JOB = ('', '0')


def need(condition, reason):
    if not condition:
        raise ValueError(reason)


def active(row):
    return (row.get('ActiveState') == 'active' and row.get('Job') in NO_JOB
            and row.get('SubState') in TIMER_CYCLE | {'elapsed'})


def stopped(row):
    return (row.get('ActiveState') == 'inactive' and row.get('SubState') == 'dead'
            and row.get('Job') in NO_JOB and row.get('MainPID', '0') == '0')


def same_timer(expected, actual):
    """Ignore the successful scheduling cycle only within one active invocation."""
    if stopped(expected) and stopped(actual):
        return expected == actual
    if not active(expected) or not active(actual):
        return False
    invocation = expected.get('InvocationID', '')
    entered = expected.get('ActiveEnterTimestampMonotonic', '')
    if not re.fullmatch('[a-f0-9]{32}', invocation) or not invocation.strip('0') or not entered.isdecimal() or int(entered) <= 0:
        return False
    if expected == actual:
        return True
    if expected['SubState'] not in TIMER_CYCLE or actual['SubState'] not in TIMER_CYCLE:
        return False
    return dict(expected, SubState='waiting') == dict(actual, SubState='waiting')


def worker_stop_dependencies(timers, workers):
    """Find direct stop propagation from a target timer, including inverse edges."""
    fields = ('PartOf', 'Requires', 'BindsTo', 'StopPropagatedFrom')
    conflicts = {}
    for name, row in workers.items():
        linked = {unit for field in fields for unit in row[field].split()}
        blocked = sorted(linked.intersection(timers))
        if blocked:
            conflicts[name] = blocked
    return conflicts


def require_worker_stop_independent(timers, workers, command):
    fields = 'Id,PartOf,Requires,BindsTo,StopPropagatedFrom'
    raw = command(['/usr/bin/systemctl', 'show', *workers, '-p', fields])
    rows = {}
    for section in raw.decode().strip().split('\n\n'):
        row = dict(line.split('=', 1) for line in section.splitlines())
        name = row.get('Id')
        need(name not in rows and set(row) == set(fields.split(',')), 'worker_stop_dependencies_incomplete')
        rows[name] = row
    need(rows.keys() == set(workers), 'worker_stop_dependency_inventory_changed')
    conflicts = worker_stop_dependencies(timers, rows)
    need(not conflicts, 'timer_stop_would_interrupt_worker:' + ','.join(conflicts))


def wait_stable_workers(workers, observe, is_quiet, *, timeout=180, clock=time.monotonic, sleep=time.sleep):
    """Require two identical quiet observations within one wait budget."""
    deadline = clock() + timeout
    previous = None
    while clock() < deadline:
        current = observe(workers)
        need(current.keys() == set(workers), 'worker_inventory_changed')
        if all(is_quiet(name, row) for name, row in current.items()):
            if current == previous and clock() <= deadline:
                return [previous, current]
            previous = {name: dict(row) for name, row in current.items()}
        else:
            previous = None
        sleep(min(1, max(0, deadline - clock())))
    raise ValueError('scheduled_workers_did_not_drain')


def prepare_timer_window(timers, workers, observe, command, worker_ready, record):
    """Bind the reviewed unit order to the systemd operations used by a launcher."""
    def validate_stop():
        require_worker_stop_independent(timers, workers, command)

    validate_stop()
    original = observe(timers)
    need(original.keys() == set(timers), 'timer_inventory_changed')

    def operate(action, name):
        command(['/usr/bin/systemctl', action, '--quiet', name], timeout=40)

    def drain():
        return wait_stable_workers(workers, observe, worker_ready)

    return TimerWindow({name: original[name] for name in timers}, observe, operate, record,
                       validate_stop=validate_stop), drain


class TimerWindow:
    def __init__(self, original, observe, operate, record, *, validate_stop=None):
        need(all(same_timer(row, row) for row in original.values()), 'original_timer_not_settled')
        self.original = {name: dict(row) for name, row in original.items()}
        self.originally_active = {name for name, row in original.items() if active(row)}
        self.expected = dict(self.original)
        self.observe = observe
        self.operate = operate
        self.record = record
        self.validate_stop = validate_stop or (lambda: None)
        self.paused = set()
        self.resumed = set()
        self.pending = None
        self.sequence = 0
        self.conflicts = 0

    def check(self):
        need(self.pending is None, 'timer_operation_outcome_unknown')
        current = self.observe(tuple(self.original))
        different = [name for name, row in self.expected.items()
                     if name not in current or not same_timer(row, current[name])]
        unexpected = sorted(current.keys() - self.expected.keys())
        if different or unexpected:
            self.conflicts += 1
            self.record(f'timer-conflict-{self.conflicts:02}', {
                'different': {name: {'expected': self.expected[name], 'observed': current.get(name)} for name in different},
                'unexpected': unexpected,
            })
            raise ValueError('timer_state_changed_outside_window:' + ','.join(different + unexpected))
        return current

    def change(self, action, name):
        before = dict(self.check()[name])
        need(action in ('start', 'stop'), 'unsupported_timer_operation')
        need((stopped if action == 'start' else active)(before), 'timer_operation_precondition:' + name)
        self.sequence += 1
        request = {'operation': action, 'unit': name, 'before': before}
        self.record(f'timer-{self.sequence:02}-intent', request)
        self.check()
        self.pending = request
        self.operate(action, name)
        actual = dict(self.observe((name,))[name])
        self.record(f'timer-{self.sequence:02}-observation', {**request, 'observed': actual})
        need((active if action == 'start' else stopped)(actual), 'timer_transition_unconfirmed:' + name)
        self.record(f'timer-{self.sequence:02}-result', {**request, 'after': actual})
        self.expected[name] = actual
        self.pending = None

    def pause(self):
        self.check()
        self.validate_stop()
        for name in self.original:
            if name in self.originally_active:
                self.change('stop', name)
                self.paused.add(name)

    def require_paused(self):
        current = self.check()
        need(self.paused == self.originally_active and not self.resumed
             and all(stopped(row) for row in current.values()), 'timer_window_not_fully_paused')

    def resume(self):
        self.check()
        for name in self.original:
            if name in self.paused and name not in self.resumed:
                self.change('start', name)
                self.resumed.add(name)
        current = self.check()
        need(all((active if name in self.originally_active else stopped)(row) for name, row in current.items()),
             'timer_resume_incomplete')

    def reclose_resumed(self):
        self.check()
        self.validate_stop()
        for name in reversed(self.original):
            if name in self.resumed:
                self.change('stop', name)
                self.resumed.remove(name)


def steps(window, drain, save, invoke, validate_plan, validate_activation, validate_health, validate_resume):
    window.pause()
    save('drained-before-plan', drain())
    window.require_paused()
    invoke('plan')
    validate_plan()
    window.require_paused()
    invoke('stage')
    save('drained-before-activate', drain())
    validate_activation()
    window.require_paused()
    invoke('activate')
    window.require_paused()
    invoke('health')
    validate_health()
    window.resume()
    validate_resume()


def recover(window, error, drain, invoke, signed_started, validate_restored):
    window.check()
    need(not getattr(error, 'uncertain', False), 'signed_hook_outcome_unknown')
    if signed_started:
        if window.resumed:
            window.reclose_resumed()
            drain()
        window.require_paused()
        invoke('rollback')
    window.resume()
    validate_restored()

"""Wire the shared timer window into the signed updater's ordinary hook path.

This file is embedded after the shared coordination source by bundle.py.
The caller supplies a fixed reviewed contract, local trust key and host guards.
"""
from pathlib import Path


def coordinated_hooks(hook, *, timers, workers, observe, command, worker_ready, save_observation,
                      validate_plan, validate_activation, validate_health, validate_resume,
                      validate_restored):
    window = None
    drain = None
    started = False
    history = []
    order = ('plan', 'stage', 'activate', 'health')

    def invoke(stage, phase, transaction):
        nonlocal window, drain, started
        if phase == 'plan':
            window, drain = prepare_timer_window(timers, workers, observe, command,
                                                worker_ready, save_observation)
            window.pause()
            save_observation('drained-before-plan', drain())
            window.require_paused()
            started = True
            result = hook(stage, phase, transaction)
            history.append(phase)
            try:
                validate_plan(transaction)
            except Exception as error:
                error.record = result
                raise
            return result
        if phase == 'rollback':
            if window is None:
                validate_restored(transaction)
                return {'action': 'rollback', 'scope': 'before_timer_coordination'}
            completed = []

            def signed_rollback(action):
                completed.append(hook(stage, action, transaction))

            # run_update invokes rollback only when the last signed hook's outcome is known.
            recover(window, None, drain, signed_rollback, started,
                    lambda: validate_restored(transaction))
            return completed[0] if completed else {'action': 'rollback', 'scope': 'timers_only'}
        need(window is not None and len(history) < len(order) and phase == order[len(history)],
             'signed_update_hook_order')
        if phase == 'activate':
            save_observation('drained-before-activate', drain())
            validate_activation(transaction)
        window.require_paused()
        result = hook(stage, phase, transaction)
        history.append(phase)
        if phase == 'health':
            try:
                validate_health(transaction)
                window.resume()
                validate_resume(transaction)
            except Exception as error:
                error.record = result
                raise
        return result

    return invoke


def run_coordinated_update(state, archive, metadata, signature, key, **window):
    from updater import hook, run_update

    return run_update(Path(state), archive, metadata, signature, key, manual=True,
                      openssl='/usr/bin/openssl', hook_fn=coordinated_hooks(hook, **window))
