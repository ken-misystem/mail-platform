"""Verify ordinary update coordination with the collector's known and unknown failures."""
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import uuid

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'framework'))
import ordinary_update as ordinary
import release
import update_coordination as coordination
import updater


def failure(name=None, **fields):
    return {'Id':name or ordinary.RESIDUAL_SERVICE, 'ActiveState':'failed', 'SubState':'failed',
            'MainPID':'0', 'Job':'', 'InvocationID':'a'*32, 'Result':'exit-code',
            'ExecMainCode':'1', 'ExecMainStatus':'1', **fields}


class ResidualClassification(unittest.TestCase):
    def test_exact_current_invocation_is_the_only_known_hold(self):
        valid = b'{"status":"held","reason":"previous_cycle_not_verified"}\n'
        with patch.object(ordinary,'command',return_value=valid) as command:
            self.assertTrue(ordinary.check_worker_failure(ordinary.RESIDUAL_SERVICE,failure()))
            argv = command.call_args.args[0]
            self.assertIn('_SYSTEMD_UNIT='+ordinary.RESIDUAL_SERVICE,argv)
            self.assertIn('_SYSTEMD_INVOCATION_ID='+'a'*32,argv)
        for evidence in (b'', b'{"status":"fail","reason":"previous_cycle_not_verified"}\n',
                         b'{"reason":"previous_cycle_not_verified"}\n', b'not-json\n',
                         valid+b'{"status":"fail","reason":"another_failure"}\n',
                         b'unexpected traceback\n'+valid):
            with self.subTest(evidence=evidence), patch.object(ordinary,'command',return_value=evidence):
                with self.assertRaisesRegex(ValueError,'scheduled_worker_failed:mail-residual-pop'):
                    ordinary.check_worker_failure(ordinary.RESIDUAL_SERVICE,failure())

    def test_failed_metadata_cannot_borrow_the_known_hold(self):
        variations = [{'InvocationID':'0'*32},{'InvocationID':''},{'MainPID':'205'},{'Job':'32'},
                      {'Result':'signal'},{'ExecMainCode':'2'},{'ExecMainStatus':'75'}]
        with patch.object(ordinary,'command') as command:
            for fields in variations:
                with self.subTest(fields=fields), self.assertRaisesRegex(ValueError,'scheduled_worker_failed'):
                    ordinary.check_worker_failure(ordinary.RESIDUAL_SERVICE,failure(**fields))
            with self.assertRaisesRegex(ValueError,'scheduled_worker_failed:other.service'):
                ordinary.check_worker_failure('other.service',failure('other.service'))
            command.assert_not_called()


class SignedHookWindow(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        (self.root/'installed-code.json').write_bytes(b'{}')
        self.tx = self.root/'transaction'
        self.tx.mkdir()
        self.latch = self.root/'held-cycle.json'
        self.latch.write_bytes(b'{"previous":1}\n')
        self.worker = ordinary.RESIDUAL_SERVICE
        self.timer = self.worker.removesuffix('.service')+'.timer'
        self.timer_row = {'Id':self.timer,'ActiveState':'active','SubState':'waiting','MainPID':'0',
                          'Job':'','InvocationID':'a'*32,'ActiveEnterTimestampMonotonic':'429'}
        self.worker_row = failure()
        self.events = []
        self.evidence = b'{"status":"held","reason":"previous_cycle_not_verified"}\n'
        self.unknown_after_stop = False
        self.contract = {'format':1,'pause':[self.timer], 'stop':[], 'start':[], 'reload':[], 'health':[]}
        self.files = {ordinary.CONTRACT:(json.dumps(self.contract).encode(),0o644)}
        self.enterContext(patch('code_update.contract',return_value=self.contract))
        self.enterContext(patch.object(ordinary,'command',side_effect=self.command))
        self.enterContext(patch.object(ordinary,'properties',side_effect=self.observe))
        wait = coordination.wait_stable_workers
        self.enterContext(patch.object(coordination,'wait_stable_workers',
                                      side_effect=lambda *args:wait(*args,sleep=lambda _:None)))

    def observe(self, names, fields=None):
        if fields=='Id,Triggers':
            return {self.timer:{'Triggers':self.worker}}
        rows = {self.timer:self.timer_row,self.worker:self.worker_row}
        return {name:copy.copy(rows[name]) for name in names}

    def command(self, argv, timeout=25):
        if argv[0].endswith('journalctl'):
            return self.evidence
        if argv[1]=='show':
            return f'Id={self.worker}\nPartOf=\nRequires=\nBindsTo=\nStopPropagatedFrom=\n'.encode()
        self.assertEqual(argv[-1],self.timer)
        name = argv[1]
        self.events.append(name+':timer')
        self.timer_row.update({'ActiveState':'inactive','SubState':'dead'} if name=='stop'
                              else {'ActiveState':'active','SubState':'waiting'})
        if name=='stop' and self.unknown_after_stop:
            self.evidence = b'{"status":"fail","reason":"unknown_after_pause"}\n'

    def hook(self, stage, action, transaction):
        self.events.append(action+':signed')
        if action=='plan':
            (transaction/'code-update.json').write_text(json.dumps({
                'contract':self.contract,'before_units':self.observe((self.timer,))}))
        return {'action':action,'exit':0}

    def test_known_hold_runs_all_signed_phases_and_preserves_latch(self):
        hooks = ordinary.hooks_for_release(self.root,self.files,self.hook)
        for phase in ('plan','stage','activate','health'):
            self.assertEqual(hooks(self.root,phase,self.tx)['exit'],0)
        self.assertEqual(self.events,['stop:timer','plan:signed','stage:signed',
                                      'activate:signed','health:signed','start:timer'])
        self.assertEqual(self.worker_row,failure())
        self.assertEqual(self.latch.read_bytes(),b'{"previous":1}\n')

    def test_unknown_failure_rejects_before_timer_or_stage(self):
        self.evidence = b'{"status":"fail","reason":"unverified"}\n'
        with self.assertRaisesRegex(ValueError,'scheduled_worker_failed'):
            ordinary.hooks_for_release(self.root,self.files,self.hook)
        self.assertEqual(self.events,[])
        self.assertFalse((self.tx/'timer-coordination').exists())

    def test_unknown_after_preflight_reopens_timer_and_never_runs_signed_plan(self):
        self.unknown_after_stop = True
        hooks = ordinary.hooks_for_release(self.root,self.files,self.hook)
        with self.assertRaisesRegex(ValueError,'scheduled_worker_failed'):
            hooks(self.root,'plan',self.tx)
        self.assertEqual(hooks(self.root,'rollback',self.tx)['scope'],'timers_only')
        self.assertEqual(self.events,['stop:timer','start:timer'])
        self.assertEqual(self.latch.read_bytes(),b'{"previous":1}\n')

    def test_unknown_after_staging_rolls_back_the_signed_plan_and_restores_timer(self):
        hooks = ordinary.hooks_for_release(self.root,self.files,self.hook)
        hooks(self.root,'plan',self.tx)
        hooks(self.root,'stage',self.tx)
        self.evidence = b'{"status":"fail","reason":"unknown_after_stage"}\n'
        with self.assertRaisesRegex(ValueError,'scheduled_worker_failed'):
            hooks(self.root,'activate',self.tx)
        self.assertEqual(hooks(self.root,'rollback',self.tx)['action'],'rollback')
        self.assertEqual(self.events,['stop:timer','plan:signed','stage:signed','rollback:signed','start:timer'])
        self.assertEqual(self.latch.read_bytes(),b'{"previous":1}\n')

    def test_actual_updater_refuses_unknown_before_creating_transaction_or_release(self):
        self.evidence = b'{"status":"fail","reason":"unverified"}\n'
        current = {'version':'0.4.20','release':None}
        updater.save(self.root/'installed.json',current)
        contents = {'payload/installer.py':b'pass\n',ordinary.CONTRACT:self.files[ordinary.CONTRACT][0]}
        entries = []
        for index,(name,raw) in enumerate(contents.items()):
            source = self.root/('source-'+str(index))
            source.write_bytes(raw)
            entries.append({'name':name,'source':source.name,'sha256':release.sha(raw)})
        archive = self.root/'synthetic.tar.gz'
        metadata = release.build(self.root,entries,'0.4.21',archive,ready=True)
        secret,pub = self.root/'synthetic-key',self.root/'synthetic-pub'
        subprocess.run(['/usr/bin/openssl','genpkey','-algorithm','ED25519','-out',secret],check=True)
        subprocess.run(['/usr/bin/openssl','pkey','-in',secret,'-pubout','-out',pub],check=True)
        signature = release.sign(metadata,secret)
        secret.unlink()
        with self.assertRaisesRegex(release.ReleaseError,'scheduled_worker_failed'):
            updater.run_update(self.root,archive,metadata,signature,pub,manual=True,hook_fn=self.hook,
                               hook_factory=ordinary.hooks_for_release)
        self.assertEqual(updater.load(self.root/'installed.json'),current)
        self.assertFalse((self.root/'transaction.json').exists())
        self.assertFalse((self.root/'releases').exists())
        self.assertEqual(self.events,[])


@unittest.skipUnless(os.getenv('MAIL_PLATFORM_TEST_SYSTEMD')=='1','requires dedicated systemd test host')
class ActualJournal(unittest.TestCase):
    def test_only_the_same_real_systemd_invocation_can_authorize_hold(self):
        name = 'mail-platform-residual-proof-'+uuid.uuid4().hex+'.service'
        command = ['/usr/bin/systemd-run','--quiet','--wait','--unit='+name,
                   '--property=Type=oneshot','--property=PrivateNetwork=yes',
                   '--property=StandardOutput=journal','--property=StandardError=journal']
        def service(event):
            code = 'print('+repr(json.dumps(event)) + ',flush=True);raise SystemExit(1)'
            result = subprocess.run([*command,'/usr/bin/python3','-I','-S','-B','-c',code],
                                    capture_output=True,timeout=30)
            self.assertEqual(result.returncode,1,(result.stdout,result.stderr))
            subprocess.run(['/usr/bin/journalctl','--sync'],check=True,timeout=12)
            return ordinary.properties((name,))[name]
        with patch.object(ordinary,'RESIDUAL_SERVICE',name):
            try:
                known = service(ordinary.RESIDUAL_HOLD_EVENT)
                self.assertTrue(ordinary.check_worker_failure(name,known),known)
                subprocess.run(['/usr/bin/systemctl','reset-failed',name],check=True,timeout=10)
                unknown = service({'status':'fail','reason':'synthetic_unknown'})
                self.assertNotEqual(known['InvocationID'],unknown['InvocationID'])
                with self.assertRaisesRegex(ValueError,'scheduled_worker_failed'):
                    ordinary.check_worker_failure(name,unknown)
            finally:
                subprocess.run(['/usr/bin/systemctl','reset-failed',name],capture_output=True,timeout=10)
        self.assertEqual(ordinary.properties((name,),'Id,LoadState')[name]['LoadState'],'not-found')
