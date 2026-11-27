"""Reservation recovery exercises the updater with a disposable signing key."""
import json
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

PRODUCT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(PRODUCT/'framework'))
import broker
import github
import manual_update_request as manual
import release
import updater


@unittest.skipUnless(sys.platform=='linux','Linux update files and locks')
class ManualRequest(unittest.TestCase):
    def setUp(self):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        base = Path(temporary.name)
        self.root=base/'state'
        self.root.mkdir(mode=0o700)
        self.old={'version':'0.4.19','release':None}
        updater.save(self.root/'installed.json',self.old)
        self.identifier='a'*32
        self.archive=base/'bundle.tar.gz'
        installer=base/'installer.py'
        installer.write_bytes(b'pass\n')
        self.metadata=release.build(base,[{'name':'payload/installer.py','source':'installer.py',
                                          'sha256':release.sha(installer.read_bytes())}],
                                    '0.4.20',self.archive,ready=True)
        self.pub=base/'pub'
        secret=base/'lab.key'
        subprocess.run(['/usr/bin/openssl','genpkey','-algorithm','ed25519','-out',secret],check=True)
        subprocess.run(['/usr/bin/openssl','pkey','-in',secret,'-pubout','-out',self.pub],check=True)
        self.signature=release.sign(self.metadata,secret)
        self.offer('0.4.20',self.metadata['sha256'])
        self.actions=[]

    def offer(self, version, digest):
        updater.save(self.root/'available.json',{'verified':True,'version':version,
              'cache_sha256':{'mail-platform.tar.gz':digest}})

    def reserve(self, request_id=None, version='0.4.20'):
        return broker.operation({'operation':'apply','mode':'manual','revision':0,'actor':'1',
                                 'version':version,'request_id':request_id or self.identifier}, self.root)

    def hook(self, stage, action, transaction):
        self.actions.append(action)
        return {'action':action,'exit':0}

    def update(self, hook=None):
        return updater.run_update(self.root,self.archive,self.metadata,self.signature,self.pub,
            manual=True, reservation=manual.pending_for_worker(self.root), hook_fn=hook or self.hook)

    def test_archives_after_commit_interruption_and_accepts_new_reservation(self):
        self.reserve()
        original=manual.record(self.root/manual.PENDING)
        save=updater.save
        def interrupt(path,value):
            save(path,value)
            if path==self.root/'transaction.json' and value.get('phase')=='complete':
                raise SystemExit('simulated_worker_exit_after_commit_pointer')
        with patch.object(updater,'save',interrupt),self.assertRaisesRegex(SystemExit,'after_commit_pointer'):
            self.update()
        self.assertEqual(manual.record(self.root/manual.PENDING),original)
        self.offer('0.4.21','b'*64)
        self.reserve('c'*32,'0.4.21')
        receipt=manual.record(self.root/('completed-request-'+self.identifier+'.json'))
        self.assertEqual(receipt['request'],original)
        self.assertEqual(receipt['transaction_id'],updater.load(self.root/'transaction.json')['id'])
        self.assertEqual(manual.record(self.root/manual.PENDING)['version'],'0.4.21')
        self.assertEqual(self.actions,['plan','stage','activate','health'])

    def test_interruption_after_receipt_creation_is_idempotent(self):
        self.reserve()
        self.update()
        pending=self.root/manual.PENDING
        unlink=Path.unlink
        def interrupt(path,*args,**kwargs):
            if path==pending:
                raise SystemExit('simulated_exit_before_pending_unlink')
            return unlink(path,*args,**kwargs)
        with patch.object(Path,'unlink',interrupt),self.assertRaises(SystemExit):
            manual.pending_for_worker(self.root)
        archived=self.root/('completed-request-'+self.identifier+'.json')
        receipt=archived.read_bytes()
        self.assertTrue(pending.exists())
        self.assertIsNone(manual.pending_for_worker(self.root))
        self.assertEqual(archived.read_bytes(),receipt)

    def test_rollback_and_unknown_completion_preserve_reservation(self):
        self.reserve()
        pending=self.root/manual.PENDING
        original=pending.read_bytes()
        def fail(stage,action,tx):
            if action=='health':
                raise ValueError('injected_health_failure')
            return self.hook(stage,action,tx)
        with self.assertRaisesRegex(ValueError,'update_rolled_back'):
            self.update(fail)
        self.assertEqual(updater.load(self.root/'installed.json'),self.old)
        self.assertEqual(pending.read_bytes(),original)
        self.assertIn('rollback',self.actions)
        self.assertIsNotNone(manual.pending_for_worker(self.root))
        self.assertFalse(list(self.root.glob('completed-request-*')))
        tx=updater.load(self.root/'transaction.json')
        updater.save(self.root/'transaction.json',dict(tx,phase='complete'))
        with self.assertRaisesRegex(ValueError,'manual_update_journal_mismatch'):
            manual.pending_for_worker(self.root)
        self.assertEqual(pending.read_bytes(),original)

    def test_wrong_archive_on_same_version_is_rejected_before_hooks(self):
        self.offer('0.4.20','d'*64)
        self.reserve()
        with self.assertRaisesRegex(ValueError,'manual_update_reserved_release_mismatch'):
            self.update()
        self.assertEqual(self.actions,[])
        self.assertFalse((self.root/'transaction.json').exists())

    def test_stale_form_and_legacy_request_are_preserved_or_refused(self):
        with self.assertRaisesRegex(ValueError,'manual_update_verified_candidate_required'):
            self.reserve(version='0.4.18')
        self.assertFalse((self.root/manual.PENDING).exists())
        legacy={'request_id':self.identifier,'actor':'1'}
        updater.save(self.root/manual.PENDING,legacy)
        with self.assertRaisesRegex(ValueError,'manual_update_legacy_request_requires_review'):
            manual.pending_for_worker(self.root)
        self.assertEqual(manual.record(self.root/manual.PENDING),legacy)

    def test_reserved_tag_lookup_refuses_a_different_version(self):
        row={'tag_name':'v0.4.21','assets':[]}
        with patch.object(github,'request',return_value=json.dumps(row).encode()) as request:
            with self.assertRaisesRegex(ValueError,'manual_update_reserved_tag_mismatch'):
                github.tagged('example/project','0.4.20')
        self.assertTrue(request.call_args.args[0].endswith('/releases/tags/v0.4.20'))


if __name__=='__main__':
    unittest.main(verbosity=2)
