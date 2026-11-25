"""Check bounded OS recovery, package provenance and updater unit adoption."""
import io
import json
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

PRODUCT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(PRODUCT/'framework'))
import os_reconcile as recovery
from os_package_proof import matching_archive_pin, member_hash
import os_update_units as migration
from release import sha


def services(db='2'*32, certificates=False, feature=False):
    rows = {name:{'ActiveState':'active','InvocationID':db} for name in recovery.UNITS}
    for name in recovery.CERTIFICATES:
        rows[name]['ActiveState'] = 'active' if certificates else 'inactive'
    rows[recovery.FEATURE]['ActiveState'] = 'active' if feature else 'inactive'
    return rows


class RecoveryPolicy(unittest.TestCase):
    def setUp(self):
        self.previous = {'boot':'lab','database':'1'*32,'certificates':True,'feature':True}

    def test_database_restart_recovers_enabled_groups(self):
        result = recovery.choose(self.previous,services(),'lab',{})
        self.assertTrue(result['restore_certificates'] and result['restore_feature'])

    def test_same_database_and_new_boot_do_not_reopen_stopped_services(self):
        for rows,boot in ((services(db='1'*32),'lab'),(services(),'new-boot'),(services(),'unknown')):
            result = recovery.choose(self.previous,rows,boot,{'php_pin':{}})
            self.assertFalse(any(result.values()))

    def test_changed_executable_restarts_only_running_certificate_group(self):
        result = recovery.choose(self.previous,services(db='1'*32,certificates=True,feature=True),'lab',{'openssl_pin':{}})
        self.assertTrue(result['rebind_live'])
        self.assertFalse(result['restore_feature'])

    def test_intentionally_stopped_or_initially_unobserved_stack(self):
        previous = dict(self.previous,certificates=False,feature=False)
        for known in (None,previous):
            self.assertFalse(any(recovery.choose(known,services(),'lab',{}).values()))

    def test_source_pins_and_registration_change_together(self):
        def row(data):
            raw = json.dumps(data).encode()
            return raw,{'sha256':sha(raw),'uid':0,'gid':0,'mode':0o640}
        live = {recovery.MANIFEST:row({'openssl_pin':'a'*64,'php_pin':'b'*64,'python_pin':'c'*64,'pins':{'x':'d'*64}})}
        old = live[recovery.MANIFEST][1]
        for actor in recovery.ACTORS:
            live[recovery.CONFIG+actor+'.json'] = row({'actor':actor,'profile':'production','release':recovery.LIB.rstrip('/'),
                'manifest_sha256':old['sha256'],'executables':{'php':'/usr/bin/php8.4','openssl':'/usr/bin/openssl'},'other':42})
        unrelated = {'sha256':'e'*64,'mode':0o644,'uid':0,'gid':0}
        live[recovery.RECEIPT] = row({'format':2,'version':'0.4.9','code':{recovery.MANIFEST:old,'/other':unrelated}})
        with patch.object(recovery,'trusted',side_effect=lambda path,**kw:live[path]), patch.object(recovery.os,'listxattr',return_value=[],create=True):
            result = recovery.prepared_files({'php_pin':{'executable_sha256':'f'*64}})
        self.assertEqual(len(result),7)
        manifest = json.loads(result[recovery.MANIFEST]['raw'])
        self.assertEqual(manifest,dict(json.loads(live[recovery.MANIFEST][0]),php_pin='f'*64))
        for path in (recovery.CONFIG+actor+'.json' for actor in recovery.ACTORS):
            self.assertEqual(json.loads(result[path]['raw']),dict(json.loads(live[path][0]),manifest_sha256=result[recovery.MANIFEST]['after']['sha256']))
        self.assertEqual(json.loads(result[recovery.RECEIPT]['raw'])['code'],{recovery.MANIFEST:result[recovery.MANIFEST]['after'],'/other':unrelated})


class ArchiveEvidence(unittest.TestCase):
    def test_apt_archive_hash_bound_to_package_architecture_and_version(self):
        key = 'b'*64
        row = f'Package: openssl\nArchitecture: amd64\nVersion: 3.5.9\nSHA256: {key}\n'
        self.assertEqual(matching_archive_pin(row,'openssl','3.5.9','amd64'),key)
        for raw,version,arch in ((row,'3.5.8','amd64'),(row,'3.5.9','arm64'),(row+'\n'+row.replace(key,'a'*64),'3.5.9','amd64')):
            with self.assertRaisesRegex(ValueError,'os_apt_archive_missing_or_ambiguous'):
                matching_archive_pin(raw,'openssl',version,arch)

    def test_archive_binary_requires_a_unique_root_owned_regular_file(self):
        def render(second=None):
            stream = io.BytesIO()
            with tarfile.open(fileobj=stream,mode='w:') as tar:
                first = tarfile.TarInfo('./usr/bin/openssl'); first.mode=0o755; first.size=3
                if second != 'link':
                    tar.addfile(first,io.BytesIO(b'abc'))
                if second:
                    first.type = tarfile.SYMTYPE; first.size=0; first.linkname='/other'
                    tar.addfile(first)
            stream.seek(0)
            return stream
        self.assertEqual(member_hash(render(),'/usr/bin/openssl'),sha(b'abc'))
        for case in ('link','duplicate'):
            with self.assertRaisesRegex(ValueError,'os_archive_member'):
                member_hash(render(case),'/usr/bin/openssl')


class UnitMigration(unittest.TestCase):
    def test_missing_pair_collision_and_lifecycle_checks(self):
        from types import SimpleNamespace
        paths = {n:'blueprint/systemd/'+n for n in migration.MANAGED}
        bound = {path:(PRODUCT/'payload'/path).read_bytes() for path in paths.values()}
        old = {'sha256':'a'*64,'uid':0,'gid':0,'mode':0o644}
        receipt = {'unit_files':{migration.PARENT:old},'identities':{},'version':'0.4.9'}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            engine = SimpleNamespace(files=SimpleNamespace(target=lambda name:root/Path(name).name),live=lambda _: (b'',old))
            result = migration.changes(engine,receipt,bound,[migration.PARENT])
            self.assertEqual(len(result),3)
            self.assertEqual({name for name,row in result.items() if row['before'] is None},
                             {'/etc/systemd/system/'+n for n in migration.COMPANION})
            with self.assertRaisesRegex(ValueError,'require_parent_timer_pause'):
                migration.changes(engine,receipt,bound,[])
            with self.assertRaisesRegex(ValueError,'unit_pair_incomplete'):
                migration.changes(engine,receipt,{k:v for k,v in bound.items() if k!=paths[migration.COMPANION[0]]},[migration.PARENT])
            (root/migration.COMPANION[0]).write_bytes(b'foreign')
            with self.assertRaisesRegex(ValueError,'unit_collision'):
                migration.changes(engine,receipt,bound,[migration.PARENT])
