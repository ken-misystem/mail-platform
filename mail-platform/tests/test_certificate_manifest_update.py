"""Exercise both update engines with real files and separate certificate starts."""
from contextlib import ExitStack
import json
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

PRODUCT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(PRODUCT/'framework'),str(PRODUCT)]
import adaptive_update
import certificate_manifest_update as certificate
import certificate_state
import code_update
import dkim_readiness
from host_transaction import Files, durable_json, regular
import monitor_binding
from release import canonical, sha
from update_entry import engine_for


SOURCE = PRODUCT/'payload'/certificate.RUNTIME.lstrip('/')
BOOT = SOURCE/'client-certificates/runtime-completion-v1/boot.py'
WHEEL = 'pymysql-1.2.3-py3-none-any.whl'
POLICY = certificate.RUNTIME+'test-policy.py'

# Map the fixture root into the actor's production paths. Stop at the import
# boundary after the actual startup guard verified every configured pin.
CHECK_STARTUP = r"""
import importlib, os, sys
from pathlib import Path
source, root, actor = sys.argv[1:]
sys.path.insert(0, source)
import boot, safety
boot.__file__ = '/usr/local/lib/mail-client-certificates-v1/client-certificates/runtime-completion-v1/boot.py'
boot.held = lambda path, limit=131072: safety.held(str(Path(root)/path.lstrip('/')), limit)
class PinsVerified(Exception): pass
class Boundary:
    def find_spec(self, name, path, target=None):
        if name == 'pymysql':
            raise PinsVerified()
sys.meta_path.insert(0, Boundary())
try:
    boot.load(actor,'/etc/mail-client-certificates-v1/'+actor+'.json')
except PinsVerified:
    print('STARTUP_PINS_VERIFIED')
else:
    raise AssertionError('startup_test_boundary_not_reached')
"""


class SystemdServices:
    def __init__(self, root, work, cleanup):
        prefix = work.name
        names = (*certificate.STOP,certificate.TARGET,certificate.TIMER,certificate.HEALTH)
        self.names = {unit:prefix+'-'+unit.removeprefix('mail-client-') for unit in names}
        self.files = []
        cleanup(self.clean)
        startup = work/'start.py'
        startup.write_text(CHECK_STARTUP+"""
import signal, socket
with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as s:
    address = os.environ['NOTIFY_SOCKET']
    s.sendto(b'READY=1', '\\0'+address[1:] if address.startswith('@') else address)
while True:
    signal.pause()
""",encoding='utf-8')
        dependencies = {
            certificate.GATE: (certificate.SOCKET,'mail-client-cert-issuer.service'),
            'mail-client-cert-owner.service': (certificate.GATE,'mail-client-cert-issuer.service',
                'mail-client-cert-verifier.service','mail-client-cert-lifecycle.service'),
            certificate.TARGET: (certificate.SOCKET,'mail-client-cert-owner.service'),
        }
        for unit in names:
            label = self.names[unit]
            content = '[Unit]\nDescription=Disposable certificate update test\n'
            if unit in dependencies:
                requires = ' '.join(self.names[dep] for dep in dependencies[unit])
                content += 'Requires='+requires+'\nAfter='+requires+'\n'
            if unit==certificate.TARGET:
                pass
            elif unit==certificate.TIMER:
                content += '[Timer]\nOnActiveSec=1h\nUnit='+self.names[certificate.HEALTH]+'\n'
            elif unit==certificate.SOCKET:
                content += '[Socket]\nListenStream='+str(work/'gate.sock')+'\nService='+self.names[certificate.GATE]+'\n'
            elif unit==certificate.HEALTH:
                content += '[Service]\nType=oneshot\nPrivateNetwork=yes\nExecStart=/usr/bin/true\n'
            else:
                actor = unit.removeprefix('mail-client-cert-').removesuffix('.service')
                content += ('[Service]\nType=notify\nPrivateNetwork=yes\nTimeoutStartSec=10s\n'
                            f'ExecStart={sys.executable} -I -S -B "{startup}" "{BOOT.parent}" "{root}" {actor}\n')
            file = Path('/run/systemd/system')/label
            with file.open('x',encoding='utf-8') as stream:
                self.files.append(file)
                stream.write(content)
        self.command('daemon-reload')
        self.command('start',self.names[certificate.TARGET],self.names[certificate.TIMER])

    @staticmethod
    def command(*args):
        result = subprocess.run(['/usr/bin/systemctl',*args],capture_output=True,timeout=45)
        if result.returncode:
            raise AssertionError(result.stderr.decode(errors='replace'))
        return result.stdout

    def run(self, label, argv, **kwargs):
        return self.command(*(self.names.get(arg,arg) for arg in argv[1:]))

    def clean(self):
        try:
            if self.files:
                self.command('stop',*(f.name for f in self.files))
        finally:
            for file in self.files:
                file.unlink(missing_ok=True)
            if self.files:
                self.command('daemon-reload')


class Services:
    """Test the transaction's lifecycle against a fresh process on each start."""
    def __init__(self, root):
        self.root = root
        self.active = set((*certificate.STOP,certificate.TIMER,certificate.TARGET))
        self.pids = dict.fromkeys(self.active,1200)
        self.events = []
        self.alternate_view = ''

    def startup(self, name, success=True):
        actor = name.removeprefix('mail-client-cert-').removesuffix('.service')
        result = subprocess.run([sys.executable,'-I','-S','-B','-c',CHECK_STARTUP,
                                 str(BOOT.parent),str(self.root),actor],capture_output=True,text=True,timeout=10)
        if success:
            if (result.returncode,result.stdout.strip()) != (0,'STARTUP_PINS_VERIFIED'):
                raise AssertionError(result.stderr)
        else:
            if result.returncode==0 or 'startup_manifest_pin' not in result.stderr:
                raise AssertionError(result)
        return result

    def run(self, label, argv, **kwargs):
        verb = argv[1]
        if verb=='show' and '--value' in argv:
            return self.alternate_view.encode()
        name = argv[2] if verb=='show' else argv[-1]
        if verb=='show':
            active = name in self.active
            sub = 'waiting' if name.endswith('.timer') else 'running'
            return (f"ActiveState={'active' if active else 'inactive'}\n"
                    f"SubState={sub if active else 'dead'}\n"
                    f'MainPID={self.pids.get(name,0) if active else 0}\nJob=\n').encode()
        if verb=='stop':
            self.active.discard(name)
            if name==certificate.SOCKET:
                self.active.discard(certificate.GATE)
        elif verb=='start':
            if name.endswith('.service'):
                self.startup(name)
                self.pids[name] = self.pids.get(name,1200)+1
            self.active.add(name)
        elif verb=='is-active' and name not in self.active:
            raise ValueError('test_service_not_active')
        self.events.append((verb,name))
        return b''


@unittest.skipUnless(sys.platform=='linux' and os.geteuid()==0, 'Linux root fixture')
class CertificateTransaction(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.work = Path(self.stack.enter_context(TemporaryDirectory(prefix='mail-cert-update-',dir='/run')))
        self.root = self.work/'host'
        self.root.mkdir(mode=0o755)
        self.tx = self.work/'transaction'
        self.tx.mkdir(mode=0o700)
        self.payload = self.work/'release/payload'
        self.payload.mkdir(parents=True)
        self.services = Services(self.root)
        self.old = b"policy = 'old'\n"
        self.new = b"policy = 'new'\n"
        wheel = (SOURCE/WHEEL).read_bytes()
        manifest = {'pins':{WHEEL:sha(wheel),'test-policy.py':sha(self.old)},'wheel':WHEEL,
                    **dict.fromkeys(('guard_pin','python_pin','openssl_pin','php_pin'),'0'*64)}
        self.old_manifest = canonical(manifest)
        self.put(self.root,certificate.MANIFEST,self.old_manifest)
        self.put(self.root,POLICY,self.old)
        self.put(self.root,certificate.RUNTIME+WHEEL,wheel)
        self.put(self.payload,certificate.MANIFEST,self.old_manifest)
        self.put(self.payload,POLICY,self.new)
        self.put(self.payload,certificate.RUNTIME+WHEEL,wheel)
        self.site_configs = {}
        for name,actor in certificate.CONFIGS.items():
            cfg = {'version':1,'profile':'production','actor':actor,'release':certificate.RUNTIME.rstrip('/'),
                   'manifest_sha256':sha(self.old_manifest),'site_fixture':{'value': 'preserve'}}
            raw = json.dumps(cfg,indent=1).encode()
            self.put(self.root,name,raw,0o640)
            os.chown(self.root/name.lstrip('/'),0,1234)
            self.site_configs[name]=regular(self.root/name.lstrip('/'))
        names = (*certificate.STOP,certificate.TIMER,certificate.TARGET)
        for name in names:
            self.put(self.root,'/etc/systemd/system/'+name,name.encode())
            self.put(self.payload,'/blueprint/systemd/'+name,name.encode())
        self.receipt = '/var/lib/mail-platform-update/installed-code.json'
        installed = {'format':2,'version':'0.4.19','identities':{},'site':{},'blueprints':{},'schemas':{},
            'unit_files':{name:regular(self.root/'etc/systemd/system'/name)[1] for name in names},
            'code':{name:regular(self.root/name.lstrip('/'))[1] for name in
                    (POLICY,certificate.MANIFEST,certificate.RUNTIME+WHEEL)}}
        self.put(self.root,self.receipt,canonical(installed),0o600)
        self.put(self.payload,'/blueprint/update-contract.json',canonical({
            'format':1,'from_version':'0.4.19','to_version':'0.4.20','stop':[],'start':[],
            'pause':[certificate.TIMER],'reload':[],'health':[certificate.GATE]}))
        self.put(self.payload.parent,'/bundle.json',canonical({'version':'0.4.20'}))
        self.put(self.payload,'/'+adaptive_update.DESCRIPTOR,canonical(adaptive_update.CONTRACT))
        # The fixture has no mail stack, site bindings, DKIM, or external ports.
        for module, replacements in (
            (code_update,{'bind_site':lambda f,s:f,'bind_identities':lambda f,*a:(f,{}),
                          'bind_profile':lambda f,**k:f,'baseline_identities':lambda p:{},
                          'render_roundcube_core':lambda *a:{},'rebase':lambda f,b:f}),
            (monitor_binding,{'update':lambda read:{},'RUNTIME':POLICY}),
            (dkim_readiness,{'update_apply':lambda engine:None,'update_rollback':lambda engine:None}),
            (certificate_state,{'STATE':self.root/'var/lib/mail-platform-certificates'}),
        ):
            for key,value in replacements.items():
                self.stack.enter_context(patch.object(module,key,value))

    @staticmethod
    def put(root,name,contents,mode=0o644):
        path = root/name.lstrip('/')
        path.parent.mkdir(parents=True,exist_ok=True)
        path.write_bytes(contents)
        path.chmod(mode)

    def phase(self, action):
        klass = engine_for(self.payload,{'format':1},root=self.root)
        engine = klass(self.payload,self.tx,root=self.root,commands=self.services)
        return getattr(engine,action)()

    def restart_all(self):
        for actor in certificate.ACTORS:
            self.services.startup('mail-client-cert-'+actor+'.service')

    def manifest(self):
        return (self.root/certificate.MANIFEST.lstrip('/')).read_bytes()

    def test_reproduces_manifest_only_failure_and_all_five_start_after_update(self):
        before = self.manifest()
        bad = json.loads(before)
        bad['php_pin']='f'*64
        self.put(self.root,certificate.MANIFEST,canonical(bad))
        self.assertIn(certificate.GATE,self.services.active)
        for actor in certificate.ACTORS:
            self.services.startup('mail-client-cert-'+actor+'.service',success=False)
        self.put(self.root,certificate.MANIFEST,before)
        self.restart_all()
        for action in ('plan','stage','activate','health'):
            self.phase(action)
        self.assertNotEqual(self.manifest(),before)
        self.restart_all()
        receipt = json.loads((self.root/self.receipt.lstrip('/')).read_bytes())
        self.assertEqual(receipt['code'][certificate.MANIFEST]['sha256'],sha(self.manifest()))
        self.assertTrue(set(self.site_configs).isdisjoint(receipt['code']))
        for path,(raw,attrs) in self.site_configs.items():
            current,current_attrs = regular(self.root/path.lstrip('/'))
            self.assertEqual(current,raw.replace(sha(before).encode(),sha(self.manifest()).encode()))
            self.assertEqual(current_attrs,dict(attrs,sha256=sha(current)))

    def test_interruption_after_manifest_replace_restores_all_and_starts_old_services(self):
        for action in ('plan','stage'):
            self.phase(action)
        save = Files.save_entry
        target = certificate.MANIFEST
        def interrupt(files, entry):
            if entry['path']==target and entry['phase']=='written':
                raise OSError('injected_after_rename_before_journal')
            save(files,entry)
        with patch.object(Files,'save_entry',interrupt),self.assertRaisesRegex(OSError,'injected_after_rename'):
            self.phase('activate')
        self.assertNotEqual(self.manifest(),self.old_manifest)
        self.assertTrue(all(sha(self.manifest()).encode() in (self.root/path.lstrip('/')).read_bytes()
                            for path in certificate.CONFIGS))
        self.assertFalse(set(certificate.STOP)&self.services.active)
        self.phase('rollback')
        self.assertEqual(self.manifest(),self.old_manifest)
        self.assertEqual((self.root/POLICY.lstrip('/')).read_bytes(),self.old)
        for path, expected in self.site_configs.items():
            self.assertEqual(regular(self.root/path.lstrip('/')),expected)
        self.restart_all()

    def test_old_pin_or_alternate_view_rejected_before_stop(self):
        self.services.alternate_view='/run/synthetic/enrolled:'+certificate.RUNTIME.rstrip('/')
        with self.assertRaisesRegex(ValueError,'certificate_update_active_enrollment_view'):
            self.phase('plan')
        self.services.alternate_view=''
        path = next(iter(certificate.CONFIGS))
        original,_ = self.site_configs[path]
        self.put(self.root,path,original.replace(sha(self.old_manifest).encode(),b'0'*64),0o640)
        with self.assertRaisesRegex(ValueError,'certificate_update_old_actor_pin'):
            self.phase('plan')
        self.assertEqual(self.services.events,[])

    def test_signed_timer_boundary_is_unchanged(self):
        path = self.payload/'blueprint/update-contract.json'
        signed = json.loads(path.read_bytes())
        path.write_bytes(canonical(dict(signed,pause=[])))
        with self.assertRaisesRegex(ValueError,'certificate_update_health_timer_missing_from_signed_pause'):
            self.phase('plan')
        self.assertEqual(self.services.events,[])
        path.write_bytes(canonical(signed))
        # The installed launcher already paused the timer before entering plan.
        self.services.active.remove(certificate.TIMER)
        for action in ('plan','stage','activate','health'):
            self.phase(action)
        plan = json.loads((self.tx/'code-update.json').read_bytes())
        self.assertEqual(plan['contract']['pause'],signed['pause'])
        self.assertEqual(plan['before_units'][certificate.TIMER]['ActiveState'],'inactive')
        self.assertNotIn(('start',certificate.TIMER),self.services.events)
        self.restart_all()

    def test_hybrid_static_update_and_rollback_keep_all_five_pins(self):
        self.put(self.root,'/etc/mail-platform/availability.json',canonical({
            'format':1, 'generation_root':'/var/lib/mail-platform/generations',
            'components':{'web':{'kind':'web','roots':['/opt/hypothetical-web'],
                'route':'/run/test/route','control':'/run/test/control','runtime':'/run/test/runtime',
                'unit':'mail-platform-hypothetical@.service','template':'/etc/test/fpm.conf',
                'health':{'kind':'fcgi','request':'/probe.php','reply':'ok'},'drain_seconds':1}}}),0o600)
        self.put(self.root,'/etc/systemd/system/mail-platform-hypothetical@.service',b'placeholder')
        self.put(self.root,'/etc/test/fpm.conf',b'placeholder')
        for action in ('plan','stage','activate','health'):
            self.phase(action)
        self.assertNotEqual(self.manifest(),self.old_manifest)
        self.restart_all()
        self.phase('rollback')
        self.assertEqual(self.manifest(),self.old_manifest)
        for path, expected in self.site_configs.items():
            self.assertEqual(regular(self.root/path.lstrip('/')),expected)
        self.restart_all()

    @unittest.skipUnless(os.getenv('MAIL_PLATFORM_TEST_SYSTEMD')=='1','requires disposable systemd test host')
    def test_actual_systemd_update_and_later_restart(self):
        real = SystemdServices(self.root,self.work,self.stack.callback)
        self.services = real
        before = {name:real.command('show',real.names[name],'-p','MainPID','--value')
                  for name in certificate.STOP if name.endswith('.service')}
        for phase in ('plan','stage','activate','health'):
            self.phase(phase)
        live = {name:real.command('show',real.names[name],'-p','MainPID','--value') for name in before}
        self.assertTrue(all(live[name] not in (b'0\n',before[name]) for name in before))
        real.command('stop',*(real.names[name] for name in (certificate.TARGET,*certificate.STOP)))
        real.command('start',real.names[certificate.TARGET])
        restarted = {name:real.command('show',real.names[name],'-p','MainPID','--value') for name in before}
        self.assertTrue(all(restarted[name] not in (b'0\n',live[name]) for name in before))

    @unittest.skipUnless(os.getenv('MAIL_PLATFORM_TEST_SYSTEMD')=='1','requires disposable systemd test host')
    def test_actual_systemd_restores_after_partial_actor_write(self):
        real = SystemdServices(self.root,self.work,self.stack.callback)
        self.services = real
        for phase in ('plan','stage'):
            self.phase(phase)
        write = Files.write
        target = sorted(certificate.CONFIGS)[2]

        def interrupt(files, name, *args, **kwargs):
            if name==target:
                raise OSError('injected_between_actor_configurations')
            return write(files,name,*args,**kwargs)

        with patch.object(Files,'write',interrupt),self.assertRaisesRegex(OSError,'injected_between_actor'):
            self.phase('activate')
        self.assertEqual(self.manifest(),self.old_manifest)
        self.assertEqual(sum(regular(self.root/name.lstrip('/'))!=row
                             for name,row in self.site_configs.items()),2)
        self.phase('rollback')
        for name,row in self.site_configs.items():
            self.assertEqual(regular(self.root/name.lstrip('/')),row)
        real.command('is-active','--quiet',real.names[certificate.TARGET])
        for name in certificate.STOP:
            real.command('is-active','--quiet',real.names[name])


if __name__=='__main__':
    unittest.main()
