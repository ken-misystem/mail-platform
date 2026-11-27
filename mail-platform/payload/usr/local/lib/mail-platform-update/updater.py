"""Durable update policy and verified release lifecycle; data directories stay outside releases."""
import datetime,json,os,stat,subprocess,tempfile,time
from pathlib import Path
from release import MAX_ARCHIVE,require,version,inspect,extract_verified,sha,canonical,ReleaseError

def save(path,value):
 p=Path(path)
 fd,name=tempfile.mkstemp(prefix='.'+p.name+'.',dir=p.parent)
 tmp=Path(name)
 try:
  with os.fdopen(fd,'wb')as f:f.write(canonical(value));f.flush();os.fsync(f.fileno())
  os.replace(tmp,p);d=os.open(p.parent,os.O_RDONLY|os.O_DIRECTORY)
  try:os.fsync(d)
  finally:os.close(d)
 finally:
  tmp.unlink(missing_ok=True)
def load(p,default=None):return json.loads(Path(p).read_bytes())if Path(p).exists()else default

def policy(old,mode,expected_revision):
 require(mode in('manual','automatic'),'update_mode');require(old['revision']==expected_revision,'revision_conflict')
 return {'revision':old['revision']+1,'mode':mode}
def should_apply(settings,current,offered,manual=False):
 require(settings['mode']in('manual','automatic'),'update_mode')
 require(version(offered)>version(current),'not_newer')
 return bool(manual or settings['mode']=='automatic')


def release_cache_pins(directory):
    from host_transaction import regular
    limits = {'release.json':65536, 'release.sig':65536, 'mail-platform.tar.gz':MAX_ARCHIVE}
    return {name:sha(regular(Path(directory)/name,limit)[0]) for name,limit in limits.items()}


def reusable_release_cache(available, release, cache):
    path = available.get('cache')
    pins = available.get('cache_sha256')
    if (available.get('verified') is not True or available.get('version')!=release['tag'][1:]
            or available.get('assets')!=release['assets'] or not isinstance(path,str)
            or not isinstance(pins,dict)):
        return False
    dest = Path(path)
    if (dest.parent!=Path(cache) or dest.is_symlink() or not dest.is_dir()
            or dest.name in ('','.','..')):
        return False
    try:
        return release_cache_pins(dest)==pins
    except (OSError,ValueError):
        return False


class HookFailure(ReleaseError):
    def __init__(self, record):
        super().__init__('hook_failed_' + record['action'])
        self.record = record
        self.uncertain = record['timed_out']

def hook(stage,action,transaction):
    path = Path(stage)/'payload/installer.py'
    require(path.is_file() and not path.is_symlink(), 'installer_missing')
    directory = Path(transaction)
    sequence = len(list(directory.glob('hook-*.json'))) + 1
    prefix = 'hook-' + str(sequence).zfill(3) + '-' + action
    record = {'action': action, 'started': time.time(), 'exit': None,
              'timed_out': False, 'spawn_error': None}
    output = b''
    errors = b''
    try:
        process = subprocess.run(
            ['/usr/bin/python3', '-I', '-S', '-B', str(path), action, '--transaction', str(transaction)],
            capture_output=True, timeout=600)
        record['exit'] = process.returncode
        output = process.stdout
        errors = process.stderr
    except subprocess.TimeoutExpired as error:
        record['timed_out'] = True
        output = error.stdout or b''
        errors = error.stderr or b''
    except OSError as error:
        record['spawn_error'] = {'class': type(error).__name__, 'errno': error.errno}
    for suffix, raw in [('stdout', output), ('stderr', errors)]:
        descriptor = os.open(directory/(prefix+'.'+suffix), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        record[suffix+'_sha256'] = sha(raw)
    record['finished'] = time.time()
    save(directory/(prefix+'.json'), record)
    if record['exit'] != 0 or record['timed_out'] or record['spawn_error']:
        raise HookFailure(record)
    return record

def _release_stage_matches(root, transaction):
    offered = transaction['version']
    version(offered)
    stage = Path(transaction['release'])
    parent = root/'releases'
    return (not parent.is_symlink() and not stage.is_symlink()
            and stage in (parent/offered, parent/(offered+'-'+transaction['id'])))


def _recover_prepared(root, prior, current):
    """A sealed preparation never ran the signed installer."""
    if not prior or prior['phase']!='prepared':
        return prior
    identifier = prior.get('id')
    require(type(identifier) is str and identifier.isascii() and identifier.isdecimal()
            and len(identifier)<=30, 'prepared_transaction_id')
    directory = root/('transaction-'+identifier)
    require(prior.get('events')==[] and prior.get('old')==current
            and _release_stage_matches(root,prior) and not directory.is_symlink()
            and directory.is_dir(),
            'previous_transaction_requires_review')
    attrs = directory.stat()
    require(attrs.st_uid==os.geteuid() and stat.S_IMODE(attrs.st_mode)==0o700,
            'previous_transaction_requires_review')
    for item in directory.iterdir():
        if item.name=='journal.json':
            continue
        attrs = item.lstat()
        require((item.name=='journal.json.tmp' or item.name.startswith('.journal.json.'))
                and stat.S_ISREG(attrs.st_mode) and attrs.st_nlink==1
                and attrs.st_uid==os.geteuid() and stat.S_IMODE(attrs.st_mode)==0o600,
                'previous_transaction_requires_review')
    from host_transaction import regular
    journal = directory/'journal.json'
    raw,attrs = regular(journal)
    aborted = dict(prior,phase='abandoned_before_hook')
    require(attrs['uid']==os.geteuid() and attrs['mode']==0o600 and json.loads(raw) in (prior,aborted),
            'previous_transaction_requires_review')
    save(journal,aborted)
    save(root/'transaction.json',aborted)
    return aborted


def _retire_previous(root, prior, hook_fn):
    if not prior or prior['phase'] != 'complete':
        return []
    identifier = prior.get('id')
    require(type(identifier) is str and identifier.isdecimal(), 'retirement_transaction_id')
    directory = root / ('transaction-' + identifier)
    path = directory / 'generation-update.json'
    if not path.exists():
        return []
    from host_transaction import regular
    raw, attributes = regular(path)
    require(attributes['uid'] == 0 and attributes['mode'] == 384, 'retirement_record_permissions')
    generation = json.loads(raw)
    if not generation.get('retirement_pending'):
        return []
    stage = Path(prior['release'])
    require(_release_stage_matches(root,prior),'retirement_release_scope')
    raw, attributes = regular(stage / 'payload/installer.py')
    require(attributes['uid'] == 0 and (not attributes['mode'] & 18) and (sha(raw) == prior.get('installer_sha256')), 'retirement_hook_changed')
    hook_fn(stage, 'retire', directory)
    return load(path).get('retirement_pending', [])


class UpdateBusy(ReleaseError):
    """The transaction never started because another process holds update.lock."""
    def __init__(self, lock):
        super().__init__('update_busy')
        self.owner = 'unknown'
        info = os.fstat(lock.fileno())
        device = (os.major(info.st_dev), os.minor(info.st_dev), info.st_ino)

        def holder():
            for line in Path('/proc/locks').read_text().splitlines():
                row = line.split()
                if len(row)==8 and row[1:4]==['FLOCK','ADVISORY','WRITE']:
                    major,minor,inode = row[5].split(':')
                    if (int(major,16),int(minor,16),int(inode))==device:
                        return int(row[4])

        try:
            pid = holder()
            if pid and '0::/system.slice/mail-platform-os-reconcile.service' in (
                    Path('/proc')/str(pid)/'cgroup').read_text().splitlines() and holder()==pid:
                self.owner = 'os_reconcile'
        except (OSError,ValueError):
            pass


def retire_previous(root, hook_fn=hook):
    import fcntl
    root = Path(root)
    with (root / 'update.lock').open('a+b') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise UpdateBusy(lock)
        pending = _retire_previous(root, load(root / 'transaction.json'), hook_fn)
    return {'retirement_pending': pending}

def run_update(root,archive,meta,signature,key,manual=False,openssl='openssl',hook_fn=hook,hook_factory=None,
               reservation=None):
 import fcntl
 root=Path(root);require(root.is_dir()and not root.is_symlink(),'state_root')
 with (root/'update.lock').open('a+b')as lock:
  try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
  except BlockingIOError:raise UpdateBusy(lock)
  current=load(root/'installed.json',{'version':'0.0.0','release':None})
  settings=load(root/'policy.json',{'revision':0,'mode':'manual'})
  prior=_recover_prepared(root,load(root/'transaction.json'),current)
  require(not prior or prior['phase']in('complete','rolled_back','abandoned_before_hook'),'previous_transaction_requires_review')
  require(not prior or prior['phase']!='rolled_back' or prior['version']!=meta['version'],'previous_release_failed_requires_review')
  m,files=inspect(archive,meta,signature,key,openssl)
  if reservation is not None:
   from manual_update_request import PENDING, bound, record
   require(manual and bound(reservation) and record(root/PENDING)==reservation
           and reservation['version']==m['version'] and reservation['release_sha256']==meta['sha256'],
           'manual_update_reserved_release_mismatch')
  from native_requirements import check as check_native_requirements
  native_status=check_native_requirements(files,root)
  require(not _retire_previous(root,prior,hook_fn),'previous_generation_retirement_pending')
  if not should_apply(settings,current['version'],m['version'],manual):
   from availability_plan import release_impact
   effect=release_impact(files)
   save(root/'available.json',{'version':m['version'],'verified':True,'manual_approval_required':True,'impact':effect});return {'phase':'available','version':m['version'],'impact':effect}
  require(m.get('install_ready')is True,'release_not_installable')
  require('payload/installer.py'in files,'installer_missing')
  if hook_factory is not None:
   hook_fn=hook_factory(root,files,hook_fn)
  releases=root/'releases';releases.mkdir(mode=0o700,exist_ok=True)
  require(not releases.is_symlink(),'release_staging_parent')
  identifier=str(time.time_ns())
  stage=releases/(m['version']+'-'+identifier)
  extract_verified(files,stage)
  tx={'id':identifier,'phase':'prepared','old':current,'version':m['version'],'release':str(stage),'events':[],
      'installer_sha256':sha(files['payload/installer.py'][0]),'native_requirements':native_status}
  if reservation is not None:
   tx.update(manual_request=reservation,archive_sha256=meta['sha256'])
  txdir=root/('transaction-'+tx['id']);txdir.mkdir(mode=0o700);save(txdir/'journal.json',tx);save(root/'transaction.json',tx)
  try:
   for action in('plan','stage','activate','health'):
    if action in ('activate','health'):check_native_requirements(files,root)
    tx['phase']=action+'_started';save(root/'transaction.json',tx);save(txdir/'journal.json',tx)
    event=hook_fn(stage,action,txdir);tx['events'].append(event);save(txdir/'journal.json',tx)
   save(root/'installed.json',{'version':m['version'],'release':str(stage),'previous':current['release']})
   tx['phase']='complete';save(root/'transaction.json',tx);save(txdir/'journal.json',tx)
  except Exception as failure:
   if hasattr(failure,'record'):tx['events'].append(failure.record)
   tx['failure']=type(failure).__name__+':'+str(failure);tx['phase']='rollback_started';save(root/'transaction.json',tx)
   try:
    require(not getattr(failure,'uncertain',False),'hook_timeout_requires_review')
    tx['events'].append(hook_fn(stage,'rollback',txdir))
    expected={'version':m['version'],'release':str(stage),'previous':current['release']}
    observed=load(root/'installed.json',current)
    require(observed in(current,expected),'installed_version_changed_during_recovery')
    if observed==expected:save(root/'installed.json',current)
    tx['phase']='rolled_back'
   except Exception as rollback:tx['phase']='held';tx['rollback_failure']=type(rollback).__name__+':'+str(rollback)
   save(root/'transaction.json',tx);save(txdir/'journal.json',tx);raise ReleaseError('update_'+tx['phase'])from failure
  return {'phase':tx['phase'],'version':m['version']}
