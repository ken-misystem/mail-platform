"""Installed entry point. A private-repository token is read only from systemd credentials."""
import argparse,json,os,tempfile,time
from pathlib import Path
from release import ReleaseError,require,version
from updater import load,save,run_update,retire_previous
from github import RemoteFailure,latest,fetch,repo
ROOT=Path('/var/lib/mail-platform-update')

def remote_step(stage, operation, *args):
 try:
  return operation(*args)
 except (ReleaseError, ValueError, KeyError, TypeError) as error:
  kind=error.kind if isinstance(error,RemoteFailure) else 'response'
  detail={'stage':stage,'kind':kind,'at':int(time.time())}
  if isinstance(error,RemoteFailure) and error.status is not None:
   detail['http_status']=error.status
  print(json.dumps({'event':'update_source_failure',**detail}),flush=True)
  # The root-only snapshot contains the same finite fields as the journal.
  # Unique temp names allow overlapping timer and manual checks.
  with tempfile.NamedTemporaryFile(dir=ROOT,mode='w',delete=False) as f:
   tmp=Path(f.name)
   try:
    json.dump(detail,f);f.flush();os.fsync(f.fileno())
   except BaseException:
    tmp.unlink(missing_ok=True);raise
  try:os.replace(tmp,ROOT/'source-failure.json')
  finally:tmp.unlink(missing_ok=True)
  raise ReleaseError('github_request_failed' if isinstance(error,RemoteFailure) else 'github_response_invalid') from None

def clear_remote_failure():
 (ROOT/'source-failure.json').unlink(missing_ok=True)

def token_value(raw):
 require(type(raw)is bytes and len(raw)<=4096,'token_file')
 value=raw.strip()
 if not value:return None
 require(all(33<=byte<=126 for byte in value),'token_file')
 return value.decode('ascii')

def reusable_cache(available,release,cache):
 cached=available.get('cache')
 return (available.get('verified')is True and available.get('assets')==release['assets']and available.get('version')==release['tag'][1:]and isinstance(cached,str)and Path(cached).parent==Path(cache)and Path(cached).is_dir()and not Path(cached).is_symlink())

def check(apply_manual=False, *, periodic=False):
 require(os.geteuid()==0,'root_required');os.umask(0o077)
 from dkim_readiness import refresh_for_update
 refresh_for_update()
 retire_previous(ROOT)
 cfg=load('/etc/mail-platform/update-source.json');repository=repo(cfg['repository'])
 creds=os.environ.get('CREDENTIALS_DIRECTORY');token=None
 if creds and (Path(creds)/'github-token').is_file():
  with (Path(creds)/'github-token').open('rb')as stream:token=token_value(stream.read(4097))
 try:
  release=remote_step('lookup',latest,repository,token)
 except (ReleaseError,json.JSONDecodeError):
  # The marker describes this timer run's lookup only. Never emit it for apply,
  # rollback, a pending manual request, or an unresolved update transaction.
  if periodic and not apply_manual and not (ROOT/'manual-request.json').exists():
   prior=load(ROOT/'transaction.json')
   if prior is None or prior.get('phase') in ('complete','rolled_back'):
    print('MAIL_PLATFORM_PERIODIC_LOOKUP_FAILED=1',flush=True)
  raise
 if release is None:
  clear_remote_failure()
  return {'phase':'no_release'}
 tag=release['tag'];require(tag.startswith('v'),'release_tag');version(tag[1:])
 current=load(ROOT/'installed.json',{'version':'0.0.0'})
 if version(tag[1:])<=version(current['version']):
  clear_remote_failure()
  return {'phase':'current','version':current['version']}
 cache=ROOT/'downloads';cache.mkdir(mode=0o700,exist_ok=True)
 available=load(ROOT/'available.json',{})
 cached=available.get('cache')
 reusable=reusable_cache(available,release,cache)
 settings=load(ROOT/'policy.json',{'revision':0,'mode':'manual'})
 if reusable and not apply_manual and settings['mode']=='manual':
  clear_remote_failure()
  return {'phase':'available','version':tag[1:]}
 dest=Path(cached)if reusable else remote_step('download',fetch,repository,release,cache/(tag+'-'+str(time.time_ns())),token)
 clear_remote_failure()
 metadata=json.loads((dest/'release.json').read_bytes());require(metadata['version']==tag[1:],'tag_metadata_mismatch')
 from ordinary_update import hooks_for_release
 result=run_update(ROOT,dest/'mail-platform.tar.gz',metadata,(dest/'release.sig').read_text().strip(),
                   '/etc/mail-platform/release-public.pem',manual=apply_manual,hook_factory=hooks_for_release)
 if result['phase']=='available':save(ROOT/'available.json',{'version':tag[1:],'verified':True,'manual_approval_required':True,'assets':release['assets'],'cache':str(dest),'impact':result.get('impact')})
 if result['phase']=='complete'and(ROOT/'manual-request.json').exists():
  # Preserve the accepted request instead of discarding its audit record.
  os.replace(ROOT/'manual-request.json',ROOT/('completed-request-'+str(time.time_ns())+'.json'))
 return result
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('command',choices=['check','worker','dkim-check','dkim-apply','os-reconcile']);args=p.parse_args()
 if args.command=='os-reconcile':
  from os_reconcile import main
  main();raise SystemExit(0)
 try:
  if args.command in ('dkim-check','dkim-apply'):
   require(os.geteuid()==0,'root_required');os.umask(0o077)
   from dkim_readiness import installed
   result=installed(refresh_only=args.command=='dkim-check')
  else:result=check(apply_manual=args.command=='worker'and(ROOT/'manual-request.json').exists(),
                    periodic=args.command=='worker'and os.environ.get('TRIGGER_UNIT')=='mail-platform-update.timer')
  print(json.dumps(result))
 except Exception as e:
  # Finite error names, not subprocess output, secrets, tokens or URLs.
  print(json.dumps({'phase':'failed','error':type(e).__name__,'reason':str(e)if isinstance(e,ValueError)else'operation_failed'}));raise SystemExit(1)
