"""Prove the installed PHP/OpenSSL executables against an authenticated APT archive."""
from hashlib import sha256
import os
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile

from certificate_state import require, trusted


EXECUTABLES = {'php_pin': ('php8.4-cli', '/usr/bin/php8.4'), 'openssl_pin': ('openssl', '/usr/bin/openssl')}
LIMIT = 32 * 1024**2
APT = ('-o', 'APT::Get::AllowUnauthenticated=false', '-o', 'Acquire::AllowInsecureRepositories=false',
       '-o', 'Acquire::AllowDowngradeToInsecureRepositories=false', '-o', 'Acquire::Retries=0',
       '-o', 'Acquire::http::Timeout=15', '-o', 'Acquire::https::Timeout=15',
       '-o', 'Dir::Cache::pkgcache=', '-o', 'Dir::Cache::srcpkgcache=')


def command(argv, *, cwd=None, timeout=40, stdout=subprocess.PIPE):
    result = subprocess.run(argv, cwd=cwd, stdout=stdout, stderr=subprocess.PIPE, timeout=timeout,
                            env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C','DEBIAN_FRONTEND':'noninteractive'})
    if result.returncode:
        # APT may include a private mirror URL in its diagnostics.
        error = ValueError('os_native_command_failed:' + Path(argv[0]).name)
        error.diagnostic = {'exit':result.returncode,'stderr_bytes':len(result.stderr),
                            'stderr_sha256':sha256(result.stderr).hexdigest()}
        raise error
    return result.stdout


def package_identity(package):
    fields = command(['/usr/bin/dpkg-query','-W','-f=${db:Status-Status}\t${Version}\t${Architecture}',package]).decode().split('\t')
    require(len(fields)==3 and fields[0]=='installed' and re.fullmatch('[0-9A-Za-z.+:~_-]{1,90}',fields[1])
            and re.fullmatch('[a-z0-9]{1,20}',fields[2]), 'os_package_identity:'+package)
    return tuple(fields[1:])


def matching_archive_pin(rows, package, version, architecture):
    pins = set()
    for paragraph in rows.split('\n\n'):
        data = dict(line.split(': ',1) for line in paragraph.splitlines() if ': ' in line and not line[0].isspace())
        if (data.get('Package'),data.get('Version'),data.get('Architecture')) == (package,version,architecture) and 'SHA256' in data:
            require(re.fullmatch('[0-9a-f]{64}',data['SHA256']), 'os_apt_archive_hash')
            pins.add(data['SHA256'])
    require(len(pins)==1,'os_apt_archive_missing_or_ambiguous:'+package)
    return pins.pop()


def member_hash(stream, binary):
    name = binary.lstrip('/')
    with tarfile.open(fileobj=stream,mode='r:') as archive:
        matching = [item for item in archive if item.name.removeprefix('./')==name]
        require(len(matching)==1, 'os_archive_member_inventory:'+name)
        item = matching[0]
        require(item.isfile() and not item.issparse() and item.uid==0 and item.gid==0 and item.mode==0o755
                and 0<item.size<=LIMIT,'os_archive_member_metadata:'+name)
        return sha256(archive.extractfile(item).read()).hexdigest()


def prove(field, live):
    import pwd
    package,binary = EXECUTABLES[field]
    version,arch = package_identity(package)
    owner = command(['/usr/bin/dpkg-query','-S',binary]).decode().strip()
    require(owner in (package+': '+binary,package+':'+arch+': '+binary),'os_package_owner:'+package)
    verification = command(['/usr/bin/dpkg','-V',package]).decode().splitlines()
    require(not any(line.split() and line.split()[-1]==binary for line in verification),'os_dpkg_executable_integrity:'+package)
    spec = f'{package}:{arch}={version}'
    pin = matching_archive_pin(command(['/usr/bin/apt-cache',*APT,'show',spec]).decode(),package,version,arch)
    with tempfile.TemporaryDirectory(prefix='mail-platform-os-proof-') as directory:
        scratch = Path(directory)
        # Give APT's download sandbox access to this one empty directory.
        account = pwd.getpwnam('_apt')
        os.chown(scratch,account.pw_uid,account.pw_gid)
        command(['/usr/bin/apt-get',*APT,'download',spec],cwd=scratch,timeout=55)
        assets = list(scratch.iterdir())
        require(len(assets)==1 and assets[0].suffix=='.deb' and not assets[0].is_symlink(), 'os_download_inventory')
        with assets[0].open('rb') as stream:
            raw = stream.read(LIMIT+1)
        require(0<len(raw)<=LIMIT and sha256(raw).hexdigest()==pin, 'os_download_archive_mismatch:'+package)
        # Move verified bytes out of the _apt-writable tree before parsing them as root.
        with tempfile.NamedTemporaryFile(suffix='.deb') as verified:
            verified.write(raw); verified.flush()
            for key,expected in (('Package',package),('Version',version),('Architecture',arch)):
                value = command(['/usr/bin/dpkg-deb','-f',verified.name,key]).decode().strip()
                require(value==expected,'os_archive_control:'+key)
            with tempfile.TemporaryFile() as content:
                command(['/usr/bin/dpkg-deb','--fsys-tarfile',verified.name],stdout=content)
                require(content.tell()<=2*LIMIT,'os_archive_expanded_size')
                content.seek(0)
                member = member_hash(content,binary)
    _,metadata = trusted(binary,limit=LIMIT)
    require(metadata==live and metadata['gid']==0 and metadata['mode']==0o755
            and member==metadata['sha256'] and package_identity(package)==(version,arch),'os_archive_executable_mismatch:'+package)
    return {'package':package,'version':version,'architecture':arch,'archive_sha256':pin,'executable_sha256':member}
