#!/usr/bin/env python3
"""Restricted SSH upload receiver. No shell commands, extraction links or arbitrary paths."""
import fcntl,hashlib,json,os,re,sys,tarfile,tempfile
from pathlib import Path,PurePosixPath
from rules import compile_rules

def publish(root, command, stream):
    m=re.fullmatch(r'publish ([0-9]{1,12}) ([0-9a-f]{40})',command)
    if not m:raise ValueError('Only publish SERIAL COMMIT is permitted')
    os.umask(0o007)
    serial,sha=m.groups();root=Path(root);root.mkdir(parents=True,exist_ok=True)
    releases=root/'releases';releases.mkdir(exist_ok=True);releases.chmod(0o2775)
    with (root/'publish.lock').open('a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        state=json.loads((root/'state.json').read_text()) if (root/'state.json').exists() else {'serial':-1}
        if int(serial)<state['serial']:raise ValueError('Stale publication refused')
        if int(serial)==state['serial'] and sha!=state.get('commit'):raise ValueError('Serial reused for another commit')
        with tempfile.TemporaryFile() as upload:
            size=0
            while True:
                chunk=stream.read(1024*1024)
                if not chunk:break
                size+=len(chunk)
                if size>1024**3:raise ValueError('Upload too large')
                upload.write(chunk)
            upload.seek(0)
            with tarfile.open(fileobj=upload,mode='r:gz') as tar:
                members=tar.getmembers()
                if len(members)>50000 or sum(m.size for m in members)>2*1024**3:raise ValueError('Archive too large')
                data={}
                for member in members:
                    parts=PurePosixPath(member.name).parts
                    if not member.isfile() or PurePosixPath(member.name).as_posix()!=member.name or member.name.startswith('/') or '..' in parts or '\\' in member.name or member.name in data:raise ValueError('Unsafe archive member')
                    if member.name!='manifest.json' and not member.name.startswith('public/'):raise ValueError('Unexpected archive path')
                    if any(p.startswith('.') and not (p=='.htaccess' and member.name=='public/.htaccess') for p in parts):raise ValueError('Hidden files forbidden')
                    if re.search(r'\.(?:php\d*|phtml|phar|cgi|pl|py|sh)$',member.name,re.I):raise ValueError('Executable payload forbidden')
                    data[member.name]=tar.extractfile(member).read()
        manifest=json.loads(data.pop('manifest.json'))
        files={k[7:]:v for k,v in data.items()}
        if manifest['commit']!=sha or set(files)!=set(manifest['files']):raise ValueError('Manifest mismatch')
        for name,body in files.items():
            if hashlib.sha256(body).hexdigest()!=manifest['files'][name]:raise ValueError('Checksum mismatch')
        expected=compile_rules(files['_redirects'].decode(),files['_headers'].decode()).encode()
        if files['.htaccess']!=expected:raise ValueError('Apache rules differ from approved translation')
        if 'index.html' not in files:raise ValueError('Homepage missing')
        name=serial+'-'+sha;release=releases/name
        if not release.exists():
            stage=Path(tempfile.mkdtemp(prefix='.incoming-',dir=root))
            for path,body in files.items():
                dest=stage/path;dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes(body);dest.chmod(0o664)
            for directory in stage.rglob('*'):
                if directory.is_dir():directory.chmod(0o2775)
            stage.chmod(0o2775);os.rename(stage,release)
        else:
            for path,body in files.items():
                if not (release/path).is_file() or (release/path).read_bytes()!=body:raise ValueError('Existing release differs')
        previous=os.readlink(root/'current') if (root/'current').is_symlink() else None
        link=root/'next';link.unlink(missing_ok=True);link.symlink_to('releases/'+name);os.replace(link,root/'current')
        state={'serial':int(serial),'commit':sha,'current':'releases/'+name,'previous':previous}
        pending=root/'state.next';pending.write_text(json.dumps(state));os.replace(pending,root/'state.json')
        print(json.dumps(state))

if __name__=='__main__':publish(sys.argv[1],os.environ.get('SSH_ORIGINAL_COMMAND',''),sys.stdin.buffer)
