#!/usr/bin/env python3
"""Package checked Hugo output with a hash manifest and translated Apache rules."""
import hashlib,json,re,sys,tarfile,io
from pathlib import Path
from rules import compile_rules
root,output=map(Path,sys.argv[1:3]);sha=sys.argv[3]
assert re.fullmatch('[0-9a-f]{40}',sha),'Expected full Git commit'
rules=compile_rules((root/'_redirects').read_text(),(root/'_headers').read_text()).encode()
files={}
for p in root.rglob('*'):
    if p.is_symlink():raise ValueError('Symlink in build')
    if p.is_file():files[p.relative_to(root).as_posix()]=p.read_bytes()
files['.htaccess']=rules
files['release.json']=(json.dumps({'commit':sha})+'\n').encode()
manifest={'commit':sha,'files':{k:hashlib.sha256(v).hexdigest() for k,v in files.items()}}
output.parent.mkdir(parents=True,exist_ok=True)
with tarfile.open(output,'w:gz') as tar:
    for name,data in {'manifest.json':json.dumps(manifest).encode(),**{'public/'+k:v for k,v in files.items()}}.items():
        info=tarfile.TarInfo(name);info.size=len(data);info.mode=0o644;tar.addfile(info,io.BytesIO(data))
print(json.dumps({'files':len(files),'commit':sha,'archive':str(output)}))
