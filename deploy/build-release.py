"""Package the generated homepage repository, excluding publishing machinery."""
import pathlib,shutil,subprocess,sys
root=pathlib.Path(__file__).resolve().parents[1];out=pathlib.Path(sys.argv[1]);out.mkdir(parents=True,exist_ok=True)
for name in subprocess.check_output(['git','-C',str(root),'ls-files','-z']).decode().split('\0'):
 if not name or name.startswith(('.git','.github/','deploy/')) or name in ('README.md','BACKLOG.md'):continue
 src=root/name
 if src.is_symlink():raise ValueError('Symlink: '+name)
 if not src.is_file():raise ValueError('Missing tracked file: '+name)
 dst=out/name;dst.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(src,dst)
(out/'_redirects').write_text('')
(out/'_headers').write_text('/*\n  X-Content-Type-Options: nosniff\n  Referrer-Policy: strict-origin-when-cross-origin\n')
assert (out/'index.html').is_file()
