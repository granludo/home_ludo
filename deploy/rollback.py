#!/usr/bin/env python3
"""Operator-only rollback; SSH publication keys cannot invoke this command."""
import fcntl,json,os,sys
from pathlib import Path
os.umask(0o007)
root=Path(sys.argv[1])
with (root/'publish.lock').open('a') as lock:
    fcntl.flock(lock,fcntl.LOCK_EX)
    state=json.loads((root/'state.json').read_text());target=state.get('previous')
    if not target or not (root/target).is_dir() or (root/target).resolve().parent!=(root/'releases').resolve():raise SystemExit('No valid previous release')
    before=os.readlink(root/'current')
    link=root/'rollback-next';link.unlink(missing_ok=True);link.symlink_to(target);os.replace(link,root/'current')
    state.update(current=target,previous=before)
    # Keep the highest accepted publication serial; old workflow runs stay stale.
    pending=root/'state.next';pending.write_text(json.dumps(state));os.replace(pending,root/'state.json')
    print(json.dumps(state))
