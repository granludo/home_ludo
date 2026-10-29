import hashlib,io,json,os,subprocess,sys,tarfile,tempfile,unittest
from pathlib import Path
from receive import publish
from rules import compile_rules

def archive(sha,extra=None,corrupt=False):
    files={'index.html':b'<h1>Test</h1>','_redirects':b'/feed /feed/index.xml 200\n','_headers':b'/*\n  X-Robots-Tag: noindex\n','feed/index.xml':b'<rss/>'}
    files['.htaccess']=compile_rules(files['_redirects'].decode(),files['_headers'].decode()).encode()
    files.update(extra or {})
    manifest={'commit':sha,'files':{k:hashlib.sha256(v).hexdigest() for k,v in files.items()}}
    if corrupt:files['index.html']=b'corrupted'
    buf=io.BytesIO()
    with tarfile.open(fileobj=buf,mode='w:gz') as tar:
        for name,data in {'manifest.json':json.dumps(manifest).encode(),**{'public/'+k:v for k,v in files.items()}}.items():
            info=tarfile.TarInfo(name);info.size=len(data);tar.addfile(info,io.BytesIO(data))
    buf.seek(0);return buf

class DeploymentTests(unittest.TestCase):
    def setUp(self):self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name);self.sha='a'*40
    def tearDown(self):self.temp.cleanup()
    def test_publish_rollback_and_stale(self):
        publish(self.root,'publish 1 '+self.sha,archive(self.sha))
        before=os.readlink(self.root/'current')
        publish(self.root,'publish 2 '+'b'*40,archive('b'*40))
        subprocess.run([sys.executable,str(Path(__file__).with_name('rollback.py')),str(self.root)],check=True,capture_output=True)
        self.assertEqual(os.readlink(self.root/'current'),before)
        with self.assertRaises(ValueError):publish(self.root,'publish 1 '+self.sha,archive(self.sha))
    def test_shared_group_permissions(self):
        publish(self.root,'publish 1 '+self.sha,archive(self.sha))
        for name in ['releases','current','current/feed']:
            self.assertEqual((self.root/name).stat().st_mode & 0o777,0o775)
            if sys.platform.startswith('linux'):
                self.assertTrue((self.root/name).stat().st_mode & 0o2000)
        self.assertEqual((self.root/'current/index.html').stat().st_mode & 0o777,0o664)
        self.assertEqual((self.root/'state.json').stat().st_mode & 0o777,0o660)
    def test_failed_upload_preserves_current(self):
        publish(self.root,'publish 1 '+self.sha,archive(self.sha));before=os.readlink(self.root/'current')
        with self.assertRaises(ValueError):publish(self.root,'publish 2 '+self.sha,archive(self.sha,corrupt=True))
        self.assertEqual(os.readlink(self.root/'current'),before)
    def test_traversal(self):
        with self.assertRaises(ValueError):publish(self.root,'publish 1 '+self.sha,archive(self.sha,{'../escape':b'no'}))
        self.assertFalse((self.root.parent/'escape').exists())
    def test_executable(self):
        with self.assertRaises(ValueError):publish(self.root,'publish 1 '+self.sha,archive(self.sha,{'a.php':b'<?php'}))
    def test_arbitrary_apache(self):
        with self.assertRaises(ValueError):publish(self.root,'publish 1 '+self.sha,archive(self.sha,{'.htaccess':b'SetHandler application/x-httpd-php'}))
    def test_shell_command(self):
        with self.assertRaises(ValueError):publish(self.root,'sh -c id',archive(self.sha))
    def test_unknown_rules(self):
        with self.assertRaises(ValueError):compile_rules('/foo https://example.com 200','')
        with self.assertRaises(ValueError):compile_rules('/foo /bar 404','')
    def test_legacy_literal_source(self):
        rule=compile_rules('/old/Tomàs%20Marc;s:8:explicit; https://example.com/a.mp3 302','')
        self.assertIn('Tomàs',rule)
        self.assertNotIn('%20',rule)
        self.assertIn(';s:8:explicit;',rule)
        with self.assertRaises(ValueError):compile_rules('/old/:slug /target 302','')
    def test_redirect_query_preserved(self):
        rule=compile_rules('/shop/ https://example.com/?ref=x%20 302','')
        self.assertIn(r'https://example.com/?ref=x\%20',rule)

if __name__=='__main__':unittest.main()
