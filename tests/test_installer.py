import hashlib
import os
import pathlib
import subprocess
import tempfile
import unittest

PROJECT=pathlib.Path(__file__).resolve().parents[1]
class InstallerTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.base=pathlib.Path(self.tmp.name)
        script=(PROJECT/'install.sh').read_text()
        script=script.replace('[[ $EUID -eq 0 ]]','[[ 1 -eq 1 ]]')
        script=script.replace('[[ -d /run/systemd/system ]]','[[ 1 -eq 1 ]]')
        self.script=self.base/'install.sh'; self.script.write_text(script)
        self.manager=self.base/'payload.sh'
        self.manager.write_text('#!/usr/bin/env bash\nprintf "installed:%s\\n" "$*"\n')
        self.manifest=self.base/'manifest'
        self.manifest.write_text(hashlib.sha256(self.manager.read_bytes()).hexdigest()+'  gre-fou-manager.sh\n')
        self.commands=self.base/'bin'; self.commands.mkdir()
        curl=self.commands/'curl'
        curl.write_text('''#!/usr/bin/env python3
import os,pathlib,shutil,sys
args=sys.argv[1:]
url=next(x for x in args if x.startswith('https://'))
with open(os.environ['URL_LOG'],'a') as f: f.write(url+'\\n')
if os.environ.get('FAIL_DOWNLOAD'): sys.exit(22)
source=os.environ['MANIFEST'] if url.endswith('/checksums.sha256') else os.environ['MANAGER']
shutil.copyfile(source,args[args.index('-o')+1])
'''); curl.chmod(0o755)
        self.env=dict(os.environ,PATH=str(self.commands)+os.pathsep+os.environ['PATH'],
                      MANAGER=str(self.manager),MANIFEST=str(self.manifest),URL_LOG=str(self.base/'urls'))
    def execute(self,*args):
        return subprocess.run(['bash',str(self.script),*args],capture_output=True,text=True,env=self.env,timeout=10)
    def test_installs_verified_payload_and_forwards_flags(self):
        p=self.execute('--no-deps','--ref','abc123')
        self.assertEqual(p.returncode,0,p.stderr)
        self.assertIn('installed:install --no-deps',p.stdout)
        self.assertIn('/abc123/gre-fou-manager.sh',(self.base/'urls').read_text())
    def test_checksum_mismatch_never_executes_payload(self):
        self.manifest.write_text('0'*64+'  gre-fou-manager.sh\n')
        p=self.execute('--no-deps')
        self.assertNotEqual(p.returncode,0)
        self.assertNotIn('installed:',p.stdout)
    def test_manifest_cannot_reference_another_file(self):
        self.manifest.write_text('0'*64+'  /etc/passwd\n')
        p=self.execute('--no-deps')
        self.assertNotEqual(p.returncode,0)
        self.assertIn('Invalid checksum manifest',p.stderr)
        self.assertNotIn('installed:',p.stdout)
    def test_download_failure_never_executes_payload(self):
        self.env['FAIL_DOWNLOAD']='1'
        p=self.execute('--no-deps')
        self.assertNotEqual(p.returncode,0)
        self.assertNotIn('installed:',p.stdout)
    def test_bad_refs_and_missing_args_rejected(self):
        for args in [('--ref','../../etc'),('--ref','x;id'),('--ref',),('--bad',)]:
            with self.subTest(args=args): self.assertEqual(self.execute(*args).returncode,2)
    def test_help_does_not_require_root_or_systemd(self):
        p=subprocess.run(['bash',str(PROJECT/'install.sh'),'--help'],capture_output=True,text=True)
        self.assertEqual(p.returncode,0)
        self.assertIn('--no-deps',p.stdout)
if __name__=='__main__': unittest.main()
