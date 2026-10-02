import unittest, tempfile, pathlib, json, copy, types, unittest.mock as mock, subprocess
SCRIPT=pathlib.Path(__file__).resolve().parents[1]/'gre-fou-manager.sh'
code=SCRIPT.read_text().split("<<'PY'\n",1)[1].rsplit('\nPY\n',1)[0]
m=types.ModuleType('manager'); exec(compile(code,str(SCRIPT),'exec'),m.__dict__)
C=dict(name='ir1fr1',local='192.0.2.1',remote='198.51.100.2',local_port=5555,remote_port=6666,local_inner='10.240.0.5',remote_inner='10.240.0.6',key=12345,mtu=1380,forwards=[])
def ok(stdout='',stderr='',returncode=0): return subprocess.CompletedProcess([],returncode,stdout,stderr)
class Tests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
  self.base=mock.patch.object(m,'BASE',pathlib.Path(self.tmp.name)/'config'); self.base.start(); self.addCleanup(self.base.stop)
 def test_link_reverses_every_pair_and_omits_local_forwards(self):
  c=m.add_forward(C,'both','2082,2053,3000-3002'); r=m.decode(m.encode(c))
  self.assertEqual(r['local'],C['remote']); self.assertEqual(r['remote'],C['local'])
  self.assertEqual(r['local_port'],6666); self.assertEqual(r['remote_port'],5555)
  self.assertEqual(r['local_inner'],C['remote_inner']); self.assertEqual(r['key'],12345)
  self.assertEqual(r['forwards'],[]); self.assertEqual(m.reverse(r),C)
 def test_rejects_untrusted_names_and_link_fields(self):
  for name in ['x;reboot','../../x','a$(id)','A','a b','1x','a'*12]:
   with self.subTest(name=name), self.assertRaises(ValueError): m.validate(dict(C,name=name))
  for text in ['grefou://1.@@@','other://1.e30','grefou://1.'+'A'*10001]:
   with self.assertRaises(ValueError): m.decode(text)
  with self.assertRaises(ValueError): m.validate(dict(C,command='id'))
 def test_private_pair_validation(self):
  for values in [dict(remote_inner='10.240.0.10'),dict(local_inner='10.240.0.4'),dict(remote_inner='10.240.0.7'),dict(remote_inner=C['local_inner']),dict(local_inner='8.8.8.1',remote_inner='8.8.8.2')]:
   with self.subTest(values=values), self.assertRaises(ValueError): m.validate(dict(C,**values))
 def test_strict_numeric_and_addresses(self):
  for field,value in [('key',True),('mtu',1401),('local_port',1023),('local','192.0.2.1;id'),('remote','127.0.0.1')]:
   with self.subTest(field=field), self.assertRaises(ValueError): m.validate(dict(C,**{field:value}))
 def test_ranges_and_translation(self):
  self.assertEqual(m.ports('80,82-84,80'),[80,82,83,84])
  self.assertEqual(len(m.add_forward(C,'both','3000-3002')['forwards']),6)
  self.assertEqual(m.add_forward(C,'tcp','443',8443)['forwards'][0]['target'],8443)
  for ports in ['0','65536','5-1','1-10000','1;id']:
   with self.assertRaises(ValueError): m.ports(ports)
  with self.assertRaises(ValueError): m.add_forward(C,'tcp','80,81',90)
 def test_conflict_for_duplicate_endpoint_port_subnet(self):
  other=dict(C,name='other',local_inner='10.240.0.9',remote_inner='10.240.0.10',key=678)
  with self.assertRaises(ValueError): m.conflicts(C,[other])
  other['local_port']=5556; m.conflicts(C,[other])
  with self.assertRaises(ValueError): m.conflicts(dict(C,local_inner=other['local_inner'],remote_inner=other['remote_inner']),[other])
 def test_forward_collision_tcp_udp_separate(self):
  a=m.add_forward(C,'tcp','2082')
  b=m.add_forward(dict(C,name='other',local_port=5556,key=678,local_inner='10.240.0.9',remote_inner='10.240.0.10'),'udp','2082')
  m.conflicts(a,[b]); b['forwards'][0]['proto']='tcp'
  with self.assertRaises(ValueError): m.conflicts(a,[b])
 def test_fou_forward_cross_collision(self):
  with self.assertRaises(ValueError): m.add_forward(C,'udp','5555')
  b=dict(C,name='other',local_port=5556,key=678,local_inner='10.240.0.9',remote_inner='10.240.0.10')
  with self.assertRaises(ValueError): m.conflicts(m.add_forward(C,'udp','5556'),[b])
  with self.assertRaises(ValueError): m.conflicts(C,[m.add_forward(b,'udp','5555')])
 def test_json_permissions_and_backup_does_not_overwrite(self):
  m.save(C); self.assertEqual(m.load(C['name']),C)
  self.assertEqual(m.path(C['name']).stat().st_mode & 0o777,0o600)
  dest=pathlib.Path(self.tmp.name)/'backup.json'; m.backup(dest)
  self.assertEqual(json.loads(dest.read_text())['tunnels'],[C])
  with self.assertRaises(ValueError): m.backup(dest)
 def test_restore_validates_all_before_writing(self):
  dest=pathlib.Path(self.tmp.name)/'restore.json'
  dest.write_text(json.dumps(dict(version=1,tunnels=[C,dict(C,name='second')])))
  with mock.patch.object(m,'local_check'),self.assertRaises(ValueError): m.restore(dest)
  self.assertEqual(m.configs(),[])
 def test_nft_rules_constrain_destination_and_snat(self):
  txt=m.nft_text(m.add_forward(C,'both','2082'))
  self.assertIn('dnat to 10.240.0.6:2082',txt)
  self.assertIn('ct status dnat counter snat to 10.240.0.5',txt)
  self.assertIn('udp dport 5555 ip saddr != 198.51.100.2 counter drop',txt)
  self.assertIn('maxseg size set 1340',txt)
  self.assertNotIn('flush ruleset',txt)
  self.assertTrue(m.nft_text(C,True).startswith('delete table ip gfm_ir1fr1\n'))
 def test_failed_link_add_rolls_back_only_receiver(self):
  calls=[]
  def runner(*a,**kw):
   calls.append(a)
   if a[:4]==('ip','link','show','dev'): return ok(returncode=1)
   if a[:3]==('ip','link','add'): raise RuntimeError('kernel failed')
   return ok()
  with mock.patch.object(m,'local_check'),mock.patch.object(m,'run',side_effect=runner),mock.patch.object(m,'cleanup') as cleanup:
   with self.assertRaises(RuntimeError): m.up(C)
   cleanup.assert_called_once_with(C,False,True)
 def test_existing_receiver_not_deleted_if_add_fails(self):
  def runner(*a,**kw):
   if a[:4]==('ip','link','show','dev'): return ok(returncode=1)
   if a[:3]==('ip','fou','add'): raise RuntimeError('occupied')
   return ok()
  with mock.patch.object(m,'local_check'),mock.patch.object(m,'run',side_effect=runner),mock.patch.object(m,'cleanup') as cleanup:
   with self.assertRaises(RuntimeError): m.up(C)
   cleanup.assert_called_once_with(C,False,False)
 def test_failed_nft_removes_created_link_and_receiver(self):
  def runner(*a,**kw):
   if a[:4]==('ip','link','show','dev'): return ok(returncode=1)
   if a[:3]==('nft','list','table'): return ok(returncode=1)
   if a[:2]==('nft','-f'): raise RuntimeError('nft rejected')
   return ok()
  with mock.patch.object(m,'local_check'),mock.patch.object(m,'run',side_effect=runner),mock.patch.object(m,'cleanup') as cleanup:
   with self.assertRaises(RuntimeError): m.up(C)
   cleanup.assert_called_once_with(C,True,True)
 def test_edit_failure_restores_config_and_restarts_old(self):
  m.save(C); new=dict(C,mtu=1300)
  with mock.patch.object(m,'local_check'),mock.patch.object(m,'run',return_value=ok()),mock.patch.object(m,'svc',side_effect=[None,RuntimeError('fail'),None]) as service:
   with self.assertRaises(RuntimeError): m.change(C,new)
   self.assertEqual(m.load(C['name']),C)
   self.assertEqual([a.args[0] for a in service.call_args_list],['stop','start','start'])
 def test_edit_prevalidation_does_not_stop_service(self):
  with mock.patch.object(m,'run') as run,self.assertRaises(ValueError): m.change(C,dict(C,mtu=1))
  run.assert_not_called()
 def test_receiver_delete_keeps_matching_endpoint_fields(self):
  args=m.receiver(C,'del')
  self.assertNotIn('ipproto',args); self.assertIn('peer_port',args); self.assertIn('6666',args)
 def test_health_does_not_restart_stopped_tunnel(self):
  m.save(C)
  with mock.patch.object(m,'run',return_value=ok(returncode=3)),mock.patch.object(m,'svc') as service: m.health(C['name'])
  service.assert_not_called()
 def test_root_required(self):
  with mock.patch.object(m.os,'geteuid',return_value=1000), self.assertRaises(ValueError): m.root()
 def test_invalid_zero_target_rejected(self):
  with self.assertRaises(ValueError): m.add_forward(C,'tcp','80',0)
 def test_shell_wrapper_preserves_interactive_stdin(self):
  local=pathlib.Path(self.tmp.name)/'manager.sh'
  text=SCRIPT.read_text().replace("BIN = '/usr/local/sbin/gre-fou'",'BIN = '+repr(str(local)))
  text=text.replace("BASE = pathlib.Path('/etc/gre-fou-manager')",'BASE = pathlib.Path('+repr(str(pathlib.Path(self.tmp.name)/'cfg'))+')')
  text=text.replace('if os.geteuid() != 0:', 'if False:')
  local.write_text(text)
  p=subprocess.run(['bash',str(local)],input='0\n',text=True,capture_output=True,timeout=10)
  self.assertEqual(p.returncode,0,p.stderr); self.assertIn('ساخت تونل',p.stdout)
  self.assertNotIn('ورودی پایان یافت',p.stdout)
 def test_wizard_updates_forward_listen_when_local_changes(self):
  c=m.add_forward(C,'tcp','2082')
  answers=iter(['192.0.2.3','','','','','','',''])
  with mock.patch('builtins.input',side_effect=lambda *a:next(answers)):
   out=m.wizard(c)
  self.assertEqual(out['forwards'][0]['listen'],'192.0.2.3')
if __name__=='__main__': unittest.main(verbosity=2)
