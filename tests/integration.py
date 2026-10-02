"""Root-only isolated kernel test. Never changes the host's firewall or addresses."""
import os
import pathlib
import select
import subprocess
import tempfile
import types

HERE=pathlib.Path(__file__).resolve().parent
SCRIPT=HERE.parent/'gre-fou-manager.sh'
code=SCRIPT.read_text().split("<<'PY'\n",1)[1].rsplit('\nPY\n',1)[0]
m=types.ModuleType('manager')
exec(compile(code,str(SCRIPT),'exec'),m.__dict__)
host_run=m.run

def main():
    if os.geteuid()!=0:
        raise RuntimeError('Run with sudo bash tests/integration.sh')
    for module in ('fou','ip_gre'):
        host_run('modprobe',module)
    prefix='gft'+str(os.getpid())
    namespaces={x:prefix+x for x in ('a','b','c')}
    created=[]; started=[]; server=None
    with tempfile.TemporaryDirectory(prefix='gre-fou-integration-') as tmp:
        base=pathlib.Path(tmp)
        def nsrun(label,*args,**kwargs):
            return host_run('ip','netns','exec',namespaces[label],*args,**kwargs)
        def select_endpoint(label):
            m.BASE=base/label
            m.run=lambda *args,**kwargs: nsrun(label,*args,**kwargs)
        def link(left,right,nleft,nright):
            host_run('ip','link','add',left,'type','veth','peer','name',right)
            try:
                host_run('ip','link','set',left,'netns',namespaces[nleft])
                host_run('ip','link','set',right,'netns',namespaces[nright])
            except Exception:
                host_run('ip','link','del',left,check=False)
                host_run('ip','link','del',right,check=False)
                raise
        c=dict(name='ir1fr1',local='192.0.2.1',remote='192.0.2.2',local_port=5555,
               remote_port=5556,local_inner='10.240.0.1',remote_inner='10.240.0.2',key=12345,mtu=1380,forwards=[])
        c=m.add_forward(c,'tcp','18080')
        c=m.add_forward(c,'udp','18081')
        peer=m.reverse(c)
        try:
            for label,namespace in namespaces.items():
                host_run('ip','netns','add',namespace); created.append(namespace)
                nsrun(label,'ip','link','set','lo','up')
            # All veth names are unique on the host and short enough for IFNAMSIZ.
            ab='va'+str(os.getpid()); ba='vb'+str(os.getpid())
            ac='vc'+str(os.getpid()); ca='vd'+str(os.getpid())
            link(ab,ba,'a','b'); link(ac,ca,'a','c')
            for label,dev,addr in [('a',ab,'192.0.2.1/24'),('b',ba,'192.0.2.2/24'),
                                   ('a',ac,'198.51.100.1/24'),('c',ca,'198.51.100.2/24')]:
                nsrun(label,'ip','addr','add',addr,'dev',dev)
                nsrun(label,'ip','link','set',dev,'up')
            nsrun('c','ip','route','add','192.0.2.0/24','via','198.51.100.1')
            for label,config in [('a',c),('b',peer)]:
                select_endpoint(label); m.save(config); m.up(config); started.append((label,config))
            nsrun('a','ping','-n','-I','gfir1fr1','-c','2','-W','2','10.240.0.2')
            echo_code=r'''
import socket,threading

def tcp():
    with socket.socket() as s:
        s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        s.bind(('10.240.0.2',18080)); s.listen(1); s.settimeout(15)
        ready_tcp.set()
        conn,addr=s.accept()
        with conn:
            conn.settimeout(5)
            assert addr[0]=='10.240.0.1',addr
            data=conn.recv(128); assert data==b'tcp-ok',data
            conn.sendall(data)

def udp():
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as s:
        s.bind(('10.240.0.2',18081)); s.settimeout(15)
        ready_udp.set()
        data,addr=s.recvfrom(128); assert addr[0]=='10.240.0.1',addr
        assert data==b'udp-ok',data; s.sendto(data,addr)
ready_tcp=threading.Event(); ready_udp=threading.Event()
t=threading.Thread(target=tcp); u=threading.Thread(target=udp)
t.start(); u.start()
assert ready_tcp.wait(5) and ready_udp.wait(5)
print('READY',flush=True)
t.join(); u.join()
'''
            server=subprocess.Popen(['ip','netns','exec',namespaces['b'],'python3','-u','-c',echo_code],
                                    text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            if not select.select([server.stdout],[],[],10)[0] or server.stdout.readline().strip()!='READY':
                raise RuntimeError('Echo services did not become ready')
            client_code=r'''
import socket
with socket.create_connection(('192.0.2.1',18080),timeout=5) as s:
    s.sendall(b'tcp-ok'); assert s.recv(128)==b'tcp-ok'
with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as s:
    s.settimeout(5); s.sendto(b'udp-ok',('192.0.2.1',18081))
    assert s.recvfrom(128)[0]==b'udp-ok'
print('TCP and UDP forwarding passed')
'''
            print(nsrun('c','python3','-c',client_code).stdout.strip())
            out,err=server.communicate(timeout=20)
            if server.returncode or err.strip(): raise RuntimeError('Echo server failed: '+err)
            for label,config in reversed(started):
                select_endpoint(label); m.down(config)
                assert nsrun(label,'ip','link','show','dev',m.iface(config),check=False).returncode!=0
                assert nsrun(label,'nft','list','table','ip',m.table(config),check=False).returncode!=0
                assert 'port '+str(config['local_port'])+' ' not in nsrun(label,'ip','fou','show').stdout
            started.clear()
            print('PASS: GRE/FOU ping, TCP/UDP forwarding, SNAT and cleanup')
        finally:
            if server is not None and server.poll() is None:
                server.terminate()
                try: server.communicate(timeout=5)
                except subprocess.TimeoutExpired: server.kill(); server.communicate()
            for label,config in reversed(started):
                try: select_endpoint(label); m.down(config)
                except Exception as exc: print('Cleanup error:',exc)
            for namespace in reversed(created):
                host_run('ip','netns','del',namespace,check=False)

if __name__=='__main__':
    main()
