#!/usr/bin/env bash
# GRE over FOU Manager 1.0.0 — IPv4 / Linux / systemd
set -euo pipefail
if ! command -v python3 >/dev/null 2>&1; then
  echo 'Python 3 لازم است. ابتدا اجرا کنید: sudo apt-get update && sudo apt-get install -y python3' >&2
  exit 1
fi
export FOU_MANAGER_SELF="$(readlink -f -- "$0")"
exec python3 -c "$(cat <<'PY'
import argparse, base64, copy, fcntl, ipaddress, json, os, pathlib, re, secrets
import shutil, subprocess, sys, tempfile, time, contextlib
VERSION = '1.0.0'
BASE = pathlib.Path('/etc/gre-fou-manager')
BIN = '/usr/local/sbin/gre-fou'
UNITS = pathlib.Path('/etc/systemd/system')
SCHEMA = {'name','local','remote','local_port','remote_port','local_inner','remote_inner','key','mtu','forwards'}

def run(*args, check=True, data=None, timeout=180):
    p = subprocess.run([str(a) for a in args], input=data, text=True,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
    if check and p.returncode:
        raise RuntimeError(' '.join(map(str,args)) + '\n' + (p.stderr or p.stdout).strip())
    return p

def root():
    if os.geteuid() != 0: raise ValueError('با sudo یا کاربر root اجرا کنید.')

def name_ok(name):
    if not isinstance(name,str) or not re.fullmatch(r'[a-z][a-z0-9]{0,10}',name):
        raise ValueError('نام: ۱ تا ۱۱ حرف کوچک انگلیسی یا عدد؛ شروع با حرف. مثال: ir1fr1')
    return name

def iface(c): return 'gf'+c['name']
def table(c): return 'gfm_'+c['name']
def unit(name): return 'gre-fou@'+name_ok(name)+'.service'
def path(name): return BASE / (name_ok(name)+'.json')

def ip(value):
    if not isinstance(value,str): raise ValueError('IP باید متن باشد.')
    a=ipaddress.IPv4Address(value)
    if a.is_unspecified or a.is_multicast or a.is_loopback or int(a)==0xffffffff:
        raise ValueError('IP نامعتبر: '+value)
    return str(a)

def integer(v,lo,hi,label):
    if type(v) is not int or not lo<=v<=hi: raise ValueError(label+' نامعتبر است.')
    return v

def validate(c):
    if not isinstance(c,dict) or set(c)!=SCHEMA: raise ValueError('ساختار تنظیمات معتبر نیست.')
    name_ok(c['name'])
    for k in ('local','remote','local_inner','remote_inner'): ip(c[k])
    if c['local']==c['remote']: raise ValueError('IP دو سرور باید متفاوت باشد.')
    a=ipaddress.IPv4Interface(c['local_inner']+'/30')
    b=ipaddress.IPv4Interface(c['remote_inner']+'/30')
    if a.network!=b.network or a.ip==b.ip or a.ip not in list(a.network.hosts()) or b.ip not in list(a.network.hosts()):
        raise ValueError('IPهای داخلی باید دو آدرس قابل استفاده و متفاوت از یک /30 باشند.')
    private=[ipaddress.ip_network(n) for n in ('10.0.0.0/8','172.16.0.0/12','192.168.0.0/16')]
    if not any(a.ip in n for n in private) or not any(b.ip in n for n in private): raise ValueError('IP داخلی باید از رنج‌های خصوصی RFC1918 باشد.')
    for k in ('local_port','remote_port'): integer(c[k],1024,65535,k)
    integer(c['key'],1,4294967295,'GRE key')
    integer(c['mtu'],576,1400,'MTU')
    if not isinstance(c['forwards'],list) or len(c['forwards'])>4096: raise ValueError('حداکثر ۴۰۹۶ فوروارد مجاز است.')
    seen=set()
    for f in c['forwards']:
        if not isinstance(f,dict) or set(f)!={'proto','listen','port','target'}: raise ValueError('فوروارد نامعتبر است.')
        if f['proto'] not in ('tcp','udp'): raise ValueError('پروتکل باید tcp یا udp باشد.')
        if f['listen']!=c['local']: raise ValueError('IP فوروارد باید IP محلی همین تونل باشد.')
        integer(f['port'],1,65535,'Listen port'); integer(f['target'],1,65535,'Target port')
        k=(f['proto'],f['listen'],f['port'])
        if k in seen: raise ValueError('فوروارد تکراری است.')
        if f['proto']=='udp' and f['port']==c['local_port']: raise ValueError('پورت فوروارد با FOU تداخل دارد.')
        seen.add(k)
    return c

def load(name): return validate(json.loads(path(name).read_text()))
def configs():
    return [validate(json.loads(p.read_text())) for p in sorted(BASE.glob('*.json'))]

def conflicts(c, existing):
    validate(c)
    used={(f['proto'],f['listen'],f['port']) for f in c['forwards']}
    for d in existing:
        if d['name']==c['name']: continue
        if c['local_port']==d['local_port']: raise ValueError('پورت FOU در تونل '+d['name']+' استفاده شده؛ پورت جدا انتخاب کنید.')
        if ipaddress.ip_network(c['local_inner']+'/30',strict=False)==ipaddress.ip_network(d['local_inner']+'/30',strict=False):
            raise ValueError('شبکه داخلی با تونل '+d['name']+' تداخل دارد.')
        other={(f['proto'],f['listen'],f['port']) for f in d['forwards']}
        if used & other: raise ValueError('پورت فوروارد در تونل '+d['name']+' استفاده شده است.')
        if any(f['proto']=='udp' and f['port']==d['local_port'] and f['listen']==d['local'] for f in c['forwards']):
            raise ValueError('فوروارد با پورت FOU تونل دیگر تداخل دارد.')
        if any(f['proto']=='udp' and f['port']==c['local_port'] and f['listen']==c['local'] for f in d['forwards']):
            raise ValueError('پورت FOU با فوروارد تونل دیگر تداخل دارد.')
        if (c['local'],c['remote'],c['key'])==(d['local'],d['remote'],d['key']):
            raise ValueError('زوج IP و کلید GRE تکراری است.')

@contextlib.contextmanager
def lock():
    BASE.mkdir(mode=0o700,parents=True,exist_ok=True)
    with open(BASE/'.lock','a') as f:
        fcntl.flock(f,fcntl.LOCK_EX); yield

def atomic(p,text):
    p=pathlib.Path(p); p.parent.mkdir(parents=True,exist_ok=True)
    fd,tmp=tempfile.mkstemp(dir=p.parent,prefix='.tmp-')
    try:
        with os.fdopen(fd,'w') as f: f.write(text); f.flush(); os.fsync(f.fileno())
        os.chmod(tmp,0o600); os.replace(tmp,p)
    finally:
        if os.path.exists(tmp): os.unlink(tmp)

def save(c):
    with lock():
        conflicts(c,configs()); atomic(path(c['name']),json.dumps(c,indent=2)+'\n')

def reverse(c):
    c=copy.deepcopy(c)
    for a,b in [('local','remote'),('local_port','remote_port'),('local_inner','remote_inner')]: c[a],c[b]=c[b],c[a]
    c['forwards']=[]
    return validate(c)

def encode(c):
    return 'grefou://1.'+base64.urlsafe_b64encode(json.dumps(reverse(c),separators=(',',':')).encode()).decode().rstrip('=')

def decode(s):
    s=s.strip()
    if not s.startswith('grefou://1.') or len(s)>10000: raise ValueError('لینک معتبر نیست.')
    payload=s.split('.',1)[1]
    raw=base64.b64decode(payload+'='*(-len(payload)%4),altchars=b'-_',validate=True)
    return validate(json.loads(raw))

def nft_text(c,replace=False):
    t=table(c); dev=iface(c); li=c['local_inner']; ri=c['remote_inner']
    lines=[]
    if replace: lines.append('delete table ip '+t)
    lines += ['table ip '+t+' {',
      ' chain incoming { type filter hook input priority -10; policy accept;',
      f'  ip daddr {c["local"]} udp dport {c["local_port"]} ip saddr != {c["remote"]} counter drop',
      f'  ip daddr {c["local"]} ip saddr {c["remote"]} udp sport {c["remote_port"]} udp dport {c["local_port"]} counter accept',
      f'  iifname "{dev}" ip saddr != {ri} counter drop',
      f'  iifname "{dev}" ip saddr {ri} ip daddr {li} counter accept',
      ' }',
      ' chain prerouting { type nat hook prerouting priority -110; policy accept;']
    for f in c['forwards']:
        lines.append(f'  iifname != "{dev}" ip daddr {f["listen"]} {f["proto"]} dport {f["port"]} counter dnat to {ri}:{f["target"]}')
    lines += [' }',' chain postrouting { type nat hook postrouting priority 90; policy accept;',
      f'  oifname "{dev}" ip daddr {ri} ct status dnat counter snat to {li}',
      ' }',' chain forwarding { type filter hook forward priority -10; policy accept;',
      f'  iifname "{dev}" ip saddr {ri} ct state established,related counter accept',
      f'  oifname "{dev}" ip daddr {ri} ct status dnat counter accept',' }',
      ' chain mss { type filter hook forward priority -150; policy accept;',
      f'  oifname "{dev}" tcp flags & (syn | rst) == syn tcp option maxseg size > {c["mtu"]-40} tcp option maxseg size set {c["mtu"]-40}',
      ' }','}']
    return '\n'.join(lines)+'\n'

def receiver(c,verb):
    args=['ip','fou',verb,'port',str(c['local_port'])]
    if verb=='add': args+=['ipproto','47']
    args+=['local',c['local'],'peer',c['remote'],'peer_port',str(c['remote_port'])]
    return args

def local_check(c):
    data=json.loads(run('ip','-j','-4','addr','show').stdout)
    addresses={a['local'] for d in data for a in d.get('addr_info',[])}
    if c['local'] not in addresses: raise ValueError('IP محلی روی این سرور نیست. این نسخه برای IPv4 مستقیم روی سرور است؛ NAT پشتیبانی نمی‌شود.')
    route=json.loads(run('ip','-j','route','get',c['remote']).stdout)
    if not route or route[0].get('dev','').startswith('gf'): raise ValueError('مسیر IP خارج نباید از تونل مدیریت‌شده عبور کند.')
    for d in data:
        if d['ifname']==iface(c): continue
        for a in d.get('addr_info',[]):
            if ipaddress.ip_network(c['local_inner']+'/30',strict=False).overlaps(ipaddress.ip_network(a['local']+'/'+str(a['prefixlen']),strict=False)):
                raise ValueError('شبکه داخلی با یک اینترفیس موجود تداخل دارد: '+d['ifname'])

def cleanup(c,link=True,fou=True):
    # Only this tunnel's resources; never flush a host firewall.
    errors=[]
    if run('nft','list','table','ip',table(c),check=False).returncode==0:
        p=run('nft','delete','table','ip',table(c),check=False)
        if p.returncode: errors.append(p.stderr)
    if link:
        p=run('ip','link','show','dev',iface(c),check=False)
        if p.returncode==0:
            p=run('ip','link','del','dev',iface(c),check=False)
            if p.returncode: errors.append(p.stderr)
    if fou:
        p=run(*receiver(c,'del'),check=False)
        if p.returncode and not any(s in p.stderr.lower() for s in ('no such','not found','cannot find')): errors.append(p.stderr)
    if errors: raise RuntimeError('پاک‌سازی کامل نشد: '+'; '.join(errors))

def up(c):
    with lock():
        conflicts(c,configs()); local_check(c)
        # Reject unowned interfaces rather than deleting them.
        if run('ip','link','show','dev',iface(c),check=False).returncode==0:
            raise ValueError('اینترفیس موجود است؛ ابتدا سرویس را متوقف کنید: '+iface(c))
        for module in ('ip_gre','fou'): run('modprobe',module)
        created_fou=False; created_link=False
        try:
            run(*receiver(c,'add')); created_fou=True
            run('ip','link','add',iface(c),'type','gre','local',c['local'],'remote',c['remote'],
                'key',c['key'],'ttl','64','encap','fou','encap-sport',c['local_port'],
                'encap-dport',c['remote_port'],'encap-csum'); created_link=True
            run('ip','addr','add',c['local_inner']+'/30','dev',iface(c))
            run('ip','link','set','dev',iface(c),'mtu',c['mtu'],'up')
            # Disable reverse path filtering only on our tunnel; do not change global all/default.
            run('sysctl','-w',f'net.ipv4.conf.{iface(c)}.rp_filter=0')
            if c['forwards']: run('sysctl','-w','net.ipv4.ip_forward=1')
            exists=run('nft','list','table','ip',table(c),check=False).returncode==0
            run('nft','-f','-',data=nft_text(c,exists))
        except Exception as original:
            try: cleanup(c,created_link,created_fou)
            except Exception as rollback: raise RuntimeError(str(original)+'\nخطای rollback: '+str(rollback)) from original
            raise
        print('تونل بالا آمد: '+c['name'])

def down(c):
    with lock(): cleanup(c)
    print('تونل متوقف شد: '+c['name'])

def svc(action,name):
    run('systemctl',action,unit(name))

def change(old,new):
    # Prevalidate before interrupting a working tunnel.
    conflicts(new,configs()); local_check(new)
    active=run('systemctl','is-active',unit(old['name']),check=False).returncode==0
    if active: svc('stop',old['name'])
    try:
        save(new)
        if active: svc('start',new['name'])
    except Exception as original:
        save(old)
        if active:
            try: svc('start',old['name'])
            except Exception as rollback: raise RuntimeError(str(original)+'\nبازگردانی سرویس شکست خورد: '+str(rollback)) from original
        raise
    print('ذخیره شد. اگر IP، پورت، کلید، MTU یا شبکه عوض شده، سمت دیگر را نیز هماهنگ کنید.')

def install(deps=True):
    root()
    if deps:
        if shutil.which('apt-get'):
            env=os.environ.copy(); env['DEBIAN_FRONTEND']='noninteractive'; env['NEEDRESTART_MODE']='a'
            for argv in (['apt-get','update'],['apt-get','install','-y','python3','iproute2','nftables','kmod','iputils-ping']):
                subprocess.run(argv,check=True,env=env)
        elif shutil.which('dnf'):
            subprocess.run(['dnf','install','-y','python3','iproute','nftables','kmod','iputils'],check=True)
        else: raise ValueError('Ubuntu/Debian یا AlmaLinux/Rocky لازم است؛ یا install --no-deps اجرا کنید.')
    for cmd in ('ip','nft','modprobe','sysctl','systemctl','ping'):
        if not shutil.which(cmd): raise ValueError('ابزار نصب نیست: '+cmd)
    if not pathlib.Path('/run/systemd/system').exists(): raise ValueError('systemd فعال نیست؛ محیط کانتینری پشتیبانی نمی‌شود.')
    BASE.mkdir(mode=0o700,parents=True,exist_ok=True); os.chmod(BASE,0o700)
    source=pathlib.Path(os.environ['FOU_MANAGER_SELF'])
    if str(source)!=BIN:
        atomic(BIN,source.read_text()); os.chmod(BIN,0o755)
    UNITS.joinpath('gre-fou@.service').write_text('''[Unit]
Description=GRE over FOU tunnel %i
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/sbin/gre-fou up %i
ExecStop=/usr/local/sbin/gre-fou down %i
TimeoutStartSec=90
TimeoutStopSec=90

[Install]
WantedBy=multi-user.target
''')
    UNITS.joinpath('gre-fou-health@.service').write_text('''[Unit]
Description=Check GRE over FOU peer %i
After=network-online.target
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/gre-fou health %i
TimeoutStartSec=180
''')
    UNITS.joinpath('gre-fou-health@.timer').write_text('''[Unit]
Description=Periodic GRE over FOU health check %i
[Timer]
OnBootSec=90s
OnUnitActiveSec=60s
RandomizedDelaySec=10s
Unit=gre-fou-health@%i.service
[Install]
WantedBy=timers.target
''')
    run('systemctl','daemon-reload')
    print('نصب شد. برای منو: sudo gre-fou')
    print('فایروال دیتاسنتر و سیستم باید UDP پورت FOU از IP سرور مقابل را اجازه دهند.')

def prompt(text,default=None):
    s=input(text+(' ['+str(default)+']' if default is not None else '')+': ').strip()
    return s if s else (str(default) if default is not None else '')

def next_pair():
    used={str(ipaddress.ip_network(c['local_inner']+'/30',strict=False)) for c in configs()}
    for n in range(1,16384):
        net=ipaddress.ip_network((int(ipaddress.IPv4Address('10.240.0.0'))+4*n,30))
        if str(net) not in used: return str(net[1]),str(net[2])
    raise ValueError('شبکه داخلی آزاد پیدا نشد.')

def next_port():
    used={c['local_port'] for c in configs()}
    for n in range(5555,65536):
        if n not in used: return n
    raise ValueError('پورت آزاد نیست.')

def wizard(old=None):
    a,b=next_pair()
    c=copy.deepcopy(old) if old else dict(name='',local='',remote='',local_port=next_port(),remote_port=5555,
        local_inner=a,remote_inner=b,key=secrets.randbelow(4294967295)+1,mtu=1380,forwards=[])
    if not old: c['name']=prompt('نام تونل، مثل ir1fr1')
    for k,label in [('local','IP همین سرور (ایران یا خارج)'),('remote','IP سرور مقابل'),
      ('local_port','پورت UDP همین سمت'),('remote_port','پورت UDP سمت مقابل'),
      ('local_inner','IP داخلی همین سمت'),('remote_inner','IP داخلی سمت مقابل'),
      ('key','کلید GRE (شناسه است، رمز نیست)'),('mtu','MTU')]:
        v=prompt(label,c[k] or None); c[k]=int(v) if k in ('local_port','remote_port','key','mtu') else v
    for f in c['forwards']: f['listen']=c['local']
    return validate(c)

def ports(text):
    values=[]
    for s in text.split(','):
        s=s.strip()
        if re.fullmatch(r'\d+',s): values.append(int(s))
        elif re.fullmatch(r'\d+-\d+',s):
            a,b=map(int,s.split('-'))
            if a>b or b-a>4095: raise ValueError('بازه پورت نامعتبر یا بیش از حد بزرگ است.')
            values.extend(range(a,b+1))
        else: raise ValueError('نمونه پورت: 2082,2053,3000-3010')
        if len(values)>4096: raise ValueError('تعداد پورت بیش از حد است.')
    for v in values: integer(v,1,65535,'Port')
    return sorted(set(values))

def add_forward(c,proto,ps,target=None):
    if proto not in ('tcp','udp','both'): raise ValueError('پروتکل: tcp / udp / both')
    ps=ports(ps)
    if target is not None: integer(target,1,65535,'Target port')
    if target is not None and len(ps)!=1: raise ValueError('پورت مقصد متفاوت فقط برای یک پورت مجاز است.')
    out=copy.deepcopy(c)
    for p in ps:
        for pr in (('tcp','udp') if proto=='both' else (proto,)):
            out['forwards'].append(dict(proto=pr,listen=c['local'],port=p,target=target or p))
    return validate(out)

def status(name=None):
    for c in ([load(name)] if name else configs()):
        print('\n'+c['name']+' | '+c['local']+':'+str(c['local_port'])+' -> '+c['remote']+':'+str(c['remote_port']))
        p=run('systemctl','is-active',unit(c['name']),check=False)
        print('Service: '+p.stdout.strip()+' | MTU: '+str(c['mtu'])+' | Inner: '+c['local_inner']+' -> '+c['remote_inner'])
        p=run('ip','-j','-s','link','show','dev',iface(c),check=False)
        if p.returncode==0:
            data=json.loads(p.stdout)[0]; st=data.get('stats64',data.get('stats',{}))
            print('RX: %.3f GiB | TX: %.3f GiB (از زمان ساخت اینترفیس)'%(st.get('rx',{}).get('bytes',0)/2**30,st.get('tx',{}).get('bytes',0)/2**30))
        for n,f in enumerate(c['forwards'],1):
            print(f'{n}. {f["proto"]} {f["listen"]}:{f["port"]} -> {c["remote_inner"]}:{f["target"]}')
        if not c['forwards']: print('فورواردی تعریف نشده است.')
    if not configs(): print('هنوز تونلی ساخته نشده است.')

def diagnose(c):
    status(c['name'])
    for args in [('ip','fou','show'),('ip','route','get',c['remote']),('sysctl','net.ipv4.ip_forward','net.ipv4.conf.all.rp_filter'),
                 ('ping','-n','-I',iface(c),'-c','3','-W','2',c['remote_inner']),
                 ('nft','list','table','ip',table(c))]:
        p=run(*args,check=False); print('\n$ '+' '.join(args)+'\n'+p.stdout+p.stderr)
    print('active بودن سرویس به معنی دسترسی به سمت مقابل نیست؛ نتیجه ping را بررسی کنید.')
    print('سرویس مقصد باید روی 0.0.0.0 یا IP داخلی تونل گوش بدهد. فقط 127.0.0.1 یا IP عمومی کافی نیست.')
    print('قوانین allow این مدیر، DROP در UFW/firewalld یا فایروال دیتاسنتر را خنثی نمی‌کنند.')

def create(c):
    if path(c['name']).exists(): raise ValueError('نام تونل از قبل وجود دارد.')
    local_check(c); save(c)
    try: run('systemctl','enable','--now',unit(c['name']))
    except Exception:
        print('تنظیمات ذخیره شد اما شروع سرویس شکست خورد؛ diagnose و logs را بررسی کنید.',file=sys.stderr)
        raise
    print('ساخته شد: '+c['name']+'\nلینک سمت مقابل:\n'+encode(c))

def monitor(name,enabled):
    load(name)
    run('systemctl','enable' if enabled else 'disable','--now','gre-fou-health@'+name_ok(name)+'.timer')
    print('مانیتور '+('فعال' if enabled else 'غیرفعال')+' شد؛ پس از سه تست ping ناموفق، تونل ری‌استارت می‌شود.')

def health(name):
    c=load(name)
    if run('systemctl','is-active',unit(name),check=False).returncode: return
    state=pathlib.Path('/run/gre-fou-health-'+name_ok(name))
    p=run('ping','-n','-I',iface(c),'-c','1','-W','2',c['remote_inner'],check=False)
    fails=0
    if p.returncode:
        try: fails=int(state.read_text())
        except (FileNotFoundError,ValueError): pass
        fails+=1
    atomic(state,str(fails))
    if fails>=3 and run('systemctl','is-active',unit(name),check=False).returncode==0:
        print('سه تست ناموفق؛ راه‌اندازی مجدد '+name)
        svc('restart',name); atomic(state,'0')

def remove(name):
    c=load(name)
    run('systemctl','disable','--now','gre-fou-health@'+name+'.timer')
    run('systemctl','stop','gre-fou-health@'+name+'.service',check=False)
    run('systemctl','disable','--now',unit(name))
    down(c)
    with lock(): path(name).unlink()
    pathlib.Path('/run/gre-fou-health-'+name).unlink(missing_ok=True)
    run('systemctl','reset-failed',unit(name),check=False)
    print('حذف شد: '+name)

def backup(dest):
    p=pathlib.Path(dest).expanduser().resolve()
    if p.exists(): raise ValueError('فایل مقصد موجود است؛ یک نام جدید بدهید.')
    with lock(): atomic(p,json.dumps({'version':1,'tunnels':configs()},indent=2)+'\n')
    print(str(p))

def restore(src):
    doc=json.loads(pathlib.Path(src).read_text())
    if not isinstance(doc,dict) or set(doc)!={'version','tunnels'} or doc['version']!=1 or not isinstance(doc['tunnels'],list):
        raise ValueError('بکاپ نامعتبر است.')
    if len(doc['tunnels'])>256: raise ValueError('حداکثر ۲۵۶ تونل در هر بکاپ.')
    with lock():
        existing=configs(); new=[]; names={c['name'] for c in existing}
        for c in doc['tunnels']:
            validate(c)
            if c['name'] in names: raise ValueError('نام موجود یا تکراری: '+c['name'])
            conflicts(c,existing+new); local_check(c); new.append(c); names.add(c['name'])
        written=[]
        try:
            for c in new: atomic(path(c['name']),json.dumps(c,indent=2)+'\n'); written.append(path(c['name']))
        except Exception:
            for p in written: p.unlink(missing_ok=True)
            raise
    print('تنظیمات بازیابی شد؛ سرویس‌ها هنوز شروع نشده‌اند. از منو برای هر تونل Start بزنید.')

def menu():
    while True:
        print('\nGRE over FOU Manager '+VERSION+'\n1. ساخت تونل\n2. نصب از لینک سمت مقابل\n3. وضعیت همه تونل‌ها\n4. مدیریت یک تونل\n5. بکاپ\n6. بازیابی بکاپ بدون جایگزینی\n0. خروج')
        try:
            choice=prompt('شماره')
            if choice=='0': return
            if choice=='1': create(wizard())
            elif choice=='2':
                c=decode(prompt('لینک')); c['name']=prompt('نام محلی تونل',c['name']); create(validate(c))
            elif choice=='3': status()
            elif choice=='4':
                names=[c['name'] for c in configs()]
                print('تونل‌ها: '+', '.join(names)); name=prompt('نام تونل'); c=load(name)
                print('1. وضعیت\n2. شروع و فعال‌سازی بعد از ریبوت\n3. توقف و غیرفعال‌سازی بعد از ریبوت\n4. ری‌استارت\n5. ویرایش\n6. افزودن فوروارد\n7. حذف فوروارد\n8. لینک سمت مقابل\n9. تست و عیب‌یابی\n10. لاگ\n11. حذف تونل\n12. فعال‌سازی مانیتور و بازیابی خودکار\n13. غیرفعال‌سازی مانیتور')
                op=prompt('شماره')
                if op=='1': status(name)
                elif op=='2': run('systemctl','enable','--now',unit(name))
                elif op=='3': run('systemctl','disable','--now',unit(name))
                elif op=='4': svc('restart',name)
                elif op=='5':
                    new=wizard(c)
                    for f in new['forwards']: f['listen']=new['local']
                    change(c,new)
                elif op=='6':
                    print('فوروارد از همین سرور به IP داخلی سمت مقابل؛ سرویس مقصد باید روی IP داخلی یا 0.0.0.0 گوش بدهد.')
                    pr=prompt('پروتکل tcp / udp / both','both'); ps=prompt('پورت یا لیست یا بازه')
                    tp=prompt('پورت مقصد؛ خالی یعنی همان پورت')
                    change(c,add_forward(c,pr,ps,int(tp) if tp else None))
                elif op=='7':
                    status(name); n=int(prompt('شماره فوروارد'))
                    if not 1<=n<=len(c['forwards']): raise ValueError('شماره نامعتبر است.')
                    new=copy.deepcopy(c); del new['forwards'][n-1]; change(c,new)
                elif op=='8': print(encode(c))
                elif op=='9': diagnose(c)
                elif op=='10':
                    p=run('journalctl','-u',unit(name),'-n','80','--no-pager',check=False); print(p.stdout+p.stderr)
                elif op=='12': monitor(name,True)
                elif op=='13': monitor(name,False)
                elif op=='11':
                    if prompt('برای حذف، نام تونل را دوباره وارد کنید')==name: remove(name)
            elif choice=='5': backup(prompt('مسیر فایل بکاپ','/root/gre-fou-backup-'+time.strftime('%Y%m%d-%H%M%S')+'.json'))
            elif choice=='6': restore(prompt('مسیر بکاپ'))
        except (ValueError,RuntimeError,OSError,subprocess.SubprocessError) as e: print('خطا: '+str(e),file=sys.stderr)

GUIDE = """
GRE over FOU Manager 1.0.0

نصب روی هر دو سرور:
  sudo bash gre-fou-manager.sh install
باز کردن منو:
  sudo gre-fou

۱. روی ایران گزینه ساخت تونل را انتخاب کنید.
IP همین سرور یعنی IP ایران؛ IP مقابل یعنی IP خارج.
پورت‌های UDP دو طرف می‌توانند متفاوت باشند ولی باید در دو سرور هماهنگ باشند.
IP محلی باید مستقیماً روی اینترفیس سرور وجود داشته باشد؛ NAT پشتیبانی نمی‌شود.
شبکه داخلی و پورت FOU هر تونل در هر سرور باید جدا باشد.

۲. لینک چاپ‌شده را در خارج، در گزینه نصب از لینک، وارد کنید.
لینک جهت دو سرور را خودکار برعکس می‌کند. به SSH خودکار نیازی نیست.
اگر خارج قبلاً آن پورت یا شبکه داخلی را استفاده می‌کند، روی ایران ویرایش کنید
و لینک تازه بگیرید. نام محلی تونل می‌تواند در دو سرور متفاوت باشد.

۳. در ایران، مدیریت تونل، افزودن فوروارد را انتخاب کنید.
نمونه: both و سپس 2082,2053,3000-3010
برای ترجمه پورت، فقط یک پورت ورودی بدهید و سپس پورت مقصد متفاوت تعیین کنید.
در خارج سرویس مقصد باید روی 0.0.0.0 یا IP داخلی همین تونل گوش بدهد؛
سرویس محدود به 127.0.0.1 یا فقط IP عمومی از این مسیر در دسترس نیست.
روی خارج فقط ساخت تونل کافی است؛ نیازی به فوروارد مشابه در جهت عکس نیست.
اتصال کلاینت از اینترنت انجام می‌شود؛ فوروارد از خود سرور ایران با IP عمومی
در OUTPUT این نسخه پشتیبانی نمی‌شود. برای تست از یک دستگاه سوم استفاده کنید.
سمت خارج، IP مبدا اتصال فورواردشده را IP داخلی ایران می‌بیند، زیرا SNAT فعال است.

۴. برای چند خارج به یک ایران، ساخت تونل را با نام، پورت و شبکه داخلی تازه تکرار کنید.
یک IP و پورت و پروتکل ورودی فقط به یک مقصد تعلق دارد. مثلاً 2082 به خارج اول
و 2083 به خارج دوم. برای چند ایران به یک خارج هم هر زوج یک تونل جدا می‌خواهد.
برای چند ایران به چند خارج، برای هر زوج موردنیاز همین مراحل را انجام دهید.
این نسخه تونل‌های مستقل می‌سازد؛ بالانس یا تغییر مقصد خودکار بین چند خارج ندارد.

فایروال:
UDP پورت محلی FOU را فقط از IP سرور مقابل اجازه دهید.
پورت‌های ورودی فوروارد را روی ایران باز کنید.
INPUT سمت خارج باید ترافیک سرویس‌ها از اینترفیس gfNAME و IP داخلی ایران را بپذیرد.
FORWARD ایران باید جریان فوروارد و برگشت established/related آن را بپذیرد.
فایروال دیتاسنتر هم باید UDP را اجازه دهد.
مدیر فقط جدول nftables متعلق به همان تونل را تغییر می‌دهد و ruleset را پاک نمی‌کند.
قانون accept این مدیر، قانون DROP فایروال‌های دیگر را لغو نمی‌کند.
GRE key شناسه است، رمز یا احراز هویت نیست؛ این پروتکل رمزنگاری ندارد.
لینک تنظیمات هم رمزنگاری یا امضای دیجیتال ندارد. فقط لینک مورداعتماد وارد کنید.

عیب‌یابی:
  sudo gre-fou status
  sudo gre-fou diagnose ir1fr1
  sudo gre-fou logs ir1fr1
MTU پیش‌فرض 1380 است؛ اگر بسته بزرگ مشکل داشت، هر دو سمت را به 1320 تغییر دهید.
active بودن systemd به معنی اتصال نیست؛ ping در diagnose دسترسی سمت مقابل را می‌سنجد.
RX/TX از زمان ساخت اینترفیس هستند و پس از ری‌استارت یا ریبوت صفر می‌شوند.
مانیتور اختیاری پیش‌فرض خاموش است؛ در صورت مجاز بودن ICMP فعال کنید:
  sudo gre-fou monitor ir1fr1 on
پس از سه ping ناموفق در بررسی‌های یک‌دقیقه‌ای، تونل محلی ری‌استارت می‌شود.
برای خاموش کردن:
  sudo gre-fou monitor ir1fr1 off
اگر ICMP مسدود باشد مانیتور می‌تواند تونل سالم را ری‌استارت کند.

دستورهای بدون پرسش تعاملی، پس از ساخت تونل:
  sudo gre-fou forward-add ir1fr1 both 2082,2053
  sudo gre-fou forward-add ir1fr1 tcp 443 --target 8443
  sudo gre-fou forward-delete ir1fr1 1
  sudo gre-fou stop ir1fr1
  sudo gre-fou start ir1fr1
  sudo gre-fou restart ir1fr1
  sudo gre-fou link ir1fr1
  sudo gre-fou backup /root/gre-fou-backup.json
  sudo gre-fou restore /root/gre-fou-backup.json
  sudo gre-fou remove ir1fr1
start بوت خودکار را فعال می‌کند؛ stop آن را غیرفعال می‌کند.
restore تنظیمات با نام موجود را جایگزین نمی‌کند و سرویس‌ها را خودکار بالا نمی‌آورد.
با افزودن فوروارد، ip_forward فعال می‌شود؛ حذف تونل آن را در سطح کل سیستم خاموش
نمی‌کند تا سایر سرویس‌ها متوقف نشوند.
پشتیبانی: Linux با systemd و ماژول‌های fou/ip_gre و IPv4 مستقیم.
روی Ubuntu 22.04/24.04، Debian 12/13 و AlmaLinux/Rocky 9 ابزارهای لازم نصب می‌شوند؛
پشتیبانی واقعی GRE/FOU به کرنل و اجازه NET_ADMIN ارائه‌دهنده بستگی دارد.
"""

def main():
    parser=argparse.ArgumentParser(prog='gre-fou', description='GRE over FOU Manager '+VERSION,
        epilog='نصب: sudo bash gre-fou-manager.sh install | منو: sudo gre-fou | لینک سمت دوم در منو. IPv4 مستقیم؛ systemd؛ بدون رمزنگاری. GRE key فقط شناسه است.')
    sub=parser.add_subparsers(dest='cmd')
    p=sub.add_parser('install'); p.add_argument('--no-deps',action='store_true')
    for cmd in ('up','down','start','stop','restart','remove','link','diagnose','logs','health'):
        p=sub.add_parser(cmd); p.add_argument('name')
    p=sub.add_parser('monitor'); p.add_argument('name'); p.add_argument('mode',choices=['on','off'])
    p=sub.add_parser('status'); p.add_argument('name',nargs='?')
    p=sub.add_parser('create'); p.add_argument('config',help='validated JSON file')
    p=sub.add_parser('import-link'); p.add_argument('link'); p.add_argument('--name')
    p=sub.add_parser('forward-add'); p.add_argument('name'); p.add_argument('proto',choices=['tcp','udp','both']); p.add_argument('ports'); p.add_argument('--target',type=int)
    p=sub.add_parser('forward-delete'); p.add_argument('name'); p.add_argument('index',type=int)
    for cmd in ('backup','restore'): p=sub.add_parser(cmd); p.add_argument('file')
    sub.add_parser('version')
    sub.add_parser('guide')
    args=parser.parse_args()
    if args.cmd=='version': print(VERSION); return
    if args.cmd=='guide': print(GUIDE); return
    root()
    if args.cmd=='install': install(not args.no_deps); return
    if not pathlib.Path(BIN).exists() and args.cmd not in ('up','down'):
        raise ValueError('ابتدا نصب کنید: sudo bash gre-fou-manager.sh install')
    if args.cmd is None: menu()
    elif args.cmd=='up': up(load(args.name))
    elif args.cmd=='down': down(load(args.name))
    elif args.cmd=='start': run('systemctl','enable','--now',unit(args.name))
    elif args.cmd=='stop': run('systemctl','disable','--now',unit(args.name))
    elif args.cmd=='restart': svc('restart',args.name)
    elif args.cmd=='remove': remove(args.name)
    elif args.cmd=='monitor': monitor(args.name,args.mode=='on')
    elif args.cmd=='health': health(args.name)
    elif args.cmd=='link': print(encode(load(args.name)))
    elif args.cmd=='status': status(args.name)
    elif args.cmd=='diagnose': diagnose(load(args.name))
    elif args.cmd=='logs':
        p=run('journalctl','-u',unit(args.name),'-n','100','--no-pager'); print(p.stdout)
    elif args.cmd=='create': create(validate(json.loads(pathlib.Path(args.config).read_text())))
    elif args.cmd=='import-link':
        c=decode(args.link)
        if args.name: c['name']=args.name
        create(validate(c))
    elif args.cmd=='forward-add':
        c=load(args.name); change(c,add_forward(c,args.proto,args.ports,args.target))
    elif args.cmd=='forward-delete':
        c=load(args.name); new=copy.deepcopy(c)
        if not 1<=args.index<=len(c['forwards']): raise ValueError('شماره نامعتبر است.')
        del new['forwards'][args.index-1]; change(c,new)
    elif args.cmd=='backup': backup(args.file)
    elif args.cmd=='restore': restore(args.file)

if __name__=='__main__':
    try: main()
    except EOFError: print('ورودی پایان یافت.'); sys.exit(0)
    except KeyboardInterrupt: print('\nلغو شد.'); sys.exit(130)
    except (ValueError,RuntimeError,OSError,subprocess.SubprocessError) as e:
        print('خطا: '+str(e),file=sys.stderr); sys.exit(1)
PY
)" "$@"
