#!/usr/bin/env python3
"""Install the production Flask SIEM on a dedicated systemd Linux host."""
import argparse
from contextlib import closing
import datetime
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
FRONTEND = ['index.html', 'hosts.html', 'rsyslog.html', 'rules.html', 'rules.js', 'theme.css', 'risk-details.js']
APP = Path('/opt/soc/backend')
WEB = Path('/usr/share/nginx/html/soc/frontend')
DATA = Path('/var/lib/soc-siem')
LOG = Path('/var/log/soc')


def run(args, **kwargs):
    print('+', shlex.join([str(a) for a in args]), flush=True)
    return subprocess.run([str(a) for a in args], check=True, **kwargs)


def port(value):
    number = int(value)
    if not 1 <= number <= 65535:
        raise argparse.ArgumentTypeError('port must be 1..65535')
    return number


class ConfigParser(argparse.ArgumentParser):
    def parse_args(self, args=None, namespace=None):
        values=sys.argv[1:] if args is None else list(args)
        result=super().parse_args(values,namespace)
        result._explicit_flags={v.split('=',1)[0][2:].replace('-','_') for v in values if v.startswith('--')}
        return result


def parser():
    p = ConfigParser(description='MALSONSA v1.1 automatic Linux installation')
    p.add_argument('--hostname', default='localhost')
    p.add_argument('--host-ip', help='IP displayed in the dashboard; defaults to hostname')
    p.add_argument('--bind', default='127.0.0.1', help='Nginx listen address')
    p.add_argument('--syslog-bind', default='127.0.0.1')
    p.add_argument('--web-port', type=port)
    p.add_argument('--backend-port', type=port, default=8000)
    p.add_argument('--syslog-port', type=port, default=514)
    p.add_argument('--allow-source', action='append', default=[], help='Trusted client CIDR; repeatable')
    p.add_argument('--tls-cert', type=Path)
    p.add_argument('--tls-key', type=Path)
    p.add_argument('--ip-map', help='JSON mapping of observed host/destination IPs')
    p.add_argument('--upgrade', action='store_true', help='Back up and update an existing installation')
    p.add_argument('--skip-os-packages', action='store_true')
    p.add_argument('--wheel-dir', type=Path, help='Install Python dependencies from local wheels only')
    p.add_argument('--open-firewall', action='store_true', help='Add source-restricted rules to an already active firewall')
    p.add_argument('--check', action='store_true', help='Read-only preflight')
    p.add_argument('--render-dir', type=Path, help='Write configuration previews only; do not install')
    return p


def validate(args):
    saved=Path('/etc/malsonsa/install.json')
    if args.upgrade and saved.is_file():
        previous=json.loads(saved.read_text())
        for key in ('hostname','host_ip','bind','syslog_bind','web_port','backend_port','syslog_port','allow_source','tls_cert','tls_key','ip_map'):
            if key in previous and key not in args._explicit_flags:
                value=previous[key]
                if key in ('tls_cert','tls_key') and value: value=Path(value)
                if key=='ip_map': value=json.dumps(value)
                setattr(args,key,value)
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.-]{0,252}', args.hostname):
        raise ValueError('hostname must be an IP or DNS name, without a scheme or path')
    args.bind = str(ipaddress.ip_address(args.bind))
    args.syslog_bind = str(ipaddress.ip_address(args.syslog_bind))
    if args.host_ip:
        args.host_ip = str(ipaddress.ip_address(args.host_ip))
    args.allow_source = [str(ipaddress.ip_network(v, strict=False)) for v in args.allow_source]
    if any(ipaddress.ip_network(v).prefixlen == 0 for v in args.allow_source):
        raise ValueError('--allow-source must specify a trusted network narrower than /0')
    if (not ipaddress.ip_address(args.bind).is_loopback or not ipaddress.ip_address(args.syslog_bind).is_loopback) and not args.allow_source:
        raise ValueError('external listeners require at least one --allow-source trusted CIDR')
    if bool(args.tls_cert) != bool(args.tls_key):
        raise ValueError('provide both --tls-cert and --tls-key')
    for path in (args.tls_cert, args.tls_key):
        if path and not path.is_file():
            raise ValueError('TLS certificate/key file is missing')
    args.web_port = args.web_port or (443 if args.tls_cert else 80)
    if len({args.web_port, args.backend_port, args.syslog_port}) != 3:
        raise ValueError('web, backend and syslog ports must be different')
    if args.wheel_dir and not args.wheel_dir.is_dir():
        raise ValueError('wheel directory does not exist')
    if args.ip_map is None:
        args.ip_map = {}
    else:
        args.ip_map = json.loads(args.ip_map)
    if not isinstance(args.ip_map, dict):
        raise ValueError('IP mapping must be a JSON object')
    args.ip_map = {str(ipaddress.ip_address(k)): str(ipaddress.ip_address(v)) for k,v in args.ip_map.items()}
    return args


def configs(args, log_owner='root'):
    env = {
        'SOC_APP_DIR': APP.as_posix(), 'SOC_DB_PATH': (DATA/'siem.db').as_posix(),
        'SOC_STATE_DIR': DATA.as_posix(), 'SOC_RSYSLOG_LOG': (LOG/'all-rsyslog.log').as_posix(),
        'SOC_IP_MAP': json.dumps(args.ip_map, separators=(',', ':')),
    }
    env_text = ''.join(k+'='+shlex.quote(v)+'\n' for k,v in env.items())
    common = '''User=socsiem
Group=socsiem
EnvironmentFile=/etc/malsonsa/siem.env
Restart=always
RestartSec=2
UMask=0027
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=/var/lib/soc-siem
'''
    backend = f'''[Unit]
Description=MALSONSA SIEM v1.1
After=network.target rsyslog.service
Requires=rsyslog.service
[Service]
Type=simple
WorkingDirectory={APP.as_posix()}
{common}ExecStart=/opt/soc/venv/bin/gunicorn --workers 1 --bind 127.0.0.1:{args.backend_port} --timeout 60 app:app
[Install]
WantedBy=multi-user.target
'''
    enricher = f'''[Unit]
Description=MALSONSA event enrichment
After=soc-siem.service
Wants=soc-siem.service
[Service]
Type=simple
{common}ExecStart=/opt/soc/venv/bin/python {APP.as_posix()}/soc_event_enricher.py
[Install]
WantedBy=multi-user.target
'''
    listen = ('['+args.bind+']') if ':' in args.bind else args.bind
    tls = '\n    ssl_certificate /etc/malsonsa/tls/server.crt;\n    ssl_certificate_key /etc/malsonsa/tls/server.key;\n    ssl_protocols TLSv1.2 TLSv1.3;' if args.tls_cert else ''
    acl = '\n'.join('    allow '+source+';' for source in ['127.0.0.1', '::1']+args.allow_source)
    nginx = f'''server {{
    listen {listen}:{args.web_port}{' ssl' if args.tls_cert else ''};
    server_name {args.hostname};{tls}
{acl}
    deny all;
    root {WEB.as_posix()};
    index index.html;
    location / {{ try_files $uri $uri/ =404; }}
    location /api/ {{
        proxy_pass http://127.0.0.1:{args.backend_port};
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }}
}}
'''
    sender_networks = [ipaddress.ip_network(v) for v in args.allow_source]
    senders = ', '.join(['127.0.0.1', '[::1]/128'] + [
        f'[{network.network_address}]/{network.prefixlen}' if network.version == 6 else str(network)
        for network in sender_networks
    ])
    rsyslog = f'''# Managed by MALSONSA. Dedicated receiver; do not duplicate these inputs.
module(load="imtcp")
module(load="imudp")
$AllowedSender TCP, {senders}
$AllowedSender UDP, {senders}
template(name="MalsonsaFormat" type="string" string="%timereported:::date-rfc3339%|%hostname%|%fromhost-ip%|%syslogfacility-text%|%syslogseverity-text%|%programname%|%msg%\\n")
ruleset(name="MalsonsaIngress") {{
    action(type="omfile" file="{LOG.as_posix()}/all-rsyslog.log" fileOwner="{log_owner}" fileGroup="socsiem" fileCreateMode="0640" template="MalsonsaFormat")
}}
input(type="imtcp" address="{args.syslog_bind}" port="{args.syslog_port}" ruleset="MalsonsaIngress")
input(type="imudp" address="{args.syslog_bind}" port="{args.syslog_port}" ruleset="MalsonsaIngress")
'''
    rotation = f'''{LOG.as_posix()}/all-rsyslog.log {{
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 0640 {log_owner} socsiem
    sharedscripts
    postrotate
        /bin/systemctl kill -s HUP rsyslog.service >/dev/null 2>&1 || true
    endscript
}}
'''
    settings={key:getattr(args,key) for key in ('hostname','host_ip','bind','syslog_bind','web_port','backend_port','syslog_port','allow_source','ip_map')}
    settings.update(tls_cert='/etc/malsonsa/tls/server.crt' if args.tls_cert else None,tls_key='/etc/malsonsa/tls/server.key' if args.tls_key else None)
    return {
        '/etc/malsonsa/install.json': json.dumps(settings,indent=2)+'\n',
        '/etc/malsonsa/siem.env': env_text,
        '/etc/systemd/system/soc-siem.service': backend,
        '/etc/systemd/system/soc-event-enricher.service': enricher,
        '/etc/nginx/conf.d/malsonsa.conf': nginx,
        '/etc/rsyslog.d/10-malsonsa.conf': rsyslog,
        '/etc/logrotate.d/malsonsa': rotation,
        str(WEB/'site-config.js'): 'window.SOC_CONFIG = '+json.dumps({'hostname':args.hostname,'host_ip':args.host_ip or args.hostname,'version':'1.1','siem_urls':{}}, ensure_ascii=True)+';\n',
    }


def distro():
    data = {}
    for line in Path('/etc/os-release').read_text().splitlines():
        if '=' in line:
            key,value=line.split('=',1); data[key]=value.strip('"')
    ident, version = data.get('ID'), data.get('VERSION_ID','').split('.')[0]
    if ident in ('ubuntu','debian') and version in ('22','24','12','13'):
        return 'apt'
    if ident in ('rocky','almalinux','rhel','centos') and version in ('9','10'):
        return 'dnf'
    raise ValueError('supported systems: Ubuntu 22.04/24.04, Debian 12/13, Rocky/Alma/RHEL 9/10')


def firewall_kind(args):
    if not args.open_firewall:
        return None
    if not args.allow_source:
        raise ValueError('--open-firewall requires trusted source CIDRs')
    if shutil.which('firewall-cmd') and subprocess.run(['firewall-cmd','--state'],capture_output=True).returncode == 0:
        return 'firewalld'
    if shutil.which('ufw') and 'Status: active' in subprocess.check_output(['ufw','status'],text=True,env={**os.environ,'LC_ALL':'C'}):
        return 'ufw'
    raise ValueError('start/configure firewalld or ufw before using --open-firewall; installer does not enable/reset a firewall')


def write(path, content, mode=0o644):
    path=Path(path)
    if path.is_symlink():
        raise ValueError('refusing to replace symlink: '+str(path))
    path.parent.mkdir(parents=True,exist_ok=True)
    temp=path.with_name(path.name+'.malsonsa-new')
    with temp.open('w',encoding='utf-8',newline='\n') as f: f.write(content)
    temp.chmod(mode); temp.replace(path)


def backup_files(paths, destination):
    saved = {}
    for path in paths:
        path=Path(path)
        if path.is_symlink(): raise ValueError('refusing managed symlink: '+str(path))
        saved[path]=path.exists()
        if path.is_file():
            target=destination/str(path).lstrip('/'); target.parent.mkdir(parents=True,exist_ok=True); shutil.copy2(path,target)
    return saved


def install(args):
    if sys.platform!='linux' or os.geteuid()!=0:
        raise ValueError('installation requires root on Linux; use --render-dir for configuration preview')
    family=distro(); firewall=firewall_kind(args)
    if not Path('/run/systemd/system').exists(): raise ValueError('a running systemd host is required')
    existing=(APP/'app.py').exists()
    if existing and not args.upgrade: raise ValueError('existing SIEM detected; use --upgrade to preserve and back up data')
    # Avoid accidentally replacing another site or receiver on an existing host.
    for conflict in ('/etc/nginx/conf.d/soc.psc.co.kr.conf','/etc/rsyslog.d/10-soc-input.conf'):
        if Path(conflict).exists(): raise ValueError('legacy configuration needs manual migration first: '+conflict)
    if not args.skip_os_packages:
        if family=='apt':
            run(['apt-get','update'])
            run(['apt-get','install','-y','python3','python3-venv','python3-pip','nginx','rsyslog','curl','ca-certificates','logrotate','openssl'],env={**os.environ,'DEBIAN_FRONTEND':'noninteractive'})
        else:
            run(['dnf','install','-y','python3','python3-pip','nginx','rsyslog','curl','ca-certificates','logrotate','openssl','policycoreutils-python-utils'])
    for command in ('nginx','rsyslogd','systemctl','useradd','groupadd'):
        if not shutil.which(command): raise ValueError('required command missing: '+command)
    if subprocess.run(['getent','group','socsiem'],stdout=subprocess.DEVNULL).returncode:
        run(['groupadd','--system','socsiem'])
    if subprocess.run(['id','socsiem'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode:
        run(['useradd','--system','--gid','socsiem','--home-dir','/opt/soc','--shell','/usr/sbin/nologin','socsiem'])
    log_owner='syslog' if subprocess.run(['id','syslog'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode==0 else 'root'
    for path,owner,mode in [(APP,'root',0o755),(WEB,'root',0o755),(DATA,'socsiem',0o750),(LOG,log_owner,0o2750)]:
        run(['install','-d','-m',format(mode,'o'),'-o',owner,'-g','socsiem',path])
    log=LOG/'all-rsyslog.log'; log.touch(exist_ok=True); run(['chown',log_owner+':socsiem',log]); log.chmod(0o640)
    venv=Path('/opt/soc/venv')
    if not (venv/'bin/python').exists(): run(['python3','-m','venv',venv])
    pip=[venv/'bin/python','-m','pip','install','--disable-pip-version-check','-r',ROOT/'backend/requirements.lock.txt']
    if args.wheel_dir: pip+=['--no-index','--find-links',args.wheel_dir.resolve()]
    run(pip)
    generated=configs(args,log_owner)
    runtime={APP/p.name:p for p in (ROOT/'backend').glob('*.py')}
    runtime.update({WEB/name:ROOT/'dashboard/frontend'/name for name in FRONTEND})
    touched=list(runtime)+[Path(p) for p in generated]
    if args.tls_cert: touched += [Path('/etc/malsonsa/tls/server.crt'),Path('/etc/malsonsa/tls/server.key')]
    backup=Path('/var/backups/malsonsa')/('install-'+datetime.datetime.now().strftime('%Y%m%d-%H%M%S-%f'))
    backup.mkdir(parents=True,mode=0o700)
    saved=backup_files(touched,backup)
    previously_active={s:subprocess.run(['systemctl','is-active','--quiet',s]).returncode==0 for s in ('soc-siem','soc-event-enricher')}
    db_source=DATA/'siem.db'
    if not db_source.exists() and (APP/'siem.db').exists(): db_source=APP/'siem.db'
    try:
        if existing:
            run(['systemctl','stop','soc-event-enricher','soc-siem'])
        if db_source.exists():
            with closing(sqlite3.connect('file:'+str(db_source)+'?mode=ro',uri=True)) as old, closing(sqlite3.connect(str(backup/'siem.db'))) as copy:
                old.backup(copy)
            if db_source!=DATA/'siem.db': shutil.copy2(backup/'siem.db',DATA/'siem.db')
            run(['chown','socsiem:socsiem',DATA/'siem.db'])
        for dst,src in runtime.items(): write(dst,src.read_text(encoding='utf-8'))
        for dst,text in generated.items(): write(dst,text,0o640 if dst.endswith('siem.env') else 0o644)
        Path('/etc/malsonsa').chmod(0o750); run(['chown','root:socsiem','/etc/malsonsa','/etc/malsonsa/siem.env'])
        if args.tls_cert:
            write('/etc/malsonsa/tls/server.crt',args.tls_cert.read_text(),0o644)
            write('/etc/malsonsa/tls/server.key',args.tls_key.read_text(),0o600)
        if shutil.which('restorecon'): run(['restorecon','-RF',APP,WEB,DATA,LOG,'/etc/malsonsa'])
        if shutil.which('getenforce') and subprocess.check_output(['getenforce'],text=True).strip()=='Enforcing':
            run(['setsebool','-P','httpd_can_network_connect','on'])
            if args.web_port not in (80,443):
                labels=subprocess.check_output(['semanage','port','-l'],text=True)
                http_lines=[line for line in labels.splitlines() if line.startswith('http_port_t')]
                tokens=re.findall(r'\b\d+(?:-\d+)?\b',' '.join(http_lines))
                covered=any(int(t.split('-')[0])<=args.web_port<=int(t.split('-')[-1]) for t in tokens)
                if not covered: run(['semanage','port','-a','-t','http_port_t','-p','tcp',str(args.web_port)])
        run(['nginx','-t']); run(['rsyslogd','-N1']); run(['systemd-analyze','verify','/etc/systemd/system/soc-siem.service','/etc/systemd/system/soc-event-enricher.service'])
        run(['systemctl','daemon-reload'])
        run(['systemctl','enable','nginx','rsyslog','soc-siem','soc-event-enricher'])
        run(['systemctl','restart','rsyslog','soc-siem','soc-event-enricher','nginx'])
        for _ in range(40):
            try:
                with urllib.request.urlopen(f'http://127.0.0.1:{args.backend_port}/api/health',timeout=2) as response:
                    if json.load(response)['status']=='ok': break
            except (OSError,ValueError): time.sleep(.5)
        else: raise RuntimeError('SIEM health check failed')
        run(['systemctl','is-active','nginx','rsyslog','soc-siem','soc-event-enricher'])
        if firewall:
            for source in args.allow_source:
                for protocol,number in [('tcp',args.web_port),('tcp',args.syslog_port),('udp',args.syslog_port)]:
                    if firewall=='firewalld':
                        version=ipaddress.ip_network(source).version
                        rule=f'rule family="ipv{version}" source address="{source}" port port="{number}" protocol="{protocol}" accept'
                        run(['firewall-cmd','--permanent','--add-rich-rule',rule])
                    else: run(['ufw','allow','from',source,'to','any','port',str(number),'proto',protocol])
            if firewall=='firewalld': run(['firewall-cmd','--reload'])
    except Exception:
        for service in ('soc-event-enricher','soc-siem'): subprocess.run(['systemctl','stop',service])
        for path,existed in saved.items():
            if existed: shutil.copy2(backup/str(path).lstrip('/'),path)
            elif path.exists(): path.unlink()
        subprocess.run(['systemctl','daemon-reload'])
        for service,active in previously_active.items():
            if active: subprocess.run(['systemctl','start',service])
        subprocess.run(['systemctl','try-restart','rsyslog','nginx'])
        print('Managed files restored. DB/logs are retained; backup:',backup,file=sys.stderr)
        raise
    print(f'Installed MALSONSA v1.1: {"https" if args.tls_cert else "http"}://{args.hostname}:{args.web_port}/')
    print('Backup:',backup)


def main(argv=None):
    args=validate(parser().parse_args(argv))
    if args.render_dir:
        for path,text in configs(args).items(): write(args.render_dir.joinpath(*str(path).replace('\\','/').strip('/').split('/')),text)
        print('Configuration preview:',args.render_dir)
        return
    if args.check:
        family=distro() if sys.platform=='linux' else 'unsupported (Linux required for install)'
        print(json.dumps({'version':'1.1','package_manager':family,'existing_install':(APP/'app.py').exists(),'listeners':{'web':args.bind,'syslog':args.syslog_bind},'trusted_sources':args.allow_source,'network_required':not args.skip_os_packages or not args.wheel_dir},indent=2))
        return
    install(args)


if __name__=='__main__':
    try: main()
    except (ValueError,RuntimeError,OSError,subprocess.CalledProcessError) as exc:
        print('Installation failed:',exc,file=sys.stderr); sys.exit(1)
