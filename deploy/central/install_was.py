#!/usr/bin/env python3
"""Two-phase central WAS migration. Transfer legacy.db to the DB host before apply."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import time
import urllib.request

ROOT=Path(__file__).resolve().parents[2]
APP=Path('/opt/soc/backend')
STATE=ROOT/'migration-state.json'


def command(*args):subprocess.run(list(args),check=True)


def api(path):
    with urllib.request.urlopen('http://127.0.0.1:8000'+path,timeout=30) as response:return json.load(response)


def write(path,text,mode=0o640):
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
    temporary=path.with_name(path.name+'.central-new')
    temporary.write_text(text,encoding='utf-8');temporary.chmod(mode);temporary.replace(path)


def files():
    managed={APP/name:ROOT/'backend'/name for name in ('app.py','detection_rules.py','central_store.py',
        'central_schema.sql','central_ingest.py','collection_control.py','central_worker.py','central_exporter.py','central_archive.py')}
    managed[Path('/etc/systemd/system/soc-central-worker.service')]=ROOT/'deploy/systemd/soc-central-worker.service'
    return managed


def prepare():
    health=api('/api/health')
    if health.get('storage')=='central-mariadb':raise RuntimeError('WAS already uses central storage')
    database=Path(health['db']).resolve()
    if database.parent not in (APP,Path('/var/lib/soc-siem')):raise RuntimeError('Unexpected legacy DB path')
    backup=Path('/var/backups/malsonsa')/('central-was-'+time.strftime('%Y%m%d-%H%M%S'))
    backup.mkdir(parents=True,mode=0o700)
    paths=list(files())+[Path('/etc/rsyslog.d/10-soc-input.conf'),Path('/etc/rsyslog.d/20-soc-store.conf'),
        Path('/etc/systemd/system/soc-siem.service.d/central.conf'),Path('/etc/malsonsa/central.env'),
        Path('/etc/malsonsa/central.json')]
    present={str(path):path.exists() for path in paths}
    for path in paths:
        if path.is_symlink():raise RuntimeError('Managed symlink needs review')
        if path.exists():
            target=backup/str(path).lstrip('/');target.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(path,target)
    command('systemctl','stop','soc-siem','soc-event-enricher')
    with sqlite3.connect(str(database)) as original,sqlite3.connect(str(ROOT/'legacy.db')) as copy:original.backup(copy)
    digest=hashlib.sha256((ROOT/'legacy.db').read_bytes()).hexdigest()
    STATE.write_text(json.dumps({'db':str(database),'backup':str(backup),'present':present,'sha256':digest}))
    print('Prepared WAS backup:',backup,'SQLite snapshot SHA256:',digest,flush=True)


def rollback():
    if not STATE.exists():return
    state=json.loads(STATE.read_text());backup=Path(state['backup'])
    command('systemctl','stop','soc-central-worker') if Path('/etc/systemd/system/soc-central-worker.service').exists() else None
    for name,present in state['present'].items():
        path=Path(name)
        if present:shutil.copy2(backup/name.lstrip('/'),path)
        elif path.exists():path.unlink()
    command('systemctl','daemon-reload')
    command('systemctl','restart','rsyslog','soc-siem','soc-event-enricher')
    print('WAS managed sources restored; legacy DB retained.',flush=True)


def apply():
    state=json.loads(STATE.read_text())
    if not (ROOT/'backup-confirmed.json').exists():raise RuntimeError('Transfer and verify legacy.db on primary DB host first')
    proof=json.loads((ROOT/'backup-confirmed.json').read_text())
    if proof['sha256']!=state['sha256']:raise RuntimeError('Backup verification mismatch')
    sys.path.insert(0,str(ROOT/'backend'))
    from central_store import Connection,julian
    config=json.loads((ROOT/'connection.json').read_text())
    central=Connection(config)
    original=sqlite3.connect('file:'+str(ROOT/'legacy.db')+'?mode=ro',uri=True);original.row_factory=sqlite3.Row
    try:
        count=0
        existing={row['id']:dict(row) for row in central.execute('SELECT id,time,host_ip,message FROM events')}
        fields=['id','time','host_ip','hostname','src_ip','dst_ip','event','user','program','facility','severity','mitre','score','message','raw_line']
        records=[]
        for row in original.execute('SELECT * FROM events ORDER BY id'):
            event=dict(row)
            old=existing.get(row['id'])
            if old and any(old.get(field)!=event.get(field) for field in ('time','host_ip','message')):
                raise RuntimeError('Central event ID collision')
            if not old:records.append([event.get(field) for field in fields]+[julian(event['time'])])
            count+=1
        sql='INSERT INTO events('+','.join(fields+['time_jd'])+') VALUES('+','.join('?' for _ in range(len(fields)+1))+')'
        for offset in range(0,len(records),500):central.executemany(sql,records[offset:offset+500])
        tables={row[0] for row in original.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        for table in ('monitored_hosts','detection_rules','soc_holds','soc_bookmarks'):
            if table not in tables:continue
            fields=central.columns(table)
            source_fields={row[1] for row in original.execute('PRAGMA table_info('+table+')')}
            fields=[field for field in fields if field in source_fields]
            for row in original.execute('SELECT * FROM '+table):
                key='event_id' if table in ('soc_holds','soc_bookmarks') else 'id'
                previous=central.execute('SELECT * FROM '+table+' WHERE '+key+'=?',(row[key],)).fetchone()
                if previous and any(previous[field]!=row[field] for field in fields):raise RuntimeError('Central control ID collision: '+table)
                if not previous:central.execute('INSERT INTO '+table+'('+','.join(fields)+') VALUES('+','.join('?' for _ in fields)+')',[row[field] for field in fields])
        if 'anchors' in tables:
            columns={row[1] for row in original.execute('PRAGMA table_info(anchors)')}
            ref=next((field for field in ('event_id','log_id','logid','source_event_id') if field in columns),None)
            if ref:
                for row in original.execute('SELECT * FROM anchors'):
                    if row[ref] is not None:
                        central.execute('INSERT IGNORE INTO soc_holds(event_id,held_at) VALUES(?,?)',
                            (row[ref],row['held_at'] if 'held_at' in columns and row['held_at'] else 'legacy'))
        migrated={row['id']:dict(row) for row in central.execute('SELECT id,time,host_ip,message FROM events')}
        for row in original.execute('SELECT id,time,host_ip,message FROM events'):
            verified=migrated.get(row['id'])
            if dict(verified)!=dict(row):raise RuntimeError('Event migration verification failed')
        central.execute('INSERT IGNORE INTO monitored_hosts(name,ip,os_type,role,note,enabled,created_at) VALUES(?,?,?,?,?,?,?)',
            ('Agent 185','203.230.52.185','Rocky Linux 9','monitored agent','Direct TCP rsyslog to primary DB',1,time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime())))
        central.commit()
        print('Central migration verified:',count,'events; control records preserved.',flush=True)
    except Exception:
        central.rollback();raise
    finally:central.close();original.close()
    for path,source in files().items():write(path,source.read_text(),0o644)
    write('/etc/malsonsa/central.json',json.dumps(config))
    write('/etc/malsonsa/central.env','SOC_CENTRAL_CONFIG=/etc/malsonsa/central.json\nSOC_LOCAL_HOST_IP=203.230.52.214\n'
        'SOC_IP_MAP={"172.16.16.141":"203.230.52.214","172.16.12.20":"203.230.52.185"}\n')
    command('chown','root:socsiem','/etc/malsonsa','/etc/malsonsa/central.json','/etc/malsonsa/central.env')
    command('chmod','0750','/etc/malsonsa')
    write('/etc/systemd/system/soc-siem.service.d/central.conf','[Service]\nEnvironmentFile=/etc/malsonsa/central.env\nEnvironment=PYTHONDONTWRITEBYTECODE=1\n'
        'ExecStart=\nExecStart=/opt/soc/venv/bin/gunicorn --workers 1 --threads 4 --bind 127.0.0.1:8000 --timeout 90 app:app\n')
    # The worker uses the same central connection environment as the API.
    unit=Path('/etc/systemd/system/soc-central-worker.service')
    write(unit,unit.read_text().replace('/etc/soc-siem.env','/etc/malsonsa/central.env'),0o644)
    write('/etc/rsyslog.d/10-soc-input.conf','module(load="imtcp")\nmodule(load="imudp")\n'
        'ruleset(name="SocLocalOnlyNetwork") { stop }\n'
        'input(type="imtcp" port="514" ruleset="SocLocalOnlyNetwork")\n'
        'input(type="imudp" port="514" ruleset="SocLocalOnlyNetwork")\n',0o644)
    write('/etc/rsyslog.d/20-soc-store.conf','template(name="SocLocalOnlyFormat" type="string" '
        'string="%timereported:::date-rfc3339%|%hostname%|203.230.52.214|%syslogfacility-text%|%syslogseverity-text%|%programname%|%msg%\\n")\n'
        'if ($inputname != "imtcp" and $inputname != "imudp") then { action(type="omfile" '
        'file="/var/log/soc/all-rsyslog.log" template="SocLocalOnlyFormat" fileGroup="socsiem" fileCreateMode="0640") }\n',0o644)
    command('rsyslogd','-N1')
    command('systemctl','daemon-reload')
    command('systemctl','restart','rsyslog','soc-siem')
    command('systemctl','disable','soc-event-enricher')
    command('systemctl','enable','--now','soc-central-worker')
    for attempt in range(40):
        try:
            if api('/api/health').get('storage')=='central-mariadb':break
        except OSError:time.sleep(.5)
    else:raise RuntimeError('Central API health failed')
    assert all('risk_summary' in row for row in api('/api/events?limit=10&include_risk=1')['events'])
    assert 'sources' in api('/api/source-ips?seconds=0')
    assert 'events' in api('/api/bookmarks')
    print('Central API, collection risk, bookmarks and SRC statistics verified. Backup:',state['backup'],flush=True)


def retire():
    state=json.loads(STATE.read_text())
    proof=json.loads((ROOT/'retirement-confirmed.json').read_text())
    # Called only after the operator has paused writers and verified primary copies.
    allowed_db=Path(state['db']).resolve()
    for item in proof['files']:
        path=Path(item['source'])
        resolved=path.resolve()
        allowed=(resolved==allowed_db or resolved==ROOT/'legacy.db' or
                 (resolved.parent.parent==Path('/tmp') and resolved.parent.name.startswith('malsonsa-central-was-') and path.name=='legacy.db') or
                 (resolved.is_relative_to(Path('/var/backups/malsonsa')) and path.name=='siem.db') or
                 (resolved.is_relative_to(Path('/var/log/soc')) and path.name.startswith('all-rsyslog.log')))
        if not allowed or path.is_symlink():raise RuntimeError('Unexpected retirement path')
        if not item['primary_path'].startswith('/var/backups/malsonsa/was-retired-'):
            raise RuntimeError('Unexpected primary archive path')
        if hashlib.sha256(path.read_bytes()).hexdigest()!=item['sha256']:
            raise RuntimeError('Retirement file changed since backup')
    for item in proof['files']:
        path=Path(item['source'])
        if path==Path('/var/log/soc/all-rsyslog.log'):
            path.write_bytes(b'')
        else:path.unlink()
    # The new file ingestor reads only the WAS's own locally generated messages.
    log=Path('/var/log/soc/all-rsyslog.log');log.touch(exist_ok=True)
    command('chown','root:socsiem',str(log));command('chmod','0640',str(log))
    command('systemctl','restart','rsyslog','soc-siem','soc-central-worker')
    print('Legacy WAS DB/remote-log files retired after primary SHA256 verification; new local logs are WAS-only.',flush=True)


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('phase',choices=['prepare','apply','rollback','retire'])
    args=parser.parse_args()
    if os.geteuid()!=0:raise RuntimeError('Run as root')
    if args.phase=='prepare':prepare()
    elif args.phase=='rollback':rollback()
    elif args.phase=='retire':retire()
    else:
        try:apply()
        except Exception:rollback();raise
