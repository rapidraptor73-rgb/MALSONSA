#!/usr/bin/env python3
"""Configure a durable five-minute agent queue; retain the old forwarding backup."""
import argparse
import ipaddress
from pathlib import Path
import shutil
import subprocess
import time


def install(target, data, mode=0o644):
    target=Path(target)
    temporary=target.with_name(target.name+'.new')
    temporary.write_text(data,encoding='utf-8');temporary.chmod(mode);temporary.replace(target)


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--db-ip',required=True)
    args=parser.parse_args()
    ipaddress.IPv4Address(args.db_ip)
    root=Path(__file__).resolve().parents[2]
    paths=['/etc/rsyslog.d/90-central-db-forward.conf', '/usr/local/libexec/malsonsa-agent-batch.py',
           '/usr/local/sbin/malsonsa-agent-flush', '/etc/systemd/system/malsonsa-agent-flush.service',
           '/etc/systemd/system/malsonsa-agent-flush.timer']
    backup=Path('/var/backups/malsonsa')/('agent-five-minute-'+time.strftime('%Y%m%d-%H%M%S'))
    backup.mkdir(parents=True,mode=0o700)
    for name in paths:
        source=Path(name)
        if source.is_symlink():raise RuntimeError('Managed symlink needs review')
        if source.exists():
            copy=backup/name.lstrip('/');copy.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(source,copy)
    Path('/usr/local/libexec').mkdir(exist_ok=True)
    Path('/var/lib/rsyslog/malsonsa-agent').mkdir(mode=0o700,exist_ok=True)
    if shutil.which('restorecon'):
        subprocess.run(['restorecon','-R','/var/lib/rsyslog/malsonsa-agent'],check=True)
    install(paths[1],(root/'deploy/central/agent_batch.py').read_text(),0o755)
    install(paths[2],'#!/bin/sh\nexec /usr/bin/python3 /usr/local/libexec/malsonsa-agent-batch.py flush --target '+args.db_ip+'\n',0o750)
    existing='\n'.join(p.read_text(errors='replace') for p in [Path('/etc/rsyslog.conf')]+list(Path('/etc/rsyslog.d').glob('*.conf')) if str(p)!=paths[0])
    module='' if 'load="omprog"' in existing else 'module(load="omprog")\n'
    config=module+'''# MALSONSA durable agent queue. Timer/manual flush sends to the central DB.
if ($inputname != "imtcp" and $inputname != "imudp") then {
  action(type="omprog" binary="/usr/bin/python3 /usr/local/libexec/malsonsa-agent-batch.py enqueue"
    template="RSYSLOG_SyslogProtocol23Format" confirmMessages="on" reportFailures="on"
    queue.type="LinkedList" queue.filename="central_db_fwd"
    queue.spoolDirectory="/var/lib/rsyslog" queue.size="10000"
    queue.maxDiskSpace="1g" queue.saveOnShutdown="on" action.resumeRetryCount="-1")
}
'''
    install(paths[0],config)
    try:
        subprocess.run(['rsyslogd','-N1'],check=True)
    except Exception:
        old=backup/paths[0].lstrip('/')
        if old.exists():shutil.copy2(old,paths[0])
        else:Path(paths[0]).unlink()
        raise
    for name in ('malsonsa-agent-flush.service','malsonsa-agent-flush.timer'):
        install('/etc/systemd/system/'+name,(root/'deploy/systemd'/name).read_text())
    subprocess.run(['systemctl','daemon-reload'],check=True)
    subprocess.run(['systemctl','restart','rsyslog'],check=True)
    subprocess.run(['systemctl','enable','--now','malsonsa-agent-flush.timer'],check=True)
    print('Agent queue and five-minute timer installed. Backup:',backup,flush=True)


if __name__=='__main__':main()
