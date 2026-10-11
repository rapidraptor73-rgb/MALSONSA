#!/usr/bin/env python3
"""Install central storage on the DB host; preserve other applications/databases.

Run as root from a staged repository: python3 install_primary.py --db-ip IP
--was-ip IP --agent-ip IP. Passwords are generated on the host, never in Git.
"""
import argparse
import json
import os
import re
from pathlib import Path
import secrets
import shutil
import subprocess
import time


def command(*args):
    subprocess.run(list(args),check=True)


def write(path,text,mode=0o600):
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
    temporary=path.with_name(path.name+'.new');temporary.write_text(text,encoding='utf-8')
    temporary.chmod(mode);temporary.replace(path)


def main():
    parser=argparse.ArgumentParser()
    for name in ('db-ip','was-ip','agent-ip'):parser.add_argument('--'+name,required=True)
    parser.add_argument('--skip-packages',action='store_true')
    args=parser.parse_args()
    import ipaddress
    for value in (args.db_ip,args.was_ip,args.agent_ip):ipaddress.ip_address(value)
    if os.geteuid()!=0:raise RuntimeError('Run as root on the primary DB host')
    source=Path(__file__).resolve().parents[2]
    backup=Path('/var/backups/malsonsa')/('central-primary-'+time.strftime('%Y%m%d-%H%M%S'))
    backup.mkdir(parents=True,mode=0o700)
    for name in ('/etc/mysql/mariadb.conf.d/60-malsonsa.cnf','/etc/rsyslog.d/zz-malsonsa-central.conf','/etc/rsyslog.d/65-malsonsa-central.conf','/etc/rsyslog.d/35-malsonsa-central.conf'):
        if Path(name).exists():shutil.copy2(name,backup/Path(name).name)
    os.environ['DEBIAN_FRONTEND']='noninteractive'
    if not args.skip_packages:
        command('apt-get','update')
        command('apt-get','install','-y','mariadb-server','rsyslog-mysql','python3-venv')
    config_dir=Path('/etc/malsonsa');config_dir.mkdir(mode=0o700,exist_ok=True)
    secret_file=config_dir/'central-secrets.json'
    credentials=json.loads(secret_file.read_text()) if secret_file.exists() else {
        name:secrets.token_hex(24) for name in ('was','collector','exporter','archive_token')}
    write(secret_file,json.dumps(credentials))
    command('systemctl','enable','--now','mariadb')
    for host in subprocess.check_output(['mariadb','-N','-e','SELECT Host FROM mysql.user'],text=True).splitlines():
        if host not in ('localhost','%'):
            try:ipaddress.ip_address(host)
            except ValueError:raise RuntimeError('Existing hostname-based DB grants need review before enabling IP-only authentication')
    write('/etc/mysql/mariadb.conf.d/60-malsonsa.cnf','[mysqld]\nbind-address='+args.db_ip+
          '\nskip-name-resolve\ncharacter-set-server=utf8mb4\ncollation-server=utf8mb4_unicode_ci\n',0o644)
    command('systemctl','restart','mariadb')
    # All grant host values are validated addresses, credentials are hexadecimal.
    sql="CREATE DATABASE IF NOT EXISTS malsonsa CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;\n"
    grants=[('soc_was',args.was_ip,'was',
             'SELECT,INSERT,UPDATE,DELETE,INDEX ON malsonsa.*'),
            ('soc_collector',args.db_ip,'collector','INSERT ON malsonsa.raw_logs'),
            ('soc_exporter',args.db_ip,'exporter','SELECT ON malsonsa.*')]
    for user,host,key,grant in grants:
        sql+=f"CREATE USER IF NOT EXISTS '{user}'@'{host}' IDENTIFIED BY '{credentials[key]}';\n"
        sql+=f"ALTER USER '{user}'@'{host}' IDENTIFIED BY '{credentials[key]}';\nGRANT {grant} TO '{user}'@'{host}';\n"
    # Tables must exist before narrow grants; create them using the local root socket.
    schema=(source/'backend/central_schema.sql').read_text()
    sql=sql.split('CREATE USER')[0]+'USE malsonsa;\n'+schema+'\n'+sql[sql.index('CREATE USER'):]
    sql+=f"GRANT UPDATE(exported_revision) ON malsonsa.analysis_results TO 'soc_exporter'@'{args.db_ip}';\n"
    sql+=f"GRANT SELECT,INSERT,UPDATE,DELETE ON malsonsa.analysis_export_paths TO 'soc_exporter'@'{args.db_ip}';\n"
    result=subprocess.run(['mariadb'],input=sql,text=True,capture_output=True)
    if result.returncode:raise RuntimeError('MariaDB schema/grant setup failed; credentials omitted')
    app=Path('/opt/malsonsa/backend');app.mkdir(parents=True,exist_ok=True)
    for name in ('central_store.py','central_exporter.py','central_archive.py'):
        shutil.copy2(source/'backend'/name,app/name)
    command('python3','-m','venv','/opt/malsonsa/venv')
    command('/opt/malsonsa/venv/bin/python','-m','pip','install','-r',str(source/'backend/requirements.lock.txt'))
    base={'host':args.db_ip,'database':'malsonsa','archive_token':credentials['archive_token'],
          'archive_url':'http://'+args.db_ip+':8011'}
    write(config_dir/'was.json',json.dumps(dict(base,user='soc_was',password=credentials['was'])))
    write(config_dir/'exporter.json',json.dumps(dict(base,user='soc_exporter',password=credentials['exporter'])))
    template=('INSERT INTO raw_logs(event_time,host_ip,hostname,facility,severity,program,message,raw_line) '
      "VALUES ('%timereported:::date-rfc3339%','%fromhost-ip%','%hostname%','%syslogfacility-text%',"
      "'%syslogseverity-text%','%programname%','%msg%','%rawmsg%')")
    receiver='''module(load="imtcp")
module(load="ommysql")
template(name="MalsonsaRawSQL" type="string" option.sql="on" string="TEMPLATE")
ruleset(name="MalsonsaCentralReceiver") {
  if ($fromhost-ip == "AGENT") then {
    action(type="ommysql" server="DATABASE" db="malsonsa" uid="soc_collector" pwd="PASSWORD"
      template="MalsonsaRawSQL" queue.type="LinkedList" queue.filename="malsonsa_sql"
      queue.spoolDirectory="/var/spool/rsyslog" queue.maxDiskSpace="1g" queue.saveOnShutdown="on"
      action.resumeRetryCount="-1")
  }
  stop
}
input(type="imtcp" address="DATABASE" port="514" ruleset="MalsonsaCentralReceiver")
'''.replace('TEMPLATE',template).replace('AGENT',args.agent_ip).replace('DATABASE',args.db_ip).replace('PASSWORD',credentials['collector'])
    existing='\n'.join('\n'.join(line for line in path.read_text(errors='replace').splitlines() if not line.lstrip().startswith('#'))
        for path in [Path('/etc/rsyslog.conf')]+list(Path('/etc/rsyslog.d').glob('*.conf'))
        if path.name not in ('35-malsonsa-central.conf','65-malsonsa-central.conf','zz-malsonsa-central.conf'))
    for module in ('imtcp','ommysql'):
        if re.search(r'(?:load\s*=\s*[\"\']'+module+r'[\"\']|\$ModLoad\s+'+module+r'\b)',existing):
            receiver=receiver.replace('module(load="'+module+'")\n','')
    # Debian/Ubuntu may load ommysql from mysql.conf; actions must follow it.
    for name in ('35-malsonsa-central.conf','65-malsonsa-central.conf'):
        old=Path('/etc/rsyslog.d')/name
        if old.exists():old.replace(backup/(name+'.disabled'))
    write('/etc/rsyslog.d/zz-malsonsa-central.conf',receiver)
    command('install','-d','-o','syslog','-g','adm','-m','0750','/var/spool/rsyslog')
    command('rsyslogd','-N1')
    command('systemctl','restart','rsyslog')
    Path('/var/lib/malsonsa/index').mkdir(parents=True,mode=0o750,exist_ok=True)
    for name in ('soc-central-exporter.service','soc-central-archive.service'):
        shutil.copy2(source/'deploy/systemd'/name,Path('/etc/systemd/system')/name)
    command('systemctl','daemon-reload')
    command('systemctl','enable','--now','soc-central-exporter','soc-central-archive')
    if shutil.which('ufw') and 'Status: active' in subprocess.check_output(['ufw','status'],text=True):
        for ip,port in ((args.agent_ip,'514'),(args.was_ip,'3306'),(args.was_ip,'8011')):
            command('ufw','allow','from',ip,'to',args.db_ip,'port',port,'proto','tcp')
    print('Central primary installed. Backup:',backup,flush=True)


if __name__=='__main__':main()
