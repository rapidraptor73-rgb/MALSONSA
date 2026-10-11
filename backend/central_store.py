"""MariaDB storage adapter. No monitored event is persisted on the WAS filesystem."""
import json
import os
import re
import sqlite3
import hashlib
from datetime import datetime, timezone
from pathlib import Path


def julian(value):
    try:
        parsed = datetime.fromisoformat(str(value).replace('Z', '+00:00'))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.timestamp()/86400+2440587.5
    except (ValueError, TypeError, OverflowError):
        return None


class Row(dict):
    def __getitem__(self, key):
        return list(self.values())[key] if isinstance(key, int) else super().__getitem__(key)


class Cursor:
    def __init__(self, cursor):
        self.cursor = cursor
        self.lastrowid = cursor.lastrowid
        self.rowcount = cursor.rowcount

    def fetchone(self):
        row = self.cursor.fetchone()
        return Row(row) if row is not None else None

    def fetchall(self):
        return [Row(row) for row in self.cursor.fetchall()]

    def __iter__(self):
        return iter(self.fetchall())


def translate(sql, args):
    """Translate the finite SQL vocabulary used by the existing dashboard."""
    args = list(args)
    original = sql
    for match in re.finditer(r'julianday\(\?\)', original, re.I):
        index = original[:match.start()].count('?')
        args[index] = julian(args[index])
    sql = re.sub(r'julianday\(\?\)', '?', sql, flags=re.I)
    sql = re.sub(r'julianday\(time\)', 'time_jd', sql, flags=re.I)
    sql = sql.replace('INSERT OR IGNORE', 'INSERT IGNORE').replace('INSERT OR REPLACE', 'REPLACE')
    sql = sql.replace('COLLATE NOCASE', 'COLLATE utf8mb4_unicode_ci')
    sql = re.sub(r'soc_casefold\((.*?)\)', r'LOWER(\1)', sql)
    # SQLite DDL is used only for the already provisioned rule table.
    sql = sql.replace('INTEGER PRIMARY KEY AUTOINCREMENT', 'BIGINT PRIMARY KEY AUTO_INCREMENT')
    return sql.replace('?', '%s'), args


class Connection:
    def __init__(self, config=None):
        import pymysql
        self.driver = pymysql
        if config is None:
            config = json.loads(Path(os.environ['SOC_CENTRAL_CONFIG']).read_text(encoding='utf-8'))
        self.config = config
        self.connection = pymysql.connect(host=config['host'], port=config.get('port',3306),
            user=config['user'], password=config['password'], database=config['database'],
            charset='utf8mb4', cursorclass=pymysql.cursors.DictCursor,
            connect_timeout=5, read_timeout=30, write_timeout=30, autocommit=False)

    def execute(self, sql, args=()):
        # register_rules initializes these only in SQLite; MariaDB is provisioned explicitly.
        if sql.lstrip().startswith('CREATE TABLE IF NOT EXISTS detection_rules') and 'AUTOINCREMENT' in sql:
            sql = 'SELECT 1'
        sql,args = translate(sql,args)
        cursor = self.connection.cursor()
        try:
            cursor.execute(sql,args)
        except self.driver.IntegrityError as exc:
            raise sqlite3.IntegrityError(str(exc)) from exc
        return Cursor(cursor)

    def commit(self):
        self.connection.commit()

    def executemany(self, sql, records):
        cursor=self.connection.cursor()
        translated,_=translate(sql,())
        try:
            cursor.executemany(translated,records)
        except self.driver.IntegrityError as exc:
            raise sqlite3.IntegrityError(str(exc)) from exc
        return Cursor(cursor)

    def rollback(self):
        self.connection.rollback()

    def close(self):
        self.connection.close()

    def columns(self, table):
        return [row['COLUMN_NAME'] for row in self.execute(
            'SELECT COLUMN_NAME FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=? ORDER BY ORDINAL_POSITION', (table,))]

    def exists(self, table):
        return self.execute('SELECT 1 FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=?',(table,)).fetchone() is not None


def provision(config):
    connection=Connection(config)
    try:
        schema=Path(__file__).with_name('central_schema.sql').read_text(encoding='utf-8')
        for statement in schema.split(';'):
            if statement.strip():
                connection.execute(statement)
        connection.commit()
    finally:
        connection.close()


def insert_normalized(connection, event, raw_id=None, event_id=None):
    names=['time','host_ip','hostname','src_ip','dst_ip','event','user','program','facility',
           'severity','mitre','score','message','raw_line']
    values=[event.get(name) for name in names]
    names.extend(['time_jd','raw_id']);values.extend([julian(event['time']),raw_id])
    if event_id is not None:
        names.insert(0,'id');values.insert(0,event_id)
    cursor=connection.execute('INSERT IGNORE INTO events('+','.join(names)+') VALUES('+','.join('?' for _ in names)+')',values)
    return cursor.lastrowid


def version(connection):
    data=[[dict(row) for row in connection.execute('SELECT * FROM '+table+' ORDER BY id')]
          for table in ('detection_rules','monitored_hosts')]
    return hashlib.sha256(json.dumps(['central-hybrid-anchors-v1',data],sort_keys=True,ensure_ascii=False).encode()).hexdigest()


def read_archive(event_id):
    import urllib.request
    import urllib.error
    config=json.loads(Path(os.environ['SOC_CENTRAL_CONFIG']).read_text(encoding='utf-8'))
    request=urllib.request.Request(config['archive_url']+'/anchor/'+str(int(event_id)),
                                   headers={'Authorization':'Bearer '+config['archive_token']})
    try:
        with urllib.request.urlopen(request,timeout=3) as response:
            return json.load(response)
    except (OSError,ValueError):
        return None
