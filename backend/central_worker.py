"""WAS: read central raw records, correlate in RAM, write results back to MariaDB."""
import hashlib
import json
import os
import time
from datetime import datetime, timezone

os.environ['SOC_DISABLE_INGESTOR'] = '1'
import app as siem
from central_store import julian, insert_normalized, version as rules_version


def consume_raw(limit=100):
    connection=siem.db()
    try:
        # One worker is active; unique raw_id also makes recovery idempotent.
        rows=connection.execute('SELECT * FROM raw_logs WHERE normalized_id IS NULL ORDER BY id LIMIT ?', (limit,)).fetchall()
        fields=['time','host_ip','hostname','src_ip','dst_ip','event','user','program','facility','severity','mitre','score','message','raw_line']
        records=[]
        for row in rows:
            line='|'.join(str(row.get(key) or '') for key in
                ('event_time','hostname','host_ip','facility','severity','program','message'))
            event=siem.parse_rsyslog_line(line)
            event['raw_line']=row['raw_line']
            records.append([event.get(field) for field in fields]+[julian(event['time']),row['id']])
        if records:
            connection.executemany('INSERT IGNORE INTO events('+','.join(fields+['time_jd','raw_id'])+') VALUES('
                +','.join('?' for _ in range(len(fields)+2))+')',records)
            raw_ids=[row['id'] for row in rows]
            normalized=connection.execute('SELECT id,raw_id FROM events WHERE raw_id IN ('+','.join('?' for _ in raw_ids)+')',raw_ids).fetchall()
            updates=[]
            for row in normalized:updates.extend([row['raw_id'],row['id']])
            if len(normalized)!=len(rows):raise RuntimeError('Missing normalized raw identity')
            connection.execute('UPDATE raw_logs SET normalized_id=CASE id '+
                ' '.join('WHEN ? THEN ?' for _ in normalized)+' END WHERE id IN ('+','.join('?' for _ in raw_ids)+')',updates+raw_ids)
        connection.commit()
        return len(rows)
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def analyze_batch(ids=None, version=None, limit=100):
    connection=siem.db()
    try:
        version=version or rules_version(connection)
        if ids is None:
            rows=connection.execute('SELECT e.* FROM events e LEFT JOIN analysis_results a ON a.event_id=e.id '
                'WHERE a.event_id IS NULL OR a.rules_version<>? ORDER BY e.id LIMIT ?', (version,limit)).fetchall()
        elif not ids:
            return 0
        else:
            rows=connection.execute('SELECT * FROM events WHERE id IN ('+','.join('?' for _ in ids)+') ORDER BY id',ids).fetchall()
        events=[dict(row) for row in rows]
        pool=[dict(row) for row in connection.execute('SELECT * FROM events ORDER BY id DESC LIMIT 5000')]
        by_host={}
        for host in {row.get('host_ip') for row in events}:
            if host:
                candidates=connection.execute('SELECT * FROM events WHERE host_ip=? ORDER BY id DESC LIMIT 5000',(host,))
            else:
                candidates=connection.execute("SELECT * FROM events WHERE host_ip IS NULL OR host_ip='' ORDER BY id DESC LIMIT 5000")
            by_host[host]=[dict(row) for row in candidates]
        pool_max=pool[0]['id'] if pool else 0
        siem.annotate_event_risk(siem.annotate_rules(events),connection)
        event_ids=[event['id'] for event in events]
        previous={row['event_id']:row['content_hash'] for row in connection.execute(
            'SELECT event_id,content_hash FROM analysis_results WHERE event_id IN ('+','.join('?' for _ in event_ids)+')',event_ids)} if event_ids else {}
        changed=[];rule_records=[]
        for event in events:
            parsed=siem.parse_time(event['time'])
            hour=parsed.astimezone(timezone.utc).strftime('%Y-%m-%d/%H') if parsed else 'unknown/00'
            payload={'schema_version':1,'event':event,'raw_id':event.get('raw_id'),
                     'rules_version':version,'pool_max_id':pool_max,
                     'host_max_id':by_host[event.get('host_ip')][0]['id'] if by_host.get(event.get('host_ip')) else 0,
                     'candidate_policy':'latest5000_samehost_src_or_user_60min'}
            similar=[]
            if parsed:
                for candidate in by_host.get(event.get('host_ip'),[]):
                    if candidate['id']==event['id']:continue
                    instant=siem.parse_time(candidate.get('time'))
                    if not instant:continue
                    difference=abs((parsed-instant).total_seconds())
                    if difference>3600:continue
                    score,reasons=siem.similar_score(event,candidate,difference)
                    if score>=60:
                        similar.append({'id':candidate['id'],'similar_score':score,'similar_reasons':reasons,
                                        'seconds':difference,'time':candidate['time']})
            payload['similar']=sorted(similar,key=lambda row:(-row['similar_score'],-row['id']))[:500]
            encoded=json.dumps(payload,sort_keys=True,ensure_ascii=False,separators=(',',':'))
            digest=hashlib.sha256(encoded.encode()).hexdigest()
            if previous.get(event['id'])==digest:
                continue
            values=[event['id'],event.get('raw_id'),event.get('host_ip'),event.get('src_ip'),event['event'],hour,
                    julian(event['time']),event['risk_summary']['total_score'],encoded,digest,version,siem.now_iso()]
            changed.append(values)
            for hit in event.get('detections',[]):
                rule_records.append((hit['rule_id'],event['id'],julian(event['time'])))
        if changed:
            connection.executemany('INSERT INTO analysis_results(event_id,raw_id,host_ip,src_ip,event,hour_key,time_jd,'
                'total_score,payload_json,content_hash,rules_version,analyzed_at) VALUES('+','.join('?' for _ in values)+') '
                'ON DUPLICATE KEY UPDATE raw_id=VALUES(raw_id),host_ip=VALUES(host_ip),src_ip=VALUES(src_ip),'
                'event=VALUES(event),hour_key=VALUES(hour_key),time_jd=VALUES(time_jd),total_score=VALUES(total_score),'
                'payload_json=VALUES(payload_json),content_hash=VALUES(content_hash),rules_version=VALUES(rules_version),'
                'analyzed_at=VALUES(analyzed_at),revision=revision+1',changed)
            changed_ids=[row[0] for row in changed]
            connection.execute('DELETE FROM analysis_rule_index WHERE event_id IN ('+','.join('?' for _ in changed_ids)+')',changed_ids)
            if rule_records:connection.executemany('INSERT INTO analysis_rule_index(rule_id,event_id,time_jd) VALUES(?,?,?)',rule_records)
        connection.commit()
        return len(events)
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def run():
    # Only the central DB server's exporter writes files. WAS holds bounded batches in RAM.
    previous=None
    refresh_ids=[]
    while True:
        try:
            added=consume_raw()
            connection=siem.db()
            try:
                version=rules_version(connection)
                current=connection.execute('SELECT MAX(id) FROM events').fetchone()[0]
                marker=(version,current)
                if marker!=previous and not refresh_ids:
                    refresh_ids=[row[0] for row in connection.execute('SELECT id FROM events ORDER BY id DESC LIMIT 5000')]
                    previous=marker
            finally:
                connection.close()
            processed=analyze_batch(version=version)
            if refresh_ids:
                batch=refresh_ids[:100]
                analyze_batch(batch,version)
                refresh_ids=refresh_ids[100:]
            if not (added or processed or refresh_ids):
                time.sleep(2)
        except Exception as exc:
            # Avoid credentials and raw payloads in journal messages.
            print('[CENTRAL] retry after '+type(exc).__name__,flush=True)
            time.sleep(5)


if __name__=='__main__':
    run()
