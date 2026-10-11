"""Idempotent raw normalization shared by scheduled and manual collection."""
from central_store import julian


def consume_raw(db, parse, limit=100):
    connection=db()
    try:
        # One worker is active; unique raw_id also makes recovery idempotent.
        rows=connection.execute('SELECT * FROM raw_logs WHERE normalized_id IS NULL ORDER BY id LIMIT ?', (limit,)).fetchall()
        fields=['time','host_ip','hostname','src_ip','dst_ip','event','user','program','facility','severity','mitre','score','message','raw_line']
        records=[]
        for row in rows:
            line='|'.join(str(row.get(key) or '') for key in
                ('event_time','hostname','host_ip','facility','severity','program','message'))
            event=parse(line)
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

