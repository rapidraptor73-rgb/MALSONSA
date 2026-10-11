#!/usr/bin/env python3
"""Verify a tagged agent probe on the WAS without leaving HOLD/bookmark state."""
import argparse
import json
import os
import sys
import time
from pathlib import Path
import urllib.request

parser=argparse.ArgumentParser();parser.add_argument('--marker',required=True);args=parser.parse_args()
if not args.marker.startswith('MALSONSA-CENTRAL-PROBE-'):raise ValueError('Expected a dedicated probe marker')
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'backend'))
from central_store import Connection, read_archive


def api(path,method='GET'):
    request=urllib.request.Request('http://127.0.0.1:8000'+path,method=method)
    with urllib.request.urlopen(request,timeout=30) as response:return json.load(response)


assert api('/api/health')['storage']=='central-mariadb'
connection=Connection()
try:
    for attempt in range(120):
        rows=connection.execute('SELECT * FROM events WHERE host_ip=? AND INSTR(message,?)>0 ORDER BY id',
                                ('203.230.52.185',args.marker)).fetchall()
        connection.commit() # release the repeatable-read snapshot between polls
        if len(rows)>=3:break
        time.sleep(1)
    else:raise RuntimeError('Agent raw logs did not reach normalized central events')
    assert all(row['raw_id'] is not None for row in rows)
    for row in rows:
        raw=connection.execute('SELECT * FROM raw_logs WHERE id=?',(row['raw_id'],)).fetchone()
        assert raw['normalized_id']==row['id'] and args.marker in raw['raw_line']
    anchor=rows[0]['id']
    for attempt in range(120):
        stored=read_archive(anchor)
        if stored and len(stored['tuples'])>=2:break
        time.sleep(1)
    else:raise RuntimeError('Hybrid index export did not complete')
    print('Agent → primary raw → WAS analysis → primary JSON/TXT index verified:',len(rows),'probe events',flush=True)
    assert not connection.execute('SELECT 1 FROM soc_holds WHERE event_id=?',(anchor,)).fetchone()
    assert not connection.execute('SELECT 1 FROM soc_bookmarks WHERE event_id=?',(anchor,)).fetchone()
    try:
        held=api('/api/anchors/'+str(anchor)+'/hold','POST')
        assert held['archive']['status']=='ready'
        api('/api/bookmarks/'+str(anchor),'POST')
        assert any(row['id']==anchor for row in api('/api/bookmarks')['events'])
        started=time.perf_counter();similar=api('/api/similar/'+str(anchor));elapsed=time.perf_counter()-started
        assert len(similar['similar'])>=2
        assert stored['analysis']['event']['risk_summary']['total_score']>=120
        source=api('/api/source-ips?seconds=0&q=198.51.100.203')['sources'][0]
        assert source['event_count']>=3 and source['risk_score']>=120
        print('HOLD position.txt:',held['archive']['position'],flush=True)
        print('Similar count:',len(similar['similar']),'lookup:',similar.get('lookup','fresh-memory'),
              'elapsed_ms:',round(elapsed*1000,2),flush=True)
        # Base similarity scores are multiples of five; 59 forces the RAM path
        # while selecting the same set as 60 for this probe.
        started=time.perf_counter();fallback=api('/api/similar/'+str(anchor)+'?min_score=59');fallback_elapsed=time.perf_counter()-started
        assert [row['id'] for row in fallback['similar']]==[row['id'] for row in similar['similar']]
        print('Same-result fresh-memory elapsed_ms:',round(fallback_elapsed*1000,2),'(single lab observation)',flush=True)
        print('SRC count/risk:',source['event_count'],source['risk_score'],flush=True)
    finally:
        api('/api/bookmarks/'+str(anchor),'DELETE');api('/api/anchors/'+str(anchor),'DELETE')
    # EXPLAIN is evidence of indexed access, not a fabricated performance comparison.
    plan=connection.execute('EXPLAIN SELECT payload_json FROM analysis_results WHERE src_ip=? ORDER BY event_id DESC LIMIT 50',
                            ('198.51.100.203',)).fetchall()
    print('Analysis lookup SQL plan:',json.dumps([dict(row) for row in plan]),flush=True)
finally:connection.close()
