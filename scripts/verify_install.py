#!/usr/bin/env python3
"""Verify a fresh install over TCP/UDP syslog, Nginx and the public API."""
import argparse
import json
import subprocess
import time
import urllib.request
import uuid
from pathlib import Path


def main():
    p=argparse.ArgumentParser(); p.add_argument('--web-port',type=int,default=80); p.add_argument('--syslog-port',type=int,default=514); p.add_argument('--expect-token'); p.add_argument('--token-file',type=Path)
    args=p.parse_args(); base='http://127.0.0.1:'+str(args.web_port)
    def api(path,method='GET',data=None):
        with urllib.request.urlopen(urllib.request.Request(base+path,method=method,data=json.dumps(data).encode() if data is not None else None,headers={'Content-Type':'application/json'}),timeout=5) as response: return json.load(response)
    assert api('/api/health')['status']=='ok'
    for file,needle in [('/','theme.css'),('/rsyslog.html','priorityFilter'),('/hosts.html','관제 호스트 관리'),('/theme.css','color-scheme:light'),('/risk-details.js','same_src'),('/site-config.js','SOC_CONFIG')]:
        with urllib.request.urlopen(base+file,timeout=5) as response: assert needle in response.read().decode(),file
    token=args.expect_token or 'install-probe-'+uuid.uuid4().hex
    if not args.expect_token:
        for protocol in ('--tcp','--udp'):
            message=f'failed password authentication failure src=198.51.100.20 dst=192.0.2.10 user=analyst probe={token}'
            subprocess.run(['logger','--server','127.0.0.1','--port',str(args.syslog_port),protocol,'--tag','MALSONSA-INSTALL-TEST',message],check=True)
    for _ in range(30):
        rows=api('/api/events?limit=1000')['events']
        found=[row for row in rows if token in row['message']]
        if len(found)>=2: break
        time.sleep(.5)
    assert len(found)>=2,'TCP/UDP test logs not ingested'
    assert all(r['src_ip']=='198.51.100.20' and r['dst_ip']=='192.0.2.10' and r['time'] and r['event']=='AUTH_FAILURE' for r in found)
    anchor=found[0]['id']; api('/api/anchors/'+str(anchor)+'/hold','POST')
    assert any(r['id']==anchor for r in api('/api/anchors')['anchors'])
    assert any(r['id']==found[1]['id'] for r in api('/api/similar/'+str(anchor))['similar'])
    api('/api/anchors/'+str(anchor),'DELETE')
    assert not any(r['id']==anchor for r in api('/api/anchors')['anchors'])
    # Bookmarks persist across the tested upgrade, independently of Hold.
    saved=api('/api/bookmarks?field=message&q='+token)['events']
    if args.expect_token:
        assert any(row['id']==anchor for row in saved),'Saved log lost during upgrade'
    api('/api/bookmarks/'+str(anchor),'POST')
    saved=api('/api/bookmarks?field=message&q='+token)['events']
    assert any(row['id']==anchor and row['bookmarked'] for row in saved)
    assert not any(row['id']==anchor for row in api('/api/anchors')['anchors'])
    sources=api('/api/source-ips?seconds=0&q=198.51.100.20')['sources']
    assert sources and sources[0]['event_count']>=2 and sources[0]['sample_count']<=20
    assert sources[0]['risk_score']>=20
    if not args.token_file:
        api('/api/bookmarks/'+str(anchor),'DELETE')
        assert not any(row['id']==anchor for row in api('/api/bookmarks?field=message&q='+token)['events'])
    with urllib.request.urlopen(base+'/rules.html',timeout=5) as response: assert '관제 룰셋' in response.read().decode()
    with urllib.request.urlopen(base+'/rules.js',timeout=5) as response: assert '/api/rules/preview' in response.read().decode()
    # A temporary rule exercises the same API used by the browser, then is removed.
    hosts=api('/api/hosts')['hosts']; host=next((h for h in hosts if h['ip']==found[0]['host_ip']),None)
    created_host=host is None
    host_id=api('/api/hosts','POST',{'name':'installer-rule-probe','ip':found[0]['host_ip']})['id'] if created_host else host['id']
    rule_id=None
    try:
        rule={'host_id':host_id,'name':'Installation rule probe','attack':'SSH password guessing','reason':'Repeated authentication failures from one source within five minutes.','points':120,'min_hits':2,'window_seconds':300,'group_by':'src_ip','conditions':[{'field':'message','operator':'contains','value':token}]}
        rule_id=api('/api/rules','POST',rule)['id']
        latest=max(found,key=lambda row:row['id'])
        assert api('/api/rules/preview','POST',{'rule':rule,'event_id':latest['id']})['matched']
        evaluated=next(row for row in api('/api/events?limit=1000')['events'] if row['id']==latest['id'])
        assert any(item['rule_id']==rule_id and item['hits']>=2 for item in evaluated['detections'])
        api('/api/rules/'+str(rule_id),'PATCH',{'enabled':False})
        evaluated=next(row for row in api('/api/events?limit=1000')['events'] if row['id']==latest['id'])
        assert not any(item['rule_id']==rule_id for item in evaluated['detections'])
    finally:
        if rule_id is not None: api('/api/rules/'+str(rule_id),'DELETE')
        if created_host: api('/api/hosts/'+str(host_id),'DELETE')
    print('Install verification passed; preserved probe token:',token)
    if args.token_file: args.token_file.write_text(token,encoding='utf-8')
    return token


if __name__=='__main__': main()
