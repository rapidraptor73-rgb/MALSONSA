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
    def api(path,method='GET'):
        with urllib.request.urlopen(urllib.request.Request(base+path,method=method),timeout=5) as response: return json.load(response)
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
    print('Install verification passed; preserved probe token:',token)
    if args.token_file: args.token_file.write_text(token,encoding='utf-8')
    return token


if __name__=='__main__': main()
