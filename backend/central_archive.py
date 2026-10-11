"""Private DB-host API: resolve position.txt then read the indexed analysis JSON."""
import hmac
import json
import os
from pathlib import Path
from flask import Flask, jsonify, request
from central_store import Connection
from central_exporter import component,target

app=Flask(__name__)
config=json.loads(Path(os.environ['SOC_CENTRAL_CONFIG']).read_text(encoding='utf-8'))
root=Path(os.environ.get('SOC_ARCHIVE_ROOT','/var/lib/malsonsa/index'))


@app.get('/anchor/<int:event_id>')
def anchor(event_id):
    supplied=request.headers.get('Authorization','')
    if not hmac.compare_digest(supplied,'Bearer '+config['archive_token']):
        return jsonify(error='unauthorized'),401
    connection=Connection()
    try:
        row=connection.execute('SELECT host_ip,revision,exported_revision FROM analysis_results WHERE event_id=?',(event_id,)).fetchone()
        if not row or row['revision']!=row['exported_revision']:
            return jsonify(error='analysis export pending'),404
        folder=target(root,component(row['host_ip'])+'/correlations/'+str(event_id))
        position=target(root,str(folder.relative_to(root))+'/position.txt').read_text(encoding='utf-8').strip()
        payload=json.loads(target(root,position).read_text(encoding='utf-8'))
        tuples=[json.loads(line) for line in (folder/'similar-tuples.txt').read_text(encoding='utf-8').splitlines() if line]
        after=connection.execute('SELECT revision,exported_revision FROM analysis_results WHERE event_id=?',(event_id,)).fetchone()
        if after['revision']!=row['revision'] or after['exported_revision']!=row['exported_revision']:
            return jsonify(error='analysis export changed; retry'),409
        if payload['event']['id']!=event_id:
            return jsonify(error='invalid index identity'),409
        return jsonify(analysis=payload,position=position,tuples=tuples,revision=row['revision'])
    except FileNotFoundError:
        return jsonify(error='analysis export pending'),404
    finally:
        connection.close()
