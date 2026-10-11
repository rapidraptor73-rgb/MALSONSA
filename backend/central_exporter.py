"""DB host: materialize analysis JSON and macro/micro directory indexes."""
import json
import hashlib
import os
import time
from pathlib import Path
from urllib.parse import quote
from central_store import Connection


def component(value):
    value=str(value or '_unknown')
    encoded=quote(value,safe='.')
    if len(encoded)>200:encoded=encoded[:160]+'~'+hashlib.sha256(value.encode()).hexdigest()[:32]
    return encoded.replace('.', '%2E') if encoded in ('.','..') else encoded


def index_paths(payload):
    event=payload['event']; parsed=event.get('time')
    from datetime import datetime,timezone
    try:
        instant=datetime.fromisoformat(parsed.replace('Z','+00:00'))
        if instant.tzinfo is None:instant=instant.replace(tzinfo=timezone.utc)
        parts=instant.astimezone(timezone.utc).strftime('%Y/%m/%d/%H')
    except (ValueError,TypeError,AttributeError):parts='unknown/00/00/00'
    name=str(int(event['id']))+'.json'
    host=component(event.get('host_ip'))
    # Hybrid index: host IP at the top; nested anchor names/values below.
    paths=[host+'/anchors/src/'+component(event.get('src_ip'))+'/dst/'+component(event.get('dst_ip'))+
           '/user/'+component(event.get('user'))+'/time/'+parts+'/'+name,
           host+'/micro/src/'+component(event.get('src_ip'))+'/'+parts+'/'+name,
           host+'/micro/event/'+component(event.get('event'))+'/'+parts+'/'+name]
    score=event['risk_summary']['total_score']
    level='critical' if score>=120 else 'high' if score>=90 else 'medium' if score>=60 else 'low'
    paths.append(host+'/micro/risk/'+level+'/'+parts+'/'+name)
    for hit in event.get('detections',[]):
        paths.append(host+'/micro/rule/'+str(int(hit['rule_id']))+'/'+parts+'/'+name)
    return list(dict.fromkeys(paths))


def target(root, relative):
    root=root.resolve()
    path=root/relative
    resolved=path.resolve()
    if not resolved.is_relative_to(root):
        raise ValueError('Index path outside archive root')
    # Deny even in-root symlinks: all managed directories are real directories.
    current=path
    while current!=root:
        if current.is_symlink():raise ValueError('Symlink in index path')
        current=current.parent
    return path


def materialize(root,payload,previous=()):
    paths=index_paths(payload)
    canonical=target(root,paths[0]);canonical.parent.mkdir(parents=True,exist_ok=True)
    temporary=canonical.with_suffix('.json.tmp')
    data=json.dumps(payload,ensure_ascii=False,sort_keys=True,separators=(',',':')).encode()
    with open(temporary,'wb') as stream:
        stream.write(data);stream.flush();os.fsync(stream.fileno())
    temporary.chmod(0o640);temporary.replace(canonical)
    for relative in paths[1:]:
        linked=target(root,relative);linked.parent.mkdir(parents=True,exist_ok=True)
        temporary=linked.with_suffix('.json.link')
        if temporary.exists():temporary.unlink()
        os.link(canonical,temporary);temporary.replace(linked)
    for relative in set(previous)-set(paths):
        old=target(root,relative)
        if old.exists():old.unlink()
    event=payload['event']
    folder=target(root,component(event.get('host_ip'))+'/correlations/'+str(int(event['id'])))
    folder.mkdir(parents=True,exist_ok=True)
    tuples=[]
    for row in payload.get('similar',[]):
        tuples.append(json.dumps([int(event['id']),int(row['id']),row['similar_score'],row['seconds']],separators=(',',':')))
    # One JSON array tuple per TXT line avoids delimiter ambiguity and is easy to parse.
    for name,content in [('similar-tuples.txt','\n'.join(tuples)+('\n' if tuples else '')),
                         ('position.txt',paths[0]+'\n')]:
        destination=folder/name;temporary=destination.with_suffix('.txt.tmp')
        with open(temporary,'w',encoding='utf-8',newline='\n') as stream:
            stream.write(content);stream.flush();os.fsync(stream.fileno())
        temporary.chmod(0o640);temporary.replace(destination)
    return paths


def export_batch(root,limit=100):
    connection=Connection()
    try:
        rows=connection.execute('SELECT * FROM analysis_results WHERE exported_revision<revision ORDER BY event_id DESC LIMIT ?',(limit,)).fetchall()
        for row in rows:
            old=connection.execute('SELECT paths_json FROM analysis_export_paths WHERE event_id=?',(row['event_id'],)).fetchone()
            paths=materialize(root,json.loads(row['payload_json']),json.loads(old['paths_json']) if old else ())
            connection.execute('INSERT INTO analysis_export_paths(event_id,paths_json) VALUES(?,?) '
                'ON DUPLICATE KEY UPDATE paths_json=VALUES(paths_json)',(row['event_id'],json.dumps(paths)))
            # Concurrent newer analysis stays pending; never mark a newer revision exported.
            connection.execute('UPDATE analysis_results SET exported_revision=? WHERE event_id=? AND revision=?',
                               (row['revision'],row['event_id'],row['revision']))
            connection.commit()
        return len(rows)
    finally:
        connection.close()


if __name__=='__main__':
    archive=Path(os.environ.get('SOC_ARCHIVE_ROOT','/var/lib/malsonsa/index'))
    archive.mkdir(parents=True,exist_ok=True)
    while True:
        try:
            if not export_batch(archive):time.sleep(2)
        except Exception as exc:
            print('[EXPORT] retry after '+type(exc).__name__,flush=True);time.sleep(5)
