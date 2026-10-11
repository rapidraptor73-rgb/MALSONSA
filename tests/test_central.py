"""Central storage dialect, hybrid archive, and optional real MariaDB integration."""
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

BACKEND=Path(__file__).resolve().parents[1]/'backend'
sys.path.insert(0,str(BACKEND))
from central_store import Connection, julian, provision, translate
from central_exporter import component, index_paths, materialize, target


class CentralIndexTests(unittest.TestCase):
    def test_long_anchor_names_remain_distinct_and_bounded(self):
        first=component('a'*255+'one');second=component('a'*255+'two')
        self.assertNotEqual(first,second)
        self.assertLessEqual(len(first),200)
        self.assertNotIn('/',component('../escape'))
    def test_time_parameters_are_converted_at_their_own_positions(self):
        sql,args=translate('SELECT * FROM events WHERE host_ip=? AND julianday(time)>=julianday(?) AND id<=?',
                           ['192.0.2.1','2026-10-11T09:00:00+09:00',7])
        self.assertIn('time_jd>=%s',sql)
        self.assertEqual(args,['192.0.2.1',julian('2026-10-11T00:00:00Z'),7])
        self.assertIsNone(julian('broken'))

    def test_hybrid_anchor_paths_tuples_and_revision_replacement(self):
        payload={'event':{'id':42,'host_ip':'192.0.2.10','src_ip':'../../escape',
            'dst_ip':'192.0.2.10','user':'../admin','time':'2026-10-11T09:00:00+09:00',
            'event':'AUTH_FAILURE','risk_summary':{'total_score':155},'detections':[{'rule_id':8}]},
            'similar':[{'id':43,'similar_score':135,'seconds':12}]}
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            paths=materialize(root,payload)
            self.assertTrue(paths[0].startswith('192.0.2.10/anchors/src/'))
            self.assertIn('/dst/192.0.2.10/user/',paths[0])
            self.assertIn('/time/2026/10/11/00/',paths[0])
            folder=root/'192.0.2.10/correlations/42'
            self.assertEqual((folder/'position.txt').read_text().strip(),paths[0])
            self.assertEqual(json.loads((folder/'similar-tuples.txt').read_text()),[42,43,135,12])
            self.assertEqual((root/paths[0]).stat().st_ino,(root/paths[1]).stat().st_ino)
            payload['event']['risk_summary']['total_score']=20
            payload['event']['detections']=[]
            newer=materialize(root,payload,paths)
            self.assertFalse((root/next(p for p in paths if '/rule/' in p)).exists())
            self.assertEqual(json.loads((root/newer[1]).read_text())['event']['risk_summary']['total_score'],20)
            with self.assertRaises(ValueError):target(root,'../escape')


@unittest.skipUnless(os.environ.get('SOC_MARIADB_TEST_CONFIG'),'isolated MariaDB configuration not supplied')
class MariaDBIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.config=json.loads(os.environ['SOC_MARIADB_TEST_CONFIG'])
        self.config.setdefault('archive_token','integration-only')
        self.config.setdefault('archive_url','http://127.0.0.1:8011')
        if not self.config['database'].endswith('_test'):
            raise RuntimeError('Integration tests require a disposable database ending in _test')
        provision(self.config)
        c=Connection(self.config)
        try:
            for table in ('analysis_rule_index','analysis_export_paths','analysis_results','soc_bookmarks',
                          'soc_holds','anchors','detection_rules','monitored_hosts','events','raw_logs'):
                c.execute('DELETE FROM '+table)
            c.commit()
        finally:c.close()
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        config_path=Path(self.temp.name)/'connection.json';config_path.write_text(json.dumps(self.config))
        self.env=patch.dict(os.environ,{'SOC_CENTRAL_CONFIG':str(config_path),'SOC_DISABLE_INGESTOR':'1',
                                       'SOC_STATE_DIR':self.temp.name,'SOC_ARCHIVE_ROOT':str(Path(self.temp.name)/'index')})
        self.env.start();self.addCleanup(self.env.stop)
        spec=importlib.util.spec_from_file_location('central_test_app',BACKEND/'app.py')
        self.module=importlib.util.module_from_spec(spec);spec.loader.exec_module(self.module)
        self.client=self.module.app.test_client()
        c=Connection()
        try:
            fields=['time','host_ip','hostname','src_ip','dst_ip','event','user','program','facility','severity','mitre','score','message','raw_line']
            records=[]
            for n in range(2):
                event=self.module.parse_rsyslog_line(f'2026-10-11T00:0{n}:00Z|agent|192.0.2.10|authpriv|warning|sshd|failed password user=admin src=198.51.100.20')
                records.append([event[field] for field in fields]+[julian(event['time'])])
            c.executemany('INSERT INTO events('+','.join(fields+['time_jd'])+') VALUES('+','.join('?' for _ in range(len(fields)+1))+')',records)
            c.commit()
        finally:c.close()

    def test_existing_ui_apis_use_central_storage_and_indexes(self):
        events=self.client.get('/api/events?include_risk=1').json['events']
        self.assertEqual(len(events),2)
        self.assertEqual(events[0]['risk_summary']['total_score'],155)
        event_id=events[0]['id']
        self.assertEqual(self.client.get('/api/health').json['storage'],'central-mariadb')
        self.assertEqual(self.client.post('/api/bookmarks/'+str(event_id)).status_code,200)
        self.assertEqual(self.client.get('/api/bookmarks?q=FAILED').json['total'],1)
        self.client.delete('/api/bookmarks/'+str(event_id))
        source=self.client.get('/api/source-ips?seconds=0').json['sources'][0]
        self.assertEqual(source['event_count'],2)
        with patch.object(self.module._central_module,'read_archive',return_value=None):
            self.assertEqual(self.client.post('/api/anchors/'+str(event_id)+'/hold').status_code,200)
        host=self.client.post('/api/hosts',json={'name':'agent','ip':'192.0.2.10'}).json['id']
        rule={'host_id':host,'name':'SSH repeated','attack':'SSH brute force','reason':'Repeated failure',
              'points':40,'conditions':[{'field':'event','operator':'equals','value':'AUTH_FAILURE'}],
              'min_hits':2,'window_seconds':300,'group_by':'src_ip'}
        response=self.client.post('/api/rules',json=rule)
        self.assertEqual(response.status_code,201,response.json)
        self.assertGreaterEqual(self.client.get('/api/events').json['events'][0]['detection_score'],40)
        self.assertEqual(self.client.get('/api/analysis').status_code,200)

    def test_raw_recovery_memory_analysis_export_and_hold_directory_lookup(self):
        c=Connection()
        try:
            raw=c.execute('INSERT INTO raw_logs(event_time,host_ip,hostname,facility,severity,program,message,raw_line) VALUES(?,?,?,?,?,?,?,?)',
                ('2026-10-11T00:02:00Z','192.0.2.10','agent','authpriv','warning','sshd',
                 "failed password user=admin src=198.51.100.20 quote='",'original RFC5424 text')).lastrowid
            c.commit()
        finally:c.close()
        spec=importlib.util.spec_from_file_location('central_worker_test',BACKEND/'central_worker.py')
        worker=importlib.util.module_from_spec(spec)
        with patch.dict(sys.modules,{'app':self.module}):spec.loader.exec_module(worker)
        self.assertEqual(worker.consume_raw(),1)
        self.assertEqual(worker.consume_raw(),0)
        self.assertEqual(worker.analyze_batch(),3)
        c=Connection()
        try:
            record=c.execute('SELECT * FROM events WHERE raw_id=?',(raw,)).fetchone()
            self.assertEqual(record['raw_line'],'original RFC5424 text')
            anchor_id=record['id']
        finally:c.close()
        from central_exporter import export_batch
        self.assertEqual(export_batch(Path(os.environ['SOC_ARCHIVE_ROOT'])),3)
        self.assertEqual(export_batch(Path(os.environ['SOC_ARCHIVE_ROOT'])),0)
        spec=importlib.util.spec_from_file_location('central_archive_test',BACKEND/'central_archive.py')
        archive=importlib.util.module_from_spec(spec);spec.loader.exec_module(archive)
        client=archive.app.test_client()
        self.assertEqual(client.get('/anchor/'+str(anchor_id)).status_code,401)
        response=client.get('/anchor/'+str(anchor_id),headers={'Authorization':'Bearer integration-only'})
        self.assertEqual(response.status_code,200,response.json)
        stored=response.json
        self.assertEqual(len(stored['tuples']),2)
        self.assertEqual(stored['analysis']['event']['id'],anchor_id)
        with patch.object(self.module._central_module,'read_archive',return_value=stored):
            held=self.client.post('/api/anchors/'+str(anchor_id)+'/hold')
            self.assertEqual(held.json['archive']['status'],'ready')
            similar=self.client.get('/api/similar/'+str(anchor_id))
            self.assertEqual(similar.json['lookup'],'position-txt')
            self.assertEqual(len(similar.json['similar']),2)
            c=Connection()
            try:
                other=self.module.parse_rsyslog_line('2026-10-11T00:03:00Z|other|192.0.2.11|authpriv|warning|sshd|failed password user=admin src=198.51.100.20')
                self.module._central_module.insert_normalized(c,other);c.commit()
            finally:c.close()
            self.assertEqual(self.client.get('/api/similar/'+str(anchor_id)).json.get('lookup'),'position-txt')
            c=Connection()
            try:
                unrelated=self.module.parse_rsyslog_line('2026-10-11T00:03:00Z|agent|192.0.2.10|daemon|info|filebeat|harvester started')
                self.module._central_module.insert_normalized(c,unrelated);c.commit()
            finally:c.close()
            self.assertEqual(self.client.get('/api/similar/'+str(anchor_id)).json.get('lookup'),'position-txt')
            # New data invalidates this snapshot and forces current in-memory analysis.
            c=Connection()
            try:
                event=self.module.parse_rsyslog_line('2026-10-11T00:03:00Z|agent|192.0.2.10|authpriv|warning|sshd|failed password user=admin src=198.51.100.20')
                self.module._central_module.insert_normalized(c,event);c.commit()
            finally:c.close()
            self.assertNotEqual(self.client.get('/api/similar/'+str(anchor_id)).json.get('lookup'),'position-txt')

    def test_burst_raw_processing_preserves_every_identity_across_batches(self):
        c=Connection()
        try:
            records=[('2026-10-11T00:04:00Z','192.0.2.10','agent','daemon','info','filebeat',
                      'harvester probe '+str(index),'raw probe '+str(index)) for index in range(50)]
            c.executemany('INSERT INTO raw_logs(event_time,host_ip,hostname,facility,severity,program,message,raw_line) VALUES(?,?,?,?,?,?,?,?)',records)
            c.commit()
        finally:c.close()
        spec=importlib.util.spec_from_file_location('central_worker_burst',BACKEND/'central_worker.py')
        worker=importlib.util.module_from_spec(spec)
        with patch.dict(sys.modules,{'app':self.module}):spec.loader.exec_module(worker)
        self.assertEqual([worker.consume_raw(20) for _ in range(4)],[20,20,10,0])
        c=Connection()
        try:
            self.assertEqual(c.execute('SELECT COUNT(*) FROM events WHERE raw_id IS NOT NULL').fetchone()[0],50)
            self.assertEqual(c.execute('SELECT COUNT(*) FROM raw_logs r JOIN events e ON e.id=r.normalized_id AND e.raw_id=r.id').fetchone()[0],50)
        finally:c.close()
        self.assertEqual(worker.analyze_batch(),52)
