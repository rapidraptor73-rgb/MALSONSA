"""Exercise the imported production API with synthetic data in a temporary DB."""
import importlib.util
import os
import sqlite3
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


class SiemIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        env = {
            'SOC_DB_PATH': str(Path(self.temp.name) / 'test.db'),
            'SOC_STATE_DIR': self.temp.name,
            'SOC_RSYSLOG_LOG': str(Path(self.temp.name) / 'synthetic.log'),
        }
        spec = importlib.util.spec_from_file_location(
            'siem_test_app', Path(__file__).resolve().parents[1] / 'backend' / 'app.py'
        )
        self.module = importlib.util.module_from_spec(spec)
        # Avoid production directory creation and a background ingestion thread.
        # The temporary state directory already exists; all DB operations are real.
        with patch.dict(os.environ, env), patch('os.makedirs'), patch('threading.Thread.start'):
            spec.loader.exec_module(self.module)
        self.module.APP_DIR = self.temp.name
        self.client = self.module.app.test_client()

    def add_event(self, time='2026-10-10T15:03:46.082249+09:00', host='192.0.2.10'):
        line = (f'{time}|test-host|{host}|authpriv|warning|sshd|'
                'Failed password for analyst from 198.51.100.20 port 12345 ssh2')
        event = self.module.parse_rsyslog_line(line)
        self.module.insert_event(event)
        return event

    def test_ingest_search_and_microsecond_timestamp(self):
        event = self.add_event()
        self.assertEqual(event['src_ip'], '198.51.100.20')
        self.assertEqual(event['dst_ip'], '192.0.2.10')
        self.assertEqual(event['event'], 'AUTH_FAILURE')
        self.assertEqual(event['mitre'], 'T1110')
        self.assertEqual(self.module.parse_time(event['time']).microsecond, 82249)
        response = self.client.get('/api/search?field=src_ip&q=198.51.100.20')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.json['events']), 1)
        self.assertEqual(self.client.get('/api/search?field=unsupported').status_code, 400)

    def test_hold_similar_host_scope_and_unhold(self):
        self.add_event()
        self.add_event('2026-10-10T15:04:46.082249+09:00')
        self.add_event('2026-10-10T15:04:46.082249+09:00', '192.0.2.11')
        self.assertEqual(self.client.post('/api/anchors/1/hold').status_code, 200)
        self.assertEqual(len(self.client.get('/api/anchors').json['anchors']), 1)
        similar = self.client.get('/api/similar/1?host_ip=192.0.2.10').json['similar']
        self.assertEqual([event['id'] for event in similar], [2])
        self.assertGreaterEqual(similar[0]['similar_score'], 60)
        self.client.delete('/api/anchors/1')
        self.assertEqual(self.client.get('/api/anchors').json['anchors'], [])
        self.assertEqual(self.client.post('/api/anchors/999/hold').status_code, 404)

    def test_host_registration_and_duplicate_validation(self):
        response = self.client.post('/api/hosts', json={'name': 'test-host', 'ip': '192.0.2.10'})
        self.assertEqual(response.status_code, 201)
        self.assertEqual(self.client.post('/api/hosts', json={'name': 'duplicate', 'ip': '192.0.2.10'}).status_code, 409)
        self.assertEqual(self.client.post('/api/hosts', json={'name': 'bad', 'ip': 'invalid'}).status_code, 400)
        self.add_event()
        self.assertEqual(self.client.get('/api/hosts').json['hosts'][0]['event_count'], 1)

    def rule(self, agent_id, **changes):
        data = dict(host_id=agent_id, name='SSH 반복 실패', attack='SSH 무차별 대입',
                    points=120, reason='같은 출발지에서 인증 실패가 반복되어 암호 추측을 의심합니다.',
                    conditions=[dict(field='event',operator='equals',value='AUTH_FAILURE')],
                    min_hits=2, window_seconds=300, group_by='src_ip', enabled=True)
        data.update(changes)
        return data

    def test_agent_rule_counts_past_hits_and_separates_hosts(self):
        host=self.client.post('/api/hosts',json={'name':'agent','ip':'192.0.2.10'}).json['id']
        result=self.client.post('/api/rules',json=self.rule(host))
        self.assertEqual(result.status_code,201)
        self.add_event('2026-10-10T15:00:00+09:00')
        self.add_event('2026-10-10T15:01:00+09:00','192.0.2.11')
        self.add_event('2026-10-10T15:02:00+09:00')
        self.add_event('2026-10-10T15:12:00+09:00')
        events={e['id']:e for e in self.client.get('/api/events').json['events']}
        self.assertEqual([events[i]['detection_score'] for i in range(1,5)],[0,0,120,0])
        detection=events[3]['detections'][0]
        self.assertEqual(detection['hits'],2)
        self.assertEqual(detection['evidence'][0]['actual'],'AUTH_FAILURE')
        self.assertEqual(self.client.post('/api/rules/preview',json={'rule':self.rule(host),'event_id':3}).json['matched'],True)
        self.assertEqual(self.client.post('/api/rules/preview',json={'rule':self.rule(host),'event_id':1}).json['matched'],False)
        similar=self.client.get('/api/similar/1?min_score=0').json['similar']
        self.assertEqual(next(e for e in similar if e['id']==3)['detection_score'],120)

    def test_rule_crud_disabled_host_and_retrospective_evaluation(self):
        host=self.client.post('/api/hosts',json={'name':'agent','ip':'192.0.2.10'}).json['id']
        self.add_event()
        rule_id=self.client.post('/api/rules',json=self.rule(host,min_hits=1)).json['id']
        self.assertEqual(self.client.get('/api/events').json['events'][0]['detection_score'],120)
        self.assertEqual(self.client.delete('/api/hosts/'+str(host)).status_code,409)
        self.assertEqual(self.client.patch('/api/rules/'+str(rule_id),json={'points':90}).status_code,200)
        self.assertEqual(self.client.get('/api/search?q=198.51.100.20').json['events'][0]['detection_score'],90)
        self.client.patch('/api/hosts/'+str(host),json={'enabled':False})
        self.assertEqual(self.client.get('/api/events').json['events'][0]['detection_score'],0)
        self.client.patch('/api/hosts/'+str(host),json={'enabled':True})
        self.client.patch('/api/rules/'+str(rule_id),json={'enabled':False})
        self.assertEqual(self.client.get('/api/events').json['events'][0]['detection_score'],0)
        self.assertEqual(self.client.get('/api/rules').json['rules'][0]['reason'],self.rule(host)['reason'])
        self.assertEqual(self.client.delete('/api/rules/'+str(rule_id)).status_code,200)
        self.assertEqual(self.client.delete('/api/hosts/'+str(host)).status_code,200)

    def test_rule_validation_and_literal_conditions(self):
        host=self.client.post('/api/hosts',json={'name':'agent','ip':'192.0.2.10'}).json['id']
        for changes in [{'points':-1},{'points':True},{'host_id':999},{'conditions':[]},
                        {'conditions':[dict(field='message); DROP TABLE events;',operator='contains',value='x')]},
                        {'conditions':[dict(field='message',operator='regex',value='.*')]}]:
            with self.subTest(changes=changes):
                self.assertEqual(self.client.post('/api/rules',json=self.rule(host,**changes)).status_code,400)
        self.add_event()
        self.client.post('/api/rules',json=self.rule(host,min_hits=1,conditions=[dict(field='message',operator='contains',value='%')]))
        self.assertEqual(self.client.get('/api/events').json['events'][0]['detection_score'],0)
        self.client.post('/api/rules',json=self.rule(host,min_hits=1,conditions=[dict(field='message',operator='contains',value='FAILED PASSWORD')]))
        self.assertEqual(self.client.get('/api/events').json['events'][0]['detection_score'],120)

    def test_multiple_rule_points_and_any_condition(self):
        host=self.client.post('/api/hosts',json={'name':'agent','ip':'192.0.2.10'}).json['id']
        self.add_event()
        self.client.post('/api/rules',json=self.rule(host,min_hits=1,points=60))
        self.client.post('/api/rules',json=self.rule(host,min_hits=1,points=30,match_mode='any',conditions=[dict(field='program',operator='equals',value='sudo'),dict(field='user',operator='equals',value='analyst')]))
        event=self.client.get('/api/events').json['events'][0]
        self.assertEqual(event['detection_score'],90)
        self.assertEqual(len(event['detections']),2)
        self.assertEqual(len(event['detections'][1]['evidence']),1)

    def test_existing_schema_required_timestamps_and_history(self):
        with sqlite3.connect(self.module.DB_PATH) as c:
            c.execute('DROP TABLE events')
            c.execute('''CREATE TABLE events(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_time TEXT NOT NULL, event_epoch INTEGER NOT NULL,
                host TEXT, event_type TEXT, message TEXT, raw TEXT,
                src_ip TEXT, dst_ip TEXT, user TEXT, program TEXT,
                mitre TEXT, payload_json TEXT)''')
            c.execute('''INSERT INTO events(event_time,event_epoch,event_type,message)
                VALUES(?,?,?,?)''', ('2026-10-10T15:03:46.082249+09:00', 1791612226,
                                     'AUTH_FAILURE', 'existing event'))
        c.close()
        self.module.ensure_schema()
        self.add_event('2026-10-10T15:04:46.082249+09:00')
        events = self.client.get('/api/events').json['events']
        self.assertEqual(len(events), 2)
        latest, existing = events
        self.assertEqual(existing['message'], 'existing event')
        self.assertEqual(existing['time'], existing['event_time'])
        self.assertEqual(latest['time'], latest['event_time'])
        self.assertEqual(latest['event_epoch'], int(self.module.parse_time(latest['time']).timestamp()))
        self.assertEqual(latest['event_type'], 'AUTH_FAILURE')
        self.assertEqual(latest['host_ip'], '192.0.2.10')
        self.assertIsNotNone(self.module.parse_time(self.client.get('/api/events').json['server_time']).tzinfo)
        self.assertEqual(self.client.post('/api/anchors/1/hold').status_code, 200)
        similar = self.client.get('/api/similar/1?min_score=40').json['similar']
        self.assertEqual([event['id'] for event in similar], [2])

    def test_offset_restarts_for_rotated_log_even_if_larger(self):
        log=Path(self.module.LOG_PATH)
        log.write_text('old line\n',encoding='utf-8')
        self.module.save_offset(4)
        self.assertEqual(self.module.load_offset(),4)
        log.rename(log.with_suffix('.old'))
        log.write_text('new log content is larger than the old offset\n',encoding='utf-8')
        self.assertEqual(self.module.load_offset(),0)

    def test_configurable_host_mapping(self):
        self.module.IP_MAP={}
        line='2026-10-10T17:40:00+09:00|test|172.16.16.141|user|notice|test|dst=172.16.16.141'
        self.assertEqual(self.module.parse_rsyslog_line(line)['host_ip'],'172.16.16.141')
        self.module.IP_MAP={'172.16.16.141':'192.0.2.10'}
        self.assertEqual(self.module.parse_rsyslog_line(line)['dst_ip'],'192.0.2.10')


if __name__ == '__main__':
    unittest.main()
