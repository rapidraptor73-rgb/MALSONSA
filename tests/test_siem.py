"""Exercise the imported production API with synthetic data in a temporary DB."""
import importlib.util
import os
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


if __name__ == '__main__':
    unittest.main()
