import importlib.util
import io
import os
from pathlib import Path
import socket
import sys
import tempfile
import types
import unittest
from unittest.mock import MagicMock, patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'backend'))
import collection_control


def load_agent():
    spec=importlib.util.spec_from_file_location('batch_agent',ROOT/'deploy/central/agent_batch.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module


class CollectionTests(unittest.TestCase):
    def test_five_minute_phase_and_manual_wakeup(self):
        self.assertEqual(collection_control.seconds_until_cycle(now=300),5)
        self.assertEqual(collection_control.seconds_until_cycle(now=305),300)
        self.assertEqual(collection_control.seconds_until_cycle(offset=30,now=305),25)
        if not hasattr(socket,'AF_UNIX'):return
        with tempfile.TemporaryDirectory() as temp,patch.object(collection_control,'SOCKET_PATH',str(Path(temp)/'wake.sock')):
            server=collection_control.worker_socket()
            try:
                self.assertTrue(collection_control.notify_worker())
                self.assertEqual(server.recv(64),b'refresh')
            finally:server.close()

    def test_agent_acknowledges_after_durable_enqueue_and_recovers_on_failure(self):
        agent=load_agent()
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'pending.db'
            reply=io.StringIO()
            agent.enqueue(path,io.BytesIO(b'<14>first\n<14>second\n'),reply)
            self.assertEqual(reply.getvalue(),'OK\nOK\nOK\n')
            c=agent.database(path)
            self.assertEqual(c.execute('SELECT COUNT(*) FROM pending').fetchone()[0],2);c.close()
            if sys.platform=='win32':return  # the installed agent runs Linux/flock
            with patch.object(agent.socket,'create_connection',side_effect=OSError('offline')):
                with self.assertRaises(OSError):agent.send_pending(path,'192.0.2.1')
            c=agent.database(path)
            self.assertEqual(c.execute('SELECT COUNT(*) FROM pending').fetchone()[0],2);c.close()
            sent=[]
            stream=MagicMock();stream.__enter__.return_value=stream
            stream.sendall.side_effect=sent.append
            with patch.object(agent.socket,'create_connection',return_value=stream):
                self.assertEqual(agent.send_pending(path,'192.0.2.1'),{'sent':2,'remaining':0})
            self.assertEqual(b''.join(sent),b'<14>first\n<14>second\n')

    def test_empty_analysis_never_reads_candidate_pool(self):
        c=MagicMock();c.execute.return_value.fetchall.return_value=[]
        fake=types.SimpleNamespace(db=lambda:c)
        spec=importlib.util.spec_from_file_location('worker_idle_test',ROOT/'backend/central_worker.py')
        worker=importlib.util.module_from_spec(spec)
        with patch.dict(sys.modules,{'app':fake}):spec.loader.exec_module(worker)
        self.assertEqual(worker.analyze_batch(version='test'),0)
        self.assertEqual(c.execute.call_count,1)
        c.close.assert_called_once()

    def test_flush_ssh_uses_fixed_command_and_host_key_verification(self):
        with tempfile.TemporaryDirectory() as temp:
            config=Path(temp)/'control.json'
            config.write_text('{"key":"/key","known_hosts":"/known","host":"192.0.2.1"}')
            result=types.SimpleNamespace(stdout=b'{"sent":4,"remaining":0}')
            with patch.dict(os.environ,{'SOC_AGENT_FLUSH_CONFIG':str(config)}),patch.object(collection_control.subprocess,'run',return_value=result) as run:
                self.assertEqual(collection_control.flush_agent()['sent'],4)
                args=run.call_args[0][0]
                self.assertIn('StrictHostKeyChecking=yes',args)
                self.assertEqual(args[-2:],['root@192.0.2.1','flush'])

