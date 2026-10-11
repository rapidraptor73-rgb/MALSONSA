"""Local worker wakeup and a fixed, restricted agent flush command."""
import json
import os
import socket
import subprocess
import time
from pathlib import Path

SOCKET_PATH = os.environ.get('SOC_COLLECTION_SOCKET', '/run/soc-central-worker/refresh.sock')
INTERVAL = 300


def seconds_until_cycle(offset=5, now=None):
    """Align automatic work after the agent's five-minute wall-clock flush."""
    return INTERVAL - (((time.time() if now is None else now)-offset) % INTERVAL)


def notify_worker():
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as client:
            client.sendto(b'refresh', SOCKET_PATH)
        return True
    except (AttributeError, OSError):
        return False


def worker_socket():
    path = Path(SOCKET_PATH)
    # The service's RuntimeDirectory owns this socket; no monitored log is stored here.
    if not path.parent.is_dir():
        return None
    if path.exists():
        path.unlink()
    server = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    server.bind(str(path))
    path.chmod(0o600)
    return server


def flush_agent():
    config_path = os.environ.get('SOC_AGENT_FLUSH_CONFIG', '/etc/malsonsa/agent-flush.json')
    if not Path(config_path).exists():
        return {'status': 'not-configured'}
    config = json.loads(Path(config_path).read_text(encoding='utf-8'))
    # Inputs come only from the administrator-owned file, never HTTP request parameters.
    command = ['/usr/bin/ssh', '-T', '-i', config['key'], '-o', 'BatchMode=yes',
               '-o', 'StrictHostKeyChecking=yes', '-o', 'UserKnownHostsFile='+config['known_hosts'],
               '-o', 'ConnectTimeout=5', '-o', 'IdentitiesOnly=yes',
               'root@'+config['host'], 'flush']
    try:
        result = subprocess.run(command, capture_output=True, timeout=45, check=True)
        response = json.loads(result.stdout)
        return {'status': 'sent', 'sent': int(response['sent']), 'remaining': int(response['remaining'])}
    except (OSError, ValueError, KeyError, subprocess.SubprocessError):
        # Never expose credentials, SSH arguments, stderr or raw messages to the browser.
        return {'status': 'failed'}
