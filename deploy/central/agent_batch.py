#!/usr/bin/env python3
"""Durable agent-local omprog queue, flushed by a timer or restricted SSH command."""
import argparse
import json
from pathlib import Path
import socket
import sqlite3
import sys
import time


def database(path):
    connection = sqlite3.connect(str(path), timeout=30)
    connection.execute('PRAGMA journal_mode=WAL')
    connection.execute('PRAGMA synchronous=FULL')
    connection.execute('CREATE TABLE IF NOT EXISTS pending(id INTEGER PRIMARY KEY AUTOINCREMENT, line BLOB NOT NULL)')
    connection.commit()
    return connection


def enqueue(path, source, reply):
    connection = database(path)
    try:
        reply.write('OK\n'); reply.flush()  # omprog startup confirmation
        for line in source:
            connection.execute('INSERT INTO pending(line) VALUES(?)', (line,))
            connection.commit()  # acknowledge only after durable local persistence
            reply.write('OK\n'); reply.flush()
    finally:
        connection.close()


def send_pending(path, host, port=514, rate=262144):
    import fcntl
    with open(str(path)+'.flush.lock', 'a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        connection = database(path)
        sent = 0
        try:
            last = connection.execute('SELECT MAX(id) FROM pending').fetchone()[0]
            if last is not None:
                with socket.create_connection((host, port), timeout=10) as stream:
                    stream.settimeout(10)
                    while True:
                        rows = connection.execute('SELECT id,line FROM pending WHERE id<=? ORDER BY id LIMIT 64', (last,)).fetchall()
                        if not rows:
                            break
                        payload = b''.join(bytes(row[1]) for row in rows)
                        stream.sendall(payload)
                        # TCP acceptance is not a MariaDB commit acknowledgment (same as omfwd).
                        connection.execute('DELETE FROM pending WHERE id<=?', (rows[-1][0],))
                        connection.commit()
                        sent += len(rows)
                        time.sleep(len(payload)/rate)
            remaining = connection.execute('SELECT COUNT(*) FROM pending').fetchone()[0]
            return {'sent': sent, 'remaining': remaining}
        finally:
            connection.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('mode', choices=['enqueue', 'flush'])
    parser.add_argument('--database', default='/var/lib/rsyslog/malsonsa-agent/pending.db')
    parser.add_argument('--target')
    args = parser.parse_args()
    path = Path(args.database)
    if args.mode == 'enqueue':
        enqueue(path, sys.stdin.buffer, sys.stdout)
    else:
        if not args.target:
            parser.error('--target is required for flush')
        print(json.dumps(send_pending(path, args.target)), flush=True)


if __name__ == '__main__':
    main()
