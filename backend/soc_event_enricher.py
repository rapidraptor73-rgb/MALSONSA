#!/usr/bin/env python3
import os
import re
import sqlite3
import time
import signal
import sys

DB_PATH = os.environ.get("SOC_DB_PATH", "/opt/soc/backend/siem.db")
POLL_SECONDS = float(os.environ.get("SOC_ENRICHER_POLL", "1"))

SRC_RE = re.compile(r'(?<![A-Za-z0-9_])src=((?:\d{1,3}\.){3}\d{1,3})(?![\d.])', re.I)
DST_RE = re.compile(r'(?<![A-Za-z0-9_])dst=((?:\d{1,3}\.){3}\d{1,3})(?![\d.])', re.I)
USER_RE = re.compile(r'(?<![A-Za-z0-9_])user=([A-Za-z0-9_.@\\-]+)', re.I)

STOP = False

def on_signal(signum, frame):
    global STOP
    STOP = True

signal.signal(signal.SIGTERM, on_signal)
signal.signal(signal.SIGINT, on_signal)

def connect():
    c = sqlite3.connect(DB_PATH, timeout=20)
    c.row_factory = sqlite3.Row
    return c

def columns(c, table):
    return [r["name"] for r in c.execute(f"PRAGMA table_info({table})").fetchall()]

def detect_schema(c):
    cols = set(columns(c, "events"))
    if not cols:
        raise RuntimeError("events table not found")

    id_col = "id" if "id" in cols else ("log_id" if "log_id" in cols else None)
    if not id_col:
        raise RuntimeError("events table has no id/log_id column")

    text_cols = [x for x in ("message", "raw_message", "raw_line") if x in cols]
    if not text_cols:
        raise RuntimeError("events table has no message/raw_message/raw_line column")

    required = []
    for col in ("src_ip", "dst_ip", "user"):
        if col not in cols:
            required.append(col)

    # Add missing structured columns without recreating the table.
    for col in required:
        c.execute(f"ALTER TABLE events ADD COLUMN {col} TEXT")

    c.commit()
    cols = set(columns(c, "events"))
    return id_col, text_cols, cols

def pick_text(row, text_cols):
    # Prefer a field that actually contains src=/dst=.
    for col in text_cols:
        v = row[col]
        if v and ("src=" in str(v).lower() or "dst=" in str(v).lower()):
            return str(v)
    for col in text_cols:
        v = row[col]
        if v:
            return str(v)
    return ""

def parse(text):
    src = None
    dst = None
    user = None

    m = SRC_RE.search(text)
    if m:
        src = m.group(1)

    m = DST_RE.search(text)
    if m:
        dst = m.group(1)

    m = USER_RE.search(text)
    if m:
        user = m.group(1)

    return src, dst, user

def process_rows(c, where_sql="", params=()):
    id_col, text_cols, cols = detect_schema(c)
    select_cols = [id_col] + text_cols + [x for x in ("src_ip","dst_ip","user") if x in cols]
    sql = "SELECT " + ",".join(select_cols) + " FROM events"
    if where_sql:
        sql += " WHERE " + where_sql
    sql += f" ORDER BY {id_col} ASC"

    changed = 0
    last_id = 0

    rows = c.execute(sql, params).fetchall()
    for row in rows:
        event_id = row[id_col]
        last_id = max(last_id, int(event_id))
        text = pick_text(row, text_cols)
        if not text:
            continue

        src, dst, user = parse(text)
        updates = []
        values = []

        if src and row["src_ip"] != src:
            updates.append("src_ip=?")
            values.append(src)

        if dst and row["dst_ip"] != dst:
            updates.append("dst_ip=?")
            values.append(dst)

        if user and row["user"] != user:
            updates.append("user=?")
            values.append(user)

        if updates:
            values.append(event_id)
            c.execute(
                f"UPDATE events SET {', '.join(updates)} WHERE {id_col}=?",
                values
            )
            changed += 1

    c.commit()
    return changed, last_id

def backfill():
    c = connect()
    try:
        changed, last_id = process_rows(c)
        print(f"[BACKFILL] updated={changed} last_id={last_id}", flush=True)
        return last_id
    finally:
        c.close()

def run():
    if not os.path.exists(DB_PATH):
        print(f"[FAIL] DB not found: {DB_PATH}", flush=True)
        return 1

    last_id = backfill()

    while not STOP:
        try:
            c = connect()
            try:
                id_col, _, _ = detect_schema(c)
                changed, new_last = process_rows(c, f"{id_col}>?", (last_id,))
                if new_last > last_id:
                    last_id = new_last
                if changed:
                    print(f"[LIVE] updated={changed} last_id={last_id}", flush=True)
            finally:
                c.close()
        except Exception as e:
            print(f"[ERROR] {e}", flush=True)

        time.sleep(POLL_SECONDS)

    return 0

if __name__ == "__main__":
    sys.exit(run())
