#!/usr/bin/env python3
import os
import re
import json
import time
import sqlite3
import threading
import ipaddress
from datetime import datetime, timezone

from flask import Flask, jsonify, request

APP_DIR = "/opt/soc/backend"
DB_PATH = os.environ.get("SOC_DB_PATH", os.path.join(APP_DIR, "siem.db"))
LOG_PATH = os.environ.get("SOC_RSYSLOG_LOG", "/var/log/soc/all-rsyslog.log")
STATE_DIR = os.environ.get("SOC_STATE_DIR", "/var/lib/soc-siem")
OFFSET_FILE = os.path.join(STATE_DIR, "rsyslog.offset.json")

app = Flask(__name__)

EVENT_MITRE = {
    "AUTH_FAILURE": "T1110",
    "AUTH_SUCCESS": "T1078",
    "PRIVILEGE_USE": "T1548",
    "ACCOUNT_CHANGE": "T1136",
    "FILE_TRANSFER": "T1105",
    "REGISTRY_CHANGE": "T1112",
    "SCAN": "T1046",
    "MALWARE": "T1204",
    "LOG": "",
}

SUSPICIOUS = {
    "AUTH_FAILURE", "PRIVILEGE_USE", "ACCOUNT_CHANGE",
    "FILE_TRANSFER", "REGISTRY_CHANGE", "SCAN", "MALWARE"
}

IP_KV_RE = re.compile(r'\b(src|dst)=((?:\d{1,3}\.){3}\d{1,3})\b', re.I)
GENERIC_IP_RE = re.compile(r'(?<![\d.])((?:\d{1,3}\.){3}\d{1,3})(?![\d.])')
USER_KV_RE = re.compile(r'\buser=([A-Za-z0-9_.\\@-]+)', re.I)
SSH_FAIL_USER_RE = re.compile(r'failed password for (?:invalid user )?([A-Za-z0-9_.\\@-]+)\s+from\s+((?:\d{1,3}\.){3}\d{1,3})', re.I)
SSH_OK_USER_RE = re.compile(r'accepted (?:password|publickey) for ([A-Za-z0-9_.\\@-]+)\s+from\s+((?:\d{1,3}\.){3}\d{1,3})', re.I)

def now_iso():
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="microseconds")

def db():
    c = sqlite3.connect(DB_PATH, timeout=20)
    c.row_factory = sqlite3.Row
    return c

def table_exists(c, name):
    return c.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
        (name,)
    ).fetchone() is not None

def cols(c, table):
    if not table_exists(c, table):
        return []
    return [r["name"] for r in c.execute(f"PRAGMA table_info({table})").fetchall()]

def ensure_schema():
    os.makedirs(APP_DIR, exist_ok=True)
    os.makedirs(STATE_DIR, exist_ok=True)

    c = db()
    try:
        if not table_exists(c, "events"):
            c.execute("""
            CREATE TABLE events(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                time TEXT NOT NULL,
                host_ip TEXT,
                hostname TEXT,
                src_ip TEXT,
                dst_ip TEXT,
                event TEXT NOT NULL DEFAULT 'LOG',
                user TEXT,
                program TEXT,
                facility TEXT,
                severity TEXT,
                mitre TEXT,
                score INTEGER NOT NULL DEFAULT 0,
                message TEXT NOT NULL,
                raw_line TEXT
            )
            """)
        else:
            wanted = {
                "time": "TEXT",
                "host_ip": "TEXT",
                "hostname": "TEXT",
                "src_ip": "TEXT",
                "dst_ip": "TEXT",
                "event": "TEXT",
                "user": "TEXT",
                "program": "TEXT",
                "facility": "TEXT",
                "severity": "TEXT",
                "mitre": "TEXT",
                "score": "INTEGER NOT NULL DEFAULT 0",
                "message": "TEXT",
                "raw_line": "TEXT",
            }
            existing = set(cols(c, "events"))
            for name, typ in wanted.items():
                if name not in existing:
                    c.execute(f"ALTER TABLE events ADD COLUMN {name} {typ}")

        c.execute("""
        CREATE TABLE IF NOT EXISTS anchors(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id INTEGER NOT NULL UNIQUE,
            held_at TEXT NOT NULL
        )
        """)

        # UI/HOLD compatibility table.
        # Existing projects may have an older anchors schema (e.g. log_id).
        # New HOLD operations use this independent table so old DB data is not broken.
        c.execute("""
        CREATE TABLE IF NOT EXISTS soc_holds(
            event_id INTEGER PRIMARY KEY,
            held_at TEXT NOT NULL
        )
        """)

        c.execute("""
        CREATE TABLE IF NOT EXISTS monitored_hosts(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            ip TEXT NOT NULL UNIQUE,
            os_type TEXT NOT NULL DEFAULT '',
            role TEXT NOT NULL DEFAULT '',
            note TEXT NOT NULL DEFAULT '',
            enabled INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL
        )
        """)

        # Backfill display columns from older event schemas without deleting data.
        event_cols = set(cols(c, "events"))
        if "raw_message" in event_cols and "message" in event_cols:
            c.execute("""
                UPDATE events SET message=raw_message
                WHERE (message IS NULL OR message='') AND raw_message IS NOT NULL
            """)
        if "event_type" in event_cols and "event" in event_cols:
            c.execute("""
                UPDATE events SET event=event_type
                WHERE (event IS NULL OR event='') AND event_type IS NOT NULL
            """)
        for legacy_time in ("event_time", "received_at", "timestamp"):
            if legacy_time in event_cols:
                c.execute(f"""
                    UPDATE events SET time={legacy_time}
                    WHERE (time IS NULL OR time='')
                      AND {legacy_time} IS NOT NULL AND {legacy_time}<>''
                """)

        c.execute("CREATE INDEX IF NOT EXISTS idx_events_time ON events(time)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_events_host_ip ON events(host_ip)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_events_src_ip ON events(src_ip)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_events_dst_ip ON events(dst_ip)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_events_event ON events(event)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_hosts_ip ON monitored_hosts(ip)")
        c.commit()
    finally:
        c.close()

def valid_ip(value):
    if not value:
        return None
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None

def classify(message):
    s = (message or "").lower()
    if any(k in s for k in ("malware", "trojan", "virus", "ransomware", "yara")):
        return "MALWARE"
    if any(k in s for k in ("nmap", "port scan", "syn scan", "scan detected")):
        return "SCAN"
    if any(k in s for k in ("tftp", "wget ", "curl ", "file transfer", "file upload", "scp ")):
        return "FILE_TRANSFER"
    if any(k in s for k in ("registry", "security\\sam", "reg add", "modify registry")):
        return "REGISTRY_CHANGE"
    if any(k in s for k in ("useradd", "adduser", "account created", "new user", "4720", "4732")):
        return "ACCOUNT_CHANGE"
    if any(k in s for k in ("sudo", "runas", "privilege escalation", "uid=0", "administrator group")):
        return "PRIVILEGE_USE"
    if any(k in s for k in ("failed password", "authentication failure", "invalid user", "login failed", "4625")):
        return "AUTH_FAILURE"
    if any(k in s for k in ("accepted password", "accepted publickey", "login successful", "4624")):
        return "AUTH_SUCCESS"
    return "LOG"

def parse_time(value):
    if not value:
        return datetime.now(timezone.utc).astimezone()
    v = value.strip()
    for candidate in (v, v.replace("Z", "+00:00")):
        try:
            return datetime.fromisoformat(candidate)
        except Exception:
            pass
    return datetime.now(timezone.utc).astimezone()

def parse_rsyslog_line(line):
    raw = line.rstrip("\n")

    # New receiver format:
    # time|hostname|fromhost-ip|facility|severity|program|message
    parts = raw.split("|", 6)
    if len(parts) == 7:
        event_time, hostname, host_ip, facility, severity, program, message = parts
    else:
        # Legacy fallback: preserve the line and infer what we can.
        event_time = now_iso()
        hostname = ""
        host_ip = None
        facility = ""
        severity = ""
        program = ""
        message = raw

    host_ip = valid_ip((host_ip or "").strip())
    if host_ip == "172.16.16.141":
        host_ip = "203.230.52.214"
    message = (message or "").strip()

    src_ip = None
    dst_ip = None
    kv = {k.lower(): v for k, v in IP_KV_RE.findall(message)}
    if "src" in kv:
        src_ip = valid_ip(kv["src"])
    if "dst" in kv:
        dst_ip = valid_ip(kv["dst"])

    user = None
    um = USER_KV_RE.search(message)
    if um:
        user = um.group(1)

    if not src_ip:
        m = SSH_FAIL_USER_RE.search(message) or SSH_OK_USER_RE.search(message)
        if m:
            user = user or m.group(1)
            src_ip = valid_ip(m.group(2))

    # For endpoint logs, if destination was not explicitly embedded,
    # the monitored host is the natural destination.
    if dst_ip == "172.16.16.141":
        dst_ip = "203.230.52.214"
    if not dst_ip and host_ip:
        dst_ip = host_ip

    event = classify(message)
    mitre = EVENT_MITRE.get(event, "")

    return {
        "time": event_time.strip() or now_iso(),
        "host_ip": host_ip,
        "hostname": (hostname or "").strip(),
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "event": event,
        "user": user,
        "program": (program or "").strip(),
        "facility": (facility or "").strip(),
        "severity": (severity or "").strip(),
        "mitre": mitre,
        "score": 0,
        "message": message,
        "raw_line": raw,
    }

def insert_event(ev):
    c = db()
    try:
        # Preserve the original schema, including its required timestamp columns.
        values = {name: ev[name] for name in (
            "time", "host_ip", "hostname", "src_ip", "dst_ip", "event", "user",
            "program", "facility", "severity", "mitre", "score", "message", "raw_line"
        )}
        legacy = {
            "event_time": ev["time"],
            "event_epoch": int(parse_time(ev["time"]).timestamp()),
            "event_type": ev["event"],
            "host": ev["host_ip"] or ev["hostname"],
            "raw": ev["raw_line"],
            "raw_message": ev["message"],
            "received_at": now_iso(),
            "payload_json": json.dumps(ev, ensure_ascii=False),
        }
        existing = set(cols(c, "events"))
        values.update({name: value for name, value in legacy.items() if name in existing})
        names = list(values)
        c.execute(
            f"INSERT INTO events({','.join(names)}) VALUES({','.join('?' for _ in names)})",
            [values[name] for name in names]
        )
        c.commit()
    finally:
        c.close()

def load_offset():
    try:
        with open(OFFSET_FILE, "r", encoding="utf-8") as f:
            return int(json.load(f).get("offset", 0))
    except Exception:
        return 0

def save_offset(offset):
    tmp = OFFSET_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump({"offset": offset}, f)
    os.replace(tmp, OFFSET_FILE)

def ingest_loop():
    offset = load_offset()
    while True:
        try:
            if not os.path.exists(LOG_PATH):
                time.sleep(2)
                continue

            size = os.path.getsize(LOG_PATH)
            if size < offset:
                offset = 0

            with open(LOG_PATH, "r", encoding="utf-8", errors="replace") as f:
                f.seek(offset)
                while True:
                    line = f.readline()
                    if not line:
                        break
                    if line.strip():
                        insert_event(parse_rsyslog_line(line))
                offset = f.tell()
                save_offset(offset)
        except Exception as e:
            print(f"[INGEST] {e}", flush=True)
        time.sleep(1)

def rowdict(r):
    return dict(r) if r else None

def held_event_ids(c):
    """Return HOLD event IDs without assuming the old anchors schema."""
    held = set()

    # New safe HOLD table.
    try:
        held.update(
            int(r["event_id"]) for r in c.execute(
                "SELECT event_id FROM soc_holds WHERE event_id IS NOT NULL"
            ).fetchall()
        )
    except Exception:
        pass

    # Best-effort read of the pre-existing anchors table.
    try:
        acols = set(cols(c, "anchors"))
        ref_col = None
        for candidate in ("event_id", "log_id", "logid", "source_event_id"):
            if candidate in acols:
                ref_col = candidate
                break
        if ref_col:
            for r in c.execute(
                f"SELECT {ref_col} AS event_id FROM anchors WHERE {ref_col} IS NOT NULL"
            ).fetchall():
                try:
                    held.add(int(r["event_id"]))
                except Exception:
                    pass
    except Exception:
        pass

    return held

def event_by_id(event_id):
    c = db()
    try:
        return rowdict(c.execute("SELECT * FROM events WHERE id=?", (event_id,)).fetchone())
    finally:
        c.close()

def sequence_bonus(a, b):
    chain = [
        ("SCAN", "AUTH_FAILURE"),
        ("AUTH_FAILURE", "AUTH_SUCCESS"),
        ("AUTH_SUCCESS", "PRIVILEGE_USE"),
        ("PRIVILEGE_USE", "ACCOUNT_CHANGE"),
        ("FILE_TRANSFER", "PRIVILEGE_USE"),
        ("ACCOUNT_CHANGE", "REGISTRY_CHANGE"),
    ]
    return 30 if (a, b) in chain or (b, a) in chain else 0

def similar_score(anchor, candidate):
    score = 0
    reasons = []

    if anchor.get("src_ip") and anchor.get("src_ip") == candidate.get("src_ip"):
        score += 30
        reasons.append("same_src:+30")
    if anchor.get("dst_ip") and anchor.get("dst_ip") == candidate.get("dst_ip"):
        score += 20
        reasons.append("same_dst:+20")
    if anchor.get("user") and anchor.get("user") == candidate.get("user"):
        score += 20
        reasons.append("same_user:+20")

    at = parse_time(anchor.get("time"))
    ct = parse_time(candidate.get("time"))
    diff = abs((ct - at).total_seconds())

    if diff <= 300:
        score += 30
        reasons.append("time_5m:+30")
    elif diff <= 900:
        score += 20
        reasons.append("time_15m:+20")
    elif diff <= 1800:
        score += 10
        reasons.append("time_30m:+10")

    sb = sequence_bonus(anchor.get("event"), candidate.get("event"))
    if sb:
        score += sb
        reasons.append("attack_sequence:+30")

    if anchor.get("mitre") and anchor.get("mitre") == candidate.get("mitre"):
        score += 15
        reasons.append("same_mitre:+15")

    if candidate.get("event") in SUSPICIOUS:
        score += 20
        reasons.append("suspicious:+20")

    return score, reasons

@app.get("/api/health")
def api_health():
    return jsonify({
        "status": "ok",
        "db": DB_PATH,
        "log": LOG_PATH,
        "time": now_iso()
    })

@app.get("/api/debug/db")
def api_debug_db():
    c = db()
    try:
        return jsonify({
            "db": DB_PATH,
            "events_count": int(c.execute("SELECT COUNT(*) cnt FROM events").fetchone()["cnt"] or 0),
            "events_columns": cols(c, "events"),
            "anchors_columns": cols(c, "anchors"),
            "hold_count": len(held_event_ids(c)),
        })
    finally:
        c.close()

@app.get("/api/events")
def api_events():
    limit = max(1, min(int(request.args.get("limit", 200)), 1000))
    src_ip = request.args.get("src_ip", "").strip()
    host_ip = request.args.get("host_ip", "").strip()
    event = request.args.get("event", "").strip()

    where = []
    args = []
    if src_ip:
        where.append("src_ip=?")
        args.append(src_ip)
    if host_ip:
        if host_ip == "__legacy__":
            where.append("(host_ip IS NULL OR host_ip='')")
        else:
            where.append("host_ip=?")
            args.append(host_ip)
    if event:
        where.append("event=?")
        args.append(event)

    sql = "SELECT * FROM events"
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY id DESC LIMIT ?"
    args.append(limit)

    c = db()
    try:
        rows = [dict(r) for r in c.execute(sql, args).fetchall()]
        held = held_event_ids(c)
        for r in rows:
            r["held"] = r["id"] in held
        return jsonify({"events": rows})
    finally:
        c.close()

@app.get("/api/search")
def api_search():
    field = request.args.get("field", "src_ip").strip()
    q = request.args.get("q", "").strip()
    scope_host_ip = request.args.get("scope_host_ip", "").strip()
    limit = max(1, min(int(request.args.get("limit", 200)), 1000))
    allowed = {"src_ip","dst_ip","host_ip","user","program","event","mitre","message"}
    if field not in allowed:
        return jsonify({"error":"invalid field"}), 400

    where = []
    args = []

    if scope_host_ip:
        if scope_host_ip == "__legacy__":
            where.append("(host_ip IS NULL OR host_ip='')")
        else:
            where.append("host_ip=?")
            args.append(scope_host_ip)

    if q:
        if field == "message":
            where.append("message LIKE ?")
            args.append(f"%{q}%")
        else:
            where.append(f"{field}=?")
            args.append(q)

    sql = "SELECT * FROM events"
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY id DESC LIMIT ?"
    args.append(limit)

    c = db()
    try:
        rows = c.execute(sql, args).fetchall()
        held = held_event_ids(c)
        out = []
        for r in rows:
            x = dict(r)
            x["held"] = x["id"] in held
            out.append(x)
        return jsonify({"events": out})
    finally:
        c.close()

@app.post("/api/anchors/<int:event_id>/hold")
def api_hold(event_id):
    if not event_by_id(event_id):
        return jsonify({"error":"event not found"}), 404
    c = db()
    try:
        c.execute(
            "INSERT OR REPLACE INTO soc_holds(event_id,held_at) VALUES(?,?)",
            (event_id, now_iso())
        )
        c.commit()
        return jsonify({"ok":True,"event_id":event_id})
    finally:
        c.close()

@app.delete("/api/anchors/<int:event_id>")
def api_unhold(event_id):
    c = db()
    try:
        c.execute("DELETE FROM soc_holds WHERE event_id=?", (event_id,))

        # Best-effort removal from an older anchors table as well.
        try:
            acols = set(cols(c, "anchors"))
            for candidate in ("event_id", "log_id", "logid", "source_event_id"):
                if candidate in acols:
                    c.execute(f"DELETE FROM anchors WHERE {candidate}=?", (event_id,))
                    break
        except Exception:
            pass

        c.commit()
        return jsonify({"ok":True})
    finally:
        c.close()

@app.get("/api/anchors")
def api_anchors():
    c = db()
    try:
        ids = sorted(held_event_ids(c), reverse=True)
        out = []
        for event_id in ids[:500]:
            r = c.execute("SELECT * FROM events WHERE id=?", (event_id,)).fetchone()
            if r:
                x = dict(r)
                x["held_at"] = None
                try:
                    h = c.execute(
                        "SELECT held_at FROM soc_holds WHERE event_id=?",
                        (event_id,)
                    ).fetchone()
                    if h:
                        x["held_at"] = h["held_at"]
                except Exception:
                    pass
                out.append(x)
        return jsonify({"anchors":out})
    finally:
        c.close()

@app.get("/api/similar/<int:event_id>")
def api_similar(event_id):
    anchor = event_by_id(event_id)
    if not anchor:
        return jsonify({"error":"event not found"}), 404

    min_score = max(0, min(int(request.args.get("min_score", 60)), 200))
    minutes = max(1, min(int(request.args.get("minutes", 60)), 1440))
    at = parse_time(anchor["time"])
    window = minutes * 60

    scope_host_ip = request.args.get("host_ip", "").strip()

    c = db()
    try:
        if scope_host_ip == "__legacy__":
            candidates = [dict(r) for r in c.execute(
                "SELECT * FROM events WHERE id<>? AND (host_ip IS NULL OR host_ip='') ORDER BY id DESC LIMIT 5000",
                (event_id,)
            ).fetchall()]
        elif scope_host_ip:
            candidates = [dict(r) for r in c.execute(
                "SELECT * FROM events WHERE id<>? AND host_ip=? ORDER BY id DESC LIMIT 5000",
                (event_id, scope_host_ip)
            ).fetchall()]
        else:
            candidates = [dict(r) for r in c.execute(
                "SELECT * FROM events WHERE id<>? ORDER BY id DESC LIMIT 5000",
                (event_id,)
            ).fetchall()]
    finally:
        c.close()

    out = []
    for cand in candidates:
        ct = parse_time(cand.get("time"))
        if abs((ct - at).total_seconds()) > window:
            continue
        score, reasons = similar_score(anchor, cand)
        if score >= min_score:
            cand["similar_score"] = score
            cand["similar_reasons"] = reasons
            out.append(cand)

    out.sort(key=lambda x: (-x["similar_score"], -x["id"]))
    return jsonify({
        "anchor": anchor,
        "min_score": min_score,
        "minutes": minutes,
        "similar": out[:500]
    })

@app.get("/api/hosts")
def api_hosts():
    c = db()
    try:
        hosts = []
        for r in c.execute("SELECT * FROM monitored_hosts ORDER BY name COLLATE NOCASE, ip").fetchall():
            h = dict(r)
            stat = c.execute(
                "SELECT COUNT(*) cnt, MAX(time) last_seen FROM events WHERE host_ip=?",
                (h["ip"],)
            ).fetchone()
            h["enabled"] = bool(h["enabled"])
            h["event_count"] = int(stat["cnt"] or 0)
            h["last_seen"] = stat["last_seen"]
            hosts.append(h)
        total = c.execute("SELECT COUNT(*) AS cnt FROM events").fetchone()["cnt"]
        legacy = c.execute(
            "SELECT COUNT(*) AS cnt FROM events WHERE host_ip IS NULL OR host_ip=''"
        ).fetchone()["cnt"]
        return jsonify({
            "hosts": hosts,
            "all_event_count": int(total or 0),
            "legacy_event_count": int(legacy or 0)
        })
    finally:
        c.close()

@app.post("/api/hosts")
def api_add_host():
    d = request.get_json(silent=True) or {}
    name = str(d.get("name","")).strip()
    ip = valid_ip(str(d.get("ip","")).strip())
    if not name:
        return jsonify({"error":"name is required"}), 400
    if not ip:
        return jsonify({"error":"invalid IP address"}), 400

    c = db()
    try:
        try:
            cur = c.execute("""
            INSERT INTO monitored_hosts(name,ip,os_type,role,note,enabled,created_at)
            VALUES(?,?,?,?,?,1,?)
            """, (
                name, ip,
                str(d.get("os_type","")).strip(),
                str(d.get("role","")).strip(),
                str(d.get("note","")).strip(),
                now_iso()
            ))
            c.commit()
        except sqlite3.IntegrityError:
            return jsonify({"error":"IP already registered"}), 409
        return jsonify({"ok":True,"id":cur.lastrowid}), 201
    finally:
        c.close()

@app.patch("/api/hosts/<int:host_id>")
def api_update_host(host_id):
    d = request.get_json(silent=True) or {}
    c = db()
    try:
        old = c.execute("SELECT * FROM monitored_hosts WHERE id=?", (host_id,)).fetchone()
        if not old:
            return jsonify({"error":"host not found"}), 404
        old = dict(old)
        ip = valid_ip(str(d.get("ip", old["ip"])).strip())
        if not ip:
            return jsonify({"error":"invalid IP address"}), 400
        enabled = 1 if bool(d.get("enabled", old["enabled"])) else 0
        try:
            c.execute("""
            UPDATE monitored_hosts SET
              name=?,ip=?,os_type=?,role=?,note=?,enabled=?
            WHERE id=?
            """, (
                str(d.get("name", old["name"])).strip(),
                ip,
                str(d.get("os_type", old["os_type"])).strip(),
                str(d.get("role", old["role"])).strip(),
                str(d.get("note", old["note"])).strip(),
                enabled,
                host_id
            ))
            c.commit()
        except sqlite3.IntegrityError:
            return jsonify({"error":"IP already registered"}), 409
        return jsonify({"ok":True})
    finally:
        c.close()

@app.delete("/api/hosts/<int:host_id>")
def api_delete_host(host_id):
    c = db()
    try:
        cur = c.execute("DELETE FROM monitored_hosts WHERE id=?", (host_id,))
        c.commit()
        if cur.rowcount == 0:
            return jsonify({"error":"host not found"}), 404
        return jsonify({"ok":True})
    finally:
        c.close()

_started = False
def start_ingestor():
    global _started
    if _started:
        return
    _started = True
    t = threading.Thread(target=ingest_loop, daemon=True)
    t.start()

ensure_schema()
start_ingestor()

if __name__ == "__main__":
    app.run("127.0.0.1", 8000, debug=False)
