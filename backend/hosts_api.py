import os, ipaddress, sqlite3
from datetime import datetime, timezone
from flask import Blueprint, jsonify, request


hosts_bp = Blueprint("hosts_bp", __name__)
DB_PATH = os.environ.get("SOC_DB_PATH", "/opt/soc/backend/siem.db")

def _db():
    c = sqlite3.connect(DB_PATH, timeout=10)
    c.row_factory = sqlite3.Row
    return c

def _cols(c, table):
    try:
        return [r["name"] for r in c.execute(f"PRAGMA table_info({table})").fetchall()]
    except Exception:
        return []

def ensure_hosts_schema():
    c = _db()
    try:
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
        )""")
        c.execute("CREATE INDEX IF NOT EXISTS idx_monitored_hosts_ip ON monitored_hosts(ip)")
        cols = _cols(c, "events")
        if cols and "host_ip" not in cols:
            c.execute("ALTER TABLE events ADD COLUMN host_ip TEXT")
            c.execute("CREATE INDEX IF NOT EXISTS idx_events_host_ip ON events(host_ip)")
        c.commit()
    finally:
        c.close()

def _time_col(c):
    cols = set(_cols(c, "events"))
    for x in ("time","ts","timestamp","received_at","created_at"):
        if x in cols:
            return x
    return None

@hosts_bp.get("/api/hosts")
def list_hosts():
    c = _db()
    try:
        rows = c.execute("SELECT * FROM monitored_hosts ORDER BY name COLLATE NOCASE, ip").fetchall()
        event_cols = set(_cols(c, "events"))
        tcol = _time_col(c)
        out = []
        for r in rows:
            h = dict(r)
            h["enabled"] = bool(h["enabled"])
            h["event_count"] = 0
            h["last_seen"] = None
            if "host_ip" in event_cols:
                if tcol:
                    q = f"SELECT COUNT(*) cnt, MAX({tcol}) last_seen FROM events WHERE host_ip=?"
                else:
                    q = "SELECT COUNT(*) cnt, NULL last_seen FROM events WHERE host_ip=?"
                s = c.execute(q, (h["ip"],)).fetchone()
                h["event_count"] = int(s["cnt"] or 0)
                h["last_seen"] = s["last_seen"]
            out.append(h)
        return jsonify({"hosts": out})
    finally:
        c.close()

@hosts_bp.post("/api/hosts")
def add_host():
    d = request.get_json(silent=True) or {}
    name = str(d.get("name","")).strip()
    ip = str(d.get("ip","")).strip()
    if not name:
        return jsonify({"error":"name is required"}), 400
    try:
        ip = str(ipaddress.ip_address(ip))
    except ValueError:
        return jsonify({"error":"invalid IP address"}), 400

    c = _db()
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
                datetime.now(timezone.utc).astimezone().isoformat()
            ))
            c.commit()
        except sqlite3.IntegrityError:
            return jsonify({"error":f"{ip} is already registered"}), 409
        return jsonify({"ok":True,"id":cur.lastrowid,"name":name,"ip":ip}), 201
    finally:
        c.close()

@hosts_bp.patch("/api/hosts/<int:host_id>")
def update_host(host_id):
    d = request.get_json(silent=True) or {}
    c = _db()
    try:
        r = c.execute("SELECT * FROM monitored_hosts WHERE id=?", (host_id,)).fetchone()
        if not r:
            return jsonify({"error":"host not found"}), 404
        old = dict(r)
        name = str(d.get("name",old["name"])).strip()
        ip = str(d.get("ip",old["ip"])).strip()
        try:
            ip = str(ipaddress.ip_address(ip))
        except ValueError:
            return jsonify({"error":"invalid IP address"}), 400
        enabled = 1 if bool(d.get("enabled", old["enabled"])) else 0
        try:
            c.execute("""
            UPDATE monitored_hosts
            SET name=?,ip=?,os_type=?,role=?,note=?,enabled=?
            WHERE id=?
            """,(
                name,ip,
                str(d.get("os_type",old["os_type"])).strip(),
                str(d.get("role",old["role"])).strip(),
                str(d.get("note",old["note"])).strip(),
                enabled,host_id
            ))
            c.commit()
        except sqlite3.IntegrityError:
            return jsonify({"error":f"{ip} is already registered"}),409
        return jsonify({"ok":True})
    finally:
        c.close()

@hosts_bp.delete("/api/hosts/<int:host_id>")
def delete_host(host_id):
    c = _db()
    try:
        cur = c.execute("DELETE FROM monitored_hosts WHERE id=?", (host_id,))
        c.commit()
        if cur.rowcount == 0:
            return jsonify({"error":"host not found"}),404
        return jsonify({"ok":True})
    finally:
        c.close()
