#!/usr/bin/env python3
import sqlite3
import re

DB="/opt/soc/backend/siem.db"
con=sqlite3.connect(DB)
con.row_factory=sqlite3.Row
cols={r["name"] for r in con.execute("PRAGMA table_info(events)")}
id_col="id" if "id" in cols else "log_id"
text_col="message" if "message" in cols else ("raw_message" if "raw_message" in cols else "raw_line")

rows=con.execute(
    f"SELECT {id_col},src_ip,dst_ip,user,{text_col} FROM events "
    f"WHERE {text_col} LIKE '%src=203.230.56.162%' "
    f"ORDER BY {id_col} DESC LIMIT 10"
).fetchall()

print("=== src=203.230.56.162 검색 결과 ===")
print("count:", len(rows))
for r in rows:
    print(dict(r))

con.close()
