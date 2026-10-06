import sqlite3
c = sqlite3.connect("app.db")
rows = c.execute("select id, prev_hash, entry_hash from login_logs order by id").fetchall()
prev = "0" * 64
for id_, p, e in rows:
    print(f"#{id_} lien_ok={p == prev}")
    prev = e
