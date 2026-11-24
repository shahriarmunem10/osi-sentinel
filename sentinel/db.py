import sqlite3
import threading
import time

import config

_lock = threading.Lock()


def _connect():
    conn = sqlite3.connect(config.DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn


def init():
    with _lock:
        conn = _connect()
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                pw_hash TEXT NOT NULL,
                must_change INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS alerts(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts REAL NOT NULL,
                layer INTEGER NOT NULL,
                threat TEXT NOT NULL,
                severity TEXT NOT NULL,
                src TEXT,
                dst TEXT,
                detail TEXT
            );
            CREATE TABLE IF NOT EXISTS packets(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts REAL NOT NULL,
                src TEXT,
                dst TEXT,
                proto TEXT,
                sport INTEGER,
                dport INTEGER,
                length INTEGER,
                layer INTEGER,
                info TEXT
            );
            CREATE TABLE IF NOT EXISTS stats(
                ts REAL NOT NULL,
                pps REAL,
                bps REAL
            );
            CREATE TABLE IF NOT EXISTS devices(
                mac TEXT PRIMARY KEY,
                ip TEXT,
                hostname TEXT,
                vendor TEXT,
                custom_name TEXT,
                known INTEGER DEFAULT 1,
                first_seen REAL,
                last_seen REAL,
                extra TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts);
            CREATE INDEX IF NOT EXISTS idx_stats_ts ON stats(ts);
            """
        )
        cols = [r[1] for r in conn.execute("PRAGMA table_info(alerts)").fetchall()]
        if "evidence" not in cols:
            conn.execute("ALTER TABLE alerts ADD COLUMN evidence TEXT")
        conn.commit()
        conn.close()


def query(sql, args=()):
    with _lock:
        conn = _connect()
        try:
            return [dict(r) for r in conn.execute(sql, args).fetchall()]
        finally:
            conn.close()


def execute(sql, args=()):
    with _lock:
        conn = _connect()
        try:
            cur = conn.execute(sql, args)
            conn.commit()
            return cur.lastrowid
        finally:
            conn.close()


def add_alert(layer, threat, severity, src, dst, detail, evidence=None):
    return execute(
        "INSERT INTO alerts(ts,layer,threat,severity,src,dst,detail,evidence) VALUES(?,?,?,?,?,?,?,?)",
        (time.time(), layer, threat, severity, src or "", dst or "", detail or "", evidence),
    )


def add_packets(rows):
    if not rows:
        return
    with _lock:
        conn = _connect()
        try:
            conn.executemany(
                "INSERT INTO packets(ts,src,dst,proto,sport,dport,length,layer,info) VALUES(?,?,?,?,?,?,?,?,?)",
                [
                    (r["ts"], r["src"], r["dst"], r["proto"], r["sport"], r["dport"], r["length"], r["layer"], r["info"])
                    for r in rows
                ],
            )
            conn.commit()
        finally:
            conn.close()


def add_stat(ts, pps, bps):
    execute("INSERT INTO stats(ts,pps,bps) VALUES(?,?,?)", (ts, pps, bps))


def prune(max_packets=20000, max_stats=20000):
    with _lock:
        conn = _connect()
        try:
            n = conn.execute("SELECT COUNT(*) FROM packets").fetchone()[0]
            if n > max_packets + 5000:
                conn.execute(
                    "DELETE FROM packets WHERE id <= (SELECT id FROM packets ORDER BY id DESC LIMIT 1 OFFSET ?)",
                    (max_packets,),
                )
            n = conn.execute("SELECT COUNT(*) FROM stats").fetchone()[0]
            if n > max_stats + 2000:
                conn.execute(
                    "DELETE FROM stats WHERE rowid <= (SELECT rowid FROM stats ORDER BY rowid DESC LIMIT 1 OFFSET ?)",
                    (max_stats,),
                )
            conn.commit()
        finally:
            conn.close()


def clear_alerts():
    execute("DELETE FROM alerts")


def clear_all():
    with _lock:
        conn = _connect()
        try:
            conn.execute("DELETE FROM alerts")
            conn.execute("DELETE FROM packets")
            conn.execute("DELETE FROM stats")
            conn.commit()
        finally:
            conn.close()
