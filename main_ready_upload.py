
import os
import sqlite3
from typing import Optional

from fastapi import FastAPI
from fastapi.responses import HTMLResponse

app = FastAPI()

DB_PATH = "database.db"


def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = db()
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS vps (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        email TEXT,
        phase TEXT,
        notes TEXT
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS metric_values (
        term TEXT NOT NULL,
        vp_id TEXT NOT NULL,
        metric_id TEXT NOT NULL,
        actual REAL,
        auto_score INTEGER,
        override_score INTEGER,
        override_reason TEXT,
        notes TEXT,
        updated_at TEXT,
        PRIMARY KEY (term, vp_id, metric_id)
    )
    """)

    # Seed a demo VP if none exist
    cur.execute("SELECT COUNT(1) AS c FROM vps")
    row = cur.fetchone()

    if row and row["c"] == 0:
        cur.execute(
            "INSERT INTO vps (id, name, email, phase, notes) VALUES (?, ?, ?, ?, ?)",
            ("demo_vp", "Demo VP", "", "", "")
        )

    conn.commit()
    conn.close()


init_db()


@app.get("/", response_class=HTMLResponse)
def home():
    conn = db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM vps")
    vps = cur.fetchall()
    conn.close()

    html = "<h1>VP Performance System</h1>"
    html += "<h2>VP List</h2><ul>"
    for vp in vps:
        html += f"<li>{vp['name']} ({vp['phase']})</li>"
    html += "</ul>"

    return html
