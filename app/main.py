import os, hashlib, hmac, secrets
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, Optional, Tuple

from fastapi import FastAPI, Request, Form, Depends
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from jinja2 import Environment, FileSystemLoader, select_autoescape
from contextlib import contextmanager

# ----------------------
# Environment Variables
# ----------------------
DATABASE_URL = os.getenv("DATABASE_URL", "").strip()
BRAND_NAME = os.getenv("BRAND_NAME", "Evalistics")
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "admin@local").strip().lower()
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin123")
PRINCIPAL_EMAIL = os.getenv("PRINCIPAL_EMAIL", "principal@local").strip().lower()
PRINCIPAL_PASSWORD = os.getenv("PRINCIPAL_PASSWORD", "principal123")
DEFAULT_TERM = os.getenv("DEFAULT_TERM", "2025-26 Term 1")

# ----------------------
# Database Pooling
# ----------------------
class DB:
    def __init__(self):
        self.is_pg = bool(DATABASE_URL)
        self.pool = None
        if self.is_pg:
            import psycopg2
            from psycopg2.pool import SimpleConnectionPool
            self.pg = psycopg2
            self.pool = SimpleConnectionPool(
                minconn=1,
                maxconn=int(os.getenv("PG_POOL_MAX", "5")),
                dsn=DATABASE_URL,
            )

    def connect(self):
        if self.is_pg:
            return self.pool.getconn()
        import sqlite3
        data_dir = os.getenv("DATA_DIR", ".")
        os.makedirs(data_dir, exist_ok=True)
        conn = sqlite3.connect(os.path.join(data_dir, "vp_perf.db"))
        conn.row_factory = sqlite3.Row
        return conn

    def release(self, conn):
        if self.is_pg:
            self.pool.putconn(conn)
        else:
            conn.close()

    @contextmanager
    def session(self):
        conn = self.connect()
        try:
            yield conn
        finally:
            self.release(conn)

db = DB()

# ----------------------
# FastAPI App
# ----------------------
app = FastAPI()
app.mount("/static", StaticFiles(directory="app/static"), name="static")

jinja = Environment(
    loader=FileSystemLoader("app/templates"),
    autoescape=select_autoescape(["html"])
)

# ----------------------
# Helper Functions
# ----------------------
def render(request: Request, template: str, **ctx):
    ctx.update(user=get_current_user(request), brand_name=BRAND_NAME, flash=request.cookies.get("flash"))
    html = jinja.get_template(template).render(**ctx)
    resp = HTMLResponse(html)
    if request.cookies.get("flash"):
        resp.delete_cookie("flash")
    return resp

def redirect(url: str, flash: str = None):
    resp = RedirectResponse(url, status_code=303)
    if flash:
        resp.set_cookie("flash", flash, max_age=5)
    return resp

def get_current_user(request: Request):
    email = request.cookies.get("session")
    if not email:
        return None
    with db.session() as conn:
        cur = conn.cursor()
        q = "SELECT email, role FROM users WHERE email=%s" if db.is_pg else "SELECT email, role FROM users WHERE email=?"
        cur.execute(q,(email,))
        r = cur.fetchone()
        return {"email":r[0],"role":r[1]} if r else None

# ----------------------
# Password Helpers
# ----------------------
def _pbkdf_hash(password: str, salt_hex: str) -> str:
    salt = bytes.fromhex(salt_hex)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 120000)
    return dk.hex()

def _make_password(password: str) -> str:
    salt_hex = secrets.token_hex(16)
    return f"{salt_hex}${_pbkdf_hash(password, salt_hex)}"

def _verify_password(password: str, stored: str) -> bool:
    try:
        salt_hex, hash_hex = stored.split("$",1)
        calc = _pbkdf_hash(password, salt_hex)
        return hmac.compare_digest(calc, hash_hex)
    except Exception:
        return False

# ----------------------
# App Initialization
# ----------------------
def init_db():
    with db.session() as conn:
        cur = conn.cursor()
        # users
        cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            email TEXT PRIMARY KEY,
            role TEXT NOT NULL,
            password_hash TEXT NOT NULL
        );
        """)
        # vps
        cur.execute("""
        CREATE TABLE IF NOT EXISTS vps (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            email TEXT,
            phase TEXT,
            notes TEXT
        );
        """)
        # terms
        cur.execute("""
        CREATE TABLE IF NOT EXISTS terms (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL UNIQUE,
            is_active BOOLEAN NOT NULL DEFAULT FALSE,
            locked BOOLEAN NOT NULL DEFAULT FALSE
        );
        """)
        # metric_values
        cur.execute("""
        CREATE TABLE IF NOT EXISTS metric_values (
            term TEXT NOT NULL,
            vp_id TEXT NOT NULL,
            metric_id TEXT NOT NULL,
            actual DOUBLE PRECISION,
            auto_score INTEGER,
            override_score INTEGER,
            override_reason TEXT,
            notes TEXT,
            updated_at TEXT,
            PRIMARY KEY (term, vp_id, metric_id)
        );
        """)
        # seed admin + principal
        principal_hash = _make_password(PRINCIPAL_PASSWORD)
        admin_hash = _make_password(ADMIN_PASSWORD)
        cur.execute(
            "INSERT INTO users(email, role, password_hash) VALUES (%s,%s,%s) ON CONFLICT (email) DO NOTHING;",
            (PRINCIPAL_EMAIL,"principal",principal_hash)
        )
        cur.execute(
            "INSERT INTO users(email, role, password_hash) VALUES (%s,%s,%s) ON CONFLICT (email) DO NOTHING;",
            (ADMIN_EMAIL,"admin",admin_hash)
        )
        # default term
        cur.execute(
            "INSERT INTO terms(name,is_active,locked) VALUES (%s,TRUE,FALSE) ON CONFLICT (name) DO NOTHING;",
            (DEFAULT_TERM,)
        )
        cur.execute(
            "UPDATE terms SET is_active = (name = %s);",
            (DEFAULT_TERM,)
        )
        conn.commit()

init_db()

# ----------------------
# Metrics & Scoring
# ----------------------
@dataclass
class Metric:
    id: str; name: str; desc: str; pillar: int; target_type: str; target_value: float; target_text: str

METRICS=[
    Metric("p1_internal","Internal assessments achievement (%)","Achievement percentage based on internal assessments.",1,"gte",80.0,"≥80%"),
    Metric("p1_pass","Pass rate (%)","Overall pass rate for the phase.",1,"gte",97.0,"≥97%"),
    Metric("p1_benchmark","Benchmark improvement (%)","Benchmark improvement percentage.",1,"gte",80.0,"≥80%"),
    Metric("p2_staff_att","Staff attendance (%)","Staff attendance percentage (excluding approved leaves).",2,"gte",96.0,"≥96%"),
    Metric("p2_parent_sla","Parent response within 48h (%)","Parent communications responded to within 48 hours.",2,"gte",100.0,"100%"),
    Metric("p2_plans","Weekly plans submitted on time (%)","Weekly plans submitted on or before deadline.",2,"gte",100.0,"100%"),
    Metric("p3_turnover","Staff turnover (%)","Annual turnover rate (lower is better).",3,"lte",25.0,"≤25%"),
    Metric("p3_pd","PD participation (%)","Participation in professional development activities.",3,"gte",90.0,"≥90%"),
    Metric("p3_culture","School culture initiatives delivered (%)","Completion rate of planned culture initiatives.",3,"gte",90.0,"≥90%"),
]
PILLAR_WEIGHTS={1:0.60,2:0.20,3:0.20}

# (THE REST OF YOUR ROUTES GO HERE — CONTINUED IN NEXT RESPONSE)

