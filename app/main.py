import os, secrets
from dataclasses import dataclass
from datetime import datetime
from typing import Optional, Dict, Any, List, Tuple

from fastapi import FastAPI, Request, Form, Depends
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from jinja2 import Environment, FileSystemLoader, select_autoescape

# Environment / Templates
env = Environment(
    loader=FileSystemLoader("templates"),
    autoescape=select_autoescape(["html"])
)

# --- Environment Variables ---
DATABASE_URL = os.getenv("DATABASE_URL", "").strip()
BRAND_NAME = os.getenv("BRAND_NAME", "Evalistics")

ADMIN_EMAIL = os.getenv("ADMIN_EMAIL","admin@local").strip().lower()
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD","admin123")

PRINCIPAL_EMAIL = os.getenv("PRINCIPAL_EMAIL","principal@local").strip().lower()
PRINCIPAL_PASSWORD = os.getenv("PRINCIPAL_PASSWORD","principal123")

DEFAULT_TERM = os.getenv("DEFAULT_TERM","2025-26 Term 1")

# --- Database Pooling ---
from contextlib import contextmanager

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
                maxconn=int(os.getenv("PG_POOL_MAX","5")),
                dsn=DATABASE_URL
            )

    def connect(self):
        if self.is_pg:
            return self.pool.getconn()
        import sqlite3
        data_dir = os.getenv("DATA_DIR",".")
        os.makedirs(data_dir, exist_ok=True)
        conn = sqlite3.connect(os.path.join(data_dir,"vp_perf.db"))
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

# --- Helpers ---
from passlib.context import CryptContext
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def _make_password(raw: str) -> str:
    return pwd_context.hash(raw)

def _verify_password(raw: str, hashed: str) -> bool:
    return pwd_context.verify(raw, hashed)

# --- Database Initialization ---
def init_db():
    with db.session() as conn:
        cur = conn.cursor()
        # Create tables
        cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            email TEXT PRIMARY KEY,
            role TEXT NOT NULL,
            password_hash TEXT NOT NULL
        );
        """)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS vps (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            email TEXT,
            phase TEXT,
            notes TEXT
        );
        """)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS terms (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL UNIQUE,
            is_active BOOLEAN NOT NULL DEFAULT FALSE,
            locked BOOLEAN NOT NULL DEFAULT FALSE
        );
        """)
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
        # Seed admin + principal
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
        # Term
        cur.execute(
            "INSERT INTO terms(name,is_active,locked) VALUES (%s,TRUE,FALSE) ON CONFLICT (name) DO NOTHING;",
            (DEFAULT_TERM,)
        )
        cur.execute(
            "UPDATE terms SET is_active = (name = %s);",
            (DEFAULT_TERM,)
        )
        conn.commit()

# Run DB init
init_db()

# --- FastAPI App ---
app = FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")

def render(request: Request, template: str, **ctx):
    ctx.update({"request":request, "brand_name":BRAND_NAME})
    html = env.get_template(template).render(**ctx)
    return HTMLResponse(html)

# --- Auth ---
def get_user_by_email(email: str):
    with db.session() as conn:
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE email=%s;", (email,))
        return cur.fetchone()

@app.post("/login")
def login(request: Request, email: str = Form(...), password: str = Form(...)):
    user = get_user_by_email(email.lower().strip())
    if not user:
        return render(request,"login.html",error="Invalid email or password.")
    if not _verify_password(password, user[2]):
        return render(request,"login.html",error="Email or password incorrect.")
    response = RedirectResponse("/dashboard", status_code=302)
    response.set_cookie(key="user_email", value=email.lower(), httponly=True)
    return response

@app.get("/logout")
def logout():
    response = RedirectResponse("/login",302)
    response.delete_cookie("user_email")
    return response

def get_current_user(request: Request):
    email = request.cookies.get("user_email")
    if not email:
        return None
    return get_user_by_email(email)

# --- Dashboard & VPs ---
@app.get("/dashboard")
def dashboard(request: Request):
    user = get_current_user(request)
    if not user:
        return RedirectResponse("/login")
    with db.session() as conn:
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM vps;")
        vps_count = cur.fetchone()[0]
        cur.execute("SELECT name FROM terms WHERE is_active=TRUE LIMIT 1;")
        term = cur.fetchone()[0] if cur.rowcount>0 else DEFAULT_TERM
    return render(request,"dashboard.html",vps_count=vps_count,term=term)

@app.get("/vps")
def vps_list(request: Request):
    user = get_current_user(request)
    if not user:
        return RedirectResponse("/login")
    with db.session() as conn:
        cur = conn.cursor()
        cur.execute("SELECT * FROM vps;")
        vps = cur.fetchall()
    return render(request,"vps_list.html",vps=vps)

@app.get("/vps/{vp_id}")
def vps_detail(request: Request, vp_id: str):
    user = get_current_user(request)
    if not user:
        return RedirectResponse("/login")
    with db.session() as conn:
        cur = conn.cursor()
        cur.execute("SELECT * FROM vps WHERE id=%s;",(vp_id,))
        vp = cur.fetchone()
        cur.execute("SELECT SUM(auto_score) FROM metric_values WHERE vp_id=%s;",(vp_id,))
        overall = cur.fetchone()[0] or 0
    return render(request,"vp_detail.html",vp=vp,overall=overall)

@app.post("/vps/add")
def add_vp(request: Request,
           id: str = Form(...),
           name: str = Form(...),
           phase: str = Form(...)):
    user = get_current_user(request)
    if not user:
        return RedirectResponse("/login")
    if not id.strip() or not name.strip():
        return render(request,"vps_form.html",error="All fields are required.")
    with db.session() as conn:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO vps(id,name,phase) VALUES (%s,%s,%s);",
            (id,name,phase)
        )
        conn.commit()
    return RedirectResponse("/vps",302)

