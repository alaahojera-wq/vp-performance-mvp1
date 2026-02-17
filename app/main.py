import os, hashlib, hmac, secrets
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Dict, Optional, Tuple

from fastapi import FastAPI, Request, Form, Depends, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from jinja2 import Environment, FileSystemLoader, select_autoescape
from contextlib import contextmanager

import jwt

# ----------------------
# Metric & Scoring
# ----------------------
@dataclass
class Metric:
    id: str
    name: str
    desc: str
    pillar: int
    target_type: str
    target_value: float
    target_text: str

METRICS = [
    Metric("p1_internal", "Internal assessments achievement (%)",
           "Achievement percentage based on internal assessments.", 1, "gte", 80.0, "≥80%"),
    Metric("p1_pass", "Pass rate (%)",
           "Overall pass rate for the phase.", 1, "gte", 97.0, "≥97%"),
    Metric("p1_benchmark", "Benchmark improvement (%)",
           "Benchmark improvement percentage.", 1, "gte", 80.0, "≥80%"),
    Metric("p2_staff_att", "Staff attendance (%)",
           "Staff attendance percentage (excluding approved leaves).", 2, "gte", 96.0, "≥96%"),
    Metric("p2_parent_sla", "Parent response within 48h (%)",
           "Parent communications responded to within 48 hours.", 2, "gte", 100.0, "100%"),
    Metric("p2_plans", "Weekly plans submitted on time (%)",
           "Weekly plans submitted on or before deadline.", 2, "gte", 100.0, "100%"),
    Metric("p3_turnover", "Staff turnover (%)",
           "Annual turnover rate (lower is better).", 3, "lte", 25.0, "≤25%"),
    Metric("p3_pd", "PD participation (%)",
           "Participation in professional development activities.", 3, "gte", 90.0, "≥90%"),
    Metric("p3_culture", "School culture initiatives delivered (%)",
           "Completion rate of planned culture initiatives.", 3, "gte", 90.0, "≥90%"),
]

PILLAR_WEIGHTS = {
    1: 0.60,
    2: 0.20,
    3: 0.20
}

# ----------------------
# Environment Variables
# ----------------------
DATABASE_URL = os.getenv("DATABASE_URL", "").strip()
SUPABASE_URL = os.getenv("SUPABASE_URL","").strip()
SUPABASE_ANON_KEY = os.getenv("SUPABASE_ANON_KEY","").strip()
BRAND_NAME = os.getenv("BRAND_NAME", "Evalistics")
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM","HS256")
JWT_EXPIRE_MINUTES = int(os.getenv("JWT_EXPIRE_MINUTES","2880"))  # 2 days

ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "admin@local").strip().lower()
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin123")
PRINCIPAL_EMAIL = os.getenv("PRINCIPAL_EMAIL", "principal@local").strip().lower()
PRINCIPAL_PASSWORD = os.getenv("PRINCIPAL_PASSWORD", "principal123")
DEFAULT_TERM = os.getenv("DEFAULT_TERM", "2025-26 Term 1")

# ----------------------
# Database Pooling / Helpers
# ----------------------
class DB:
    def __init__(self):
        self.is_pg = bool(DATABASE_URL)
        self.pool = None
        if self.is_pg:
            import psycopg
            from psycop import pool
            self.pg = psycopg
            self.pool = pool.SimpleConnectionPool(
                1,
                int(os.getenv("PG_POOL_MAX", "5")),
                DATABASE_URL
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
            if not self.is_pg:
                conn.commit()
        finally:
            self.release(conn)

    def execute(self, query: str, params: Tuple = ()):
        with self.session() as conn:
            cur = conn.cursor()
            cur.execute(query, params)
            if self.is_pg:
                conn.commit()
            return cur

    def fetchone(self, query: str, params: Tuple = ()):
        with self.session() as conn:
            cur = conn.cursor()
            cur.execute(query, params)
            return cur.fetchone()

    def fetchall(self, query: str, params: Tuple = ()):
        with self.session() as conn:
            cur = conn.cursor()
            cur.execute(query, params)
            return cur.fetchall()

db = DB()

# ----------------------
# App & Templates
# ----------------------
app = FastAPI()
app.mount("/static", StaticFiles(directory="app/static"), name="static")

jinja = Environment(
    loader=FileSystemLoader("app/templates"), 
    autoescape=select_autoescape(["html"])
)

# ----------------------
# Flash / Render Helpers
# ----------------------
def render(request: Request, template: str, **ctx):
    ctx.update(
        user=get_current_user(request),
        brand_name=BRAND_NAME,
        flash=request.cookies.get("flash")
    )
    html = jinja.get_template(template).render(**ctx)
    resp = HTMLResponse(html)
    if request.cookies.get("flash"):
        resp.delete_cookie("flash")
    return resp

def set_flash(response: RedirectResponse, message: str):
    response.set_cookie("flash", message, max_age=5)
    return response

# ----------------------
# Authentication Helpers
# ----------------------
def get_token_from_request(request: Request) -> Optional[str]:
    return request.cookies.get("jwt_token")

def create_jwt_token(email: str):
    expire = datetime.utcnow() + timedelta(minutes=JWT_EXPIRE_MINUTES)
    payload = {"sub": email, "exp": int(expire.timestamp())}
    return jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)

def decode_jwt(token: str):
    try:
        data = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        return data
    except:
        return None

def get_current_user(request: Request):
    token = get_token_from_request(request)
    if not token:
        return None
    data = decode_jwt(token)
    if not data or "sub" not in data:
        return None
    email = data["sub"]
    row = db.fetchone(
        "SELECT email, role FROM users WHERE email=%s" if db.is_pg else "SELECT email, role FROM users WHERE email=?",
        (email,)
    )
    return {"email": row[0], "role": row[1]} if row else None

def require_user(request: Request):
    user = get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return user

def require_role(role: str):
    def inner(request: Request, user=Depends(require_user)):
        if user["role"] != role:
            raise HTTPException(status_code=403, detail="Forbidden")
        return user
    return inner

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
        return hmac.compare_digest(_pbkdf_hash(password, salt_hex), hash_hex)
    except:
        return False

# ----------------------
# Initialization (DB + Seed)
# ----------------------
def init_db():
    with db.session() as conn:
        cur = conn.cursor()
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

        # seed admin + principal
        cur.execute(
            "INSERT OR IGNORE INTO users(email,role,password_hash) VALUES (?,?,?)",
            (PRINCIPAL_EMAIL, "principal", _make_password(PRINCIPAL_PASSWORD))
        )
        cur.execute(
            "INSERT OR IGNORE INTO users(email,role,password_hash) VALUES (?,?,?)",
            (ADMIN_EMAIL, "admin", _make_password(ADMIN_PASSWORD))
        )

        cur.execute(
            "INSERT OR IGNORE INTO terms(name,is_active,locked) VALUES (?,?,?)",
            (DEFAULT_TERM,1,0)
        )

    init_db()

# ----------------------
# Routes
# ----------------------

## LOGIN
@app.get("/login", response_class=HTMLResponse)
def login_get(request: Request):
    return render(request,"login.html",title="Login")

@app.post("/login")
def login_post(request: Request, email: str = Form(...), password: str = Form(...)):
    user = db.fetchone(
        "SELECT email,role,password_hash FROM users WHERE email=%s" if db.is_pg else "SELECT email,role,password_hash FROM users WHERE email=?",
        (email.strip().lower(),)
    )
    if not user or not _verify_password(password, user[2]):
        return set_flash(RedirectResponse("/login"), "Invalid email or password.")
    token = create_jwt_token(user[0])
    resp = RedirectResponse("/dashboard", status_code=303)
    resp.delete_cookie("jwt_token")
    resp.set_cookie("jwt_token", token, httponly=True)
    return resp

## LOGOUT (POST)
@app.post("/logout")
def logout_post(request: Request):
    resp = RedirectResponse("/login", status_code=303)
    resp.delete_cookie("jwt_token")
    return resp

## DASHBOARD
@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request, term: Optional[str] = None):
    user = get_current_user(request)
    if not user:
        return RedirectResponse("/login")
    terms = db.fetchall("SELECT name,locked FROM terms ORDER BY id")
    selected = term or next((t[0] for t in terms if t[1]==False), DEFAULT_TERM)
    rows = db.fetchall("SELECT id,name,email,phase,notes FROM vps ORDER BY name")
    vps = [{"id":r[0],"name":r[1],"email":r[2],"phase":r[3],"notes":r[4]} for r in rows]
    return render(request,"dashboard.html",title="Dashboard",term=selected,terms=terms,vps=vps)

## VP DETAIL
@app.get("/vp/{vp_id}", response_class=HTMLResponse)
def vp_detail(request: Request, vp_id: str, term: Optional[str] = None):
    user = get_current_user(request)
    if not user:
        return RedirectResponse("/login")  
    selected = term or get_active_term()
    locked = term_locked(selected)
    disable_edit = locked and user["role"]!="admin"

    r = db.fetchone(
        "SELECT id,name,email,phase,notes FROM vps WHERE id=%s" if db.is_pg else "SELECT id,name,email,phase,notes FROM vps WHERE id=?",(vp_id,)
    )
    if not r:
        return set_flash(RedirectResponse("/dashboard"), "VP not found.")
    vp={"id":r[0],"name":r[1],"email":r[2],"phase":r[3],"notes":r[4]}

    vals = {row[0]:row for row in db.fetchall(
        "SELECT metric_id,actual,auto_score,override_score,override_reason,notes,updated_at FROM metric_values WHERE term=%s AND vp_id=%s" if db.is_pg else "SELECT metric_id,actual,auto_score,override_score,override_reason,notes,updated_at FROM metric_values WHERE term=? AND vp_id=?", (selected,vp_id))}
    rows=[]
    for p in (1,2,3):
        rows.append({"is_header":True,"title":f"Pillar {p} ({int(PILLAR_WEIGHTS[p]*100)}%)"})
        for m in [mm for mm in METRICS if mm.pillar==p]:
            mv = vals.get(m.id)
            rows.append({
                "is_header":False,
                "id":m.id,
                "name":m.name,
                "desc":m.desc,
                "target_text":m.target_text,
                "actual":None if not mv else mv[1],
                "auto_score":None if not mv else mv[2],
                "override_score":None if not mv else mv[3],
                "notes":None if not mv else mv[5],
                "updated_at":None if not mv else mv[6],
            })
    return render(request,"vp.html",title=vp["name"],vp=vp,term=selected,terms=get_terms(),rows=rows,term_locked=locked,disable_edit=disable_edit)

## SET METRIC ACTUAL / OVERRIDE / NOTES
@app.post("/vp/{vp_id}/metric/{metric_id}/actual")
def set_actual(request: Request,vp_id: str, metric_id: str,
               term: str = Form(...), actual: Optional[float] = Form(None)):
    if term_locked(term) and get_current_user(request)["role"]!="admin":
        return set_flash(RedirectResponse(f"/vp/{vp_id}?term={term}"), "Term locked.")
    m=next((mm for mm in METRICS if mm.id==metric_id),None)
    upsert(term,vp_id,metric_id,actual=actual,auto_score=compute_auto(m,actual))
    return RedirectResponse(f"/vp/{vp_id}?term={term}", status_code=303)

@app.post("/vp/{vp_id}/metric/{metric_id}/override")
def set_override(request: Request,vp_id: str, metric_id: str,
                 term: str = Form(...), override: Optional[int] = Form(None)):
    if term_locked(term) and get_current_user(request)["role"]!="admin":
        return set_flash(RedirectResponse(f"/vp/{vp_id}?term={term}"), "Term locked.")
    upsert(term,vp_id,metric_id,override_score=override)
    return RedirectResponse(f"/vp/{vp_id}?term={term}",status_code=303)

@app.post("/vp/{vp_id}/metric/{metric_id}/notes")
def set_notes(request: Request,vp_id: str, metric_id: str,
              term: str = Form(...), notes: str = Form("")):
    if term_locked(term) and get_current_user(request)["role"]!="admin":
        return set_flash(RedirectResponse(f"/vp/{vp_id}?term={term}"), "Term locked.")
    upsert(term,vp_id,metric_id,notes=notes)
    return RedirectResponse(f"/vp/{vp_id}?term={term}",status_code=303)

## ADMIN VPs
@app.get("/admin/vps", response_class=HTMLResponse)
def admin_vps(request: Request, user=Depends(require_role("admin"))):
    rows=db.fetchall("SELECT id,name,email,phase,notes FROM vps ORDER BY name")
    return render(request,"admin_vps.html",title="Admin • VPs",vps=rows)

@app.post("/admin/vps/add")
def admin_vps_add(request: Request,
                  vp_id: str = Form(...),
                  name: str = Form(...),
                  email: str = Form(""), phase: str = Form(""), notes: str = Form(""),
                  user=Depends(require_role("admin"))):
    try:
        db.execute(
            "INSERT INTO vps(id,name,email,phase,notes) VALUES(%s,%s,%s,%s,%s)" if db.is_pg else "INSERT INTO vps(id,name,email,phase,notes) VALUES(?,?,?,?,?)",
            (vp_id.strip(),name.strip(),email.strip(),phase.strip(),notes.strip())
        )
        return set_flash(RedirectResponse("/admin/vps"),"VP added.")
    except: 
        return set_flash(RedirectResponse("/admin/vps"),"VP ID exists.")

# ... (The rest of the file continues in next message due to length limit)
@app.post("/admin/vps/delete/{vp_id}")
def admin_vps_delete(request: Request, vp_id: str, user=Depends(require_role("admin"))):
    db.execute(
        "DELETE FROM vps WHERE id=%s" if db.is_pg else "DELETE FROM vps WHERE id=?",
        (vp_id,)
    )
    return set_flash(RedirectResponse("/admin/vps"), "VP deleted.")

## ADMIN TERMS
@app.get("/admin/terms", response_class=HTMLResponse)
def admin_terms(request: Request, user=Depends(require_role("admin"))):
    terms = db.fetchall("SELECT name,locked FROM terms ORDER BY id")
    return render(request, "admin_terms.html", title="Admin • Terms", terms=terms)

@app.post("/admin/terms/add")
def admin_terms_add(request: Request, name: str = Form(...), make_active: str = Form("no"), user=Depends(require_role("admin"))):
    name = name.strip()
    try:
        db.execute(
            "INSERT INTO terms(name,is_active,locked) VALUES(%s,FALSE,FALSE)" if db.is_pg else "INSERT INTO terms(name,is_active,locked) VALUES(?,?,?)",
            (name,) if db.is_pg else (name, 0, 0),
        )
    except Exception:
        return set_flash(RedirectResponse("/admin/terms"), "Term exists.")

    if make_active == "yes":
        db.execute("UPDATE terms SET is_active=FALSE" if db.is_pg else "UPDATE terms SET is_active=0")
        db.execute(
            "UPDATE terms SET is_active=TRUE WHERE name=%s" if db.is_pg else "UPDATE terms SET is_active=1 WHERE name=?",
            (name,)
        )
    return set_flash(RedirectResponse("/admin/terms"), "Term added.")

@app.post("/admin/terms/activate")
def admin_terms_activate(request: Request, name: str = Form(...), user=Depends(require_role("admin"))):
    db.execute("UPDATE terms SET is_active=FALSE" if db.is_pg else "UPDATE terms SET is_active=0")
    db.execute(
        "UPDATE terms SET is_active=TRUE WHERE name=%s" if db.is_pg else "UPDATE terms SET is_active=1 WHERE name=?",
        (name,)
    )
    return set_flash(RedirectResponse("/admin/terms"), "Term activated.")

@app.post("/admin/terms/lock")
def admin_terms_lock(request: Request, name: str = Form(...), user=Depends(require_role("admin"))):
    db.execute(
        "UPDATE terms SET locked=NOT locked WHERE name=%s" if db.is_pg else "UPDATE terms SET locked=CASE WHEN locked=1 THEN 0 ELSE 1 END WHERE name=?",
        (name,)
    )
    return set_flash(RedirectResponse("/admin/terms"), "Term lock toggled.")

## ADMIN ACCOUNT
@app.get("/admin/account", response_class=HTMLResponse)
def admin_account(request: Request, user=Depends(require_role("admin"))):
    return render(request, "admin_account.html", title="Admin • Account")

@app.post("/admin/account")
def admin_account_update(request: Request, password: str = Form(...), user=Depends(require_role("admin"))):
    hashed = _make_password(password)
    db.execute(
        "UPDATE users SET password_hash=%s WHERE email=%s" if db.is_pg else "UPDATE users SET password_hash=? WHERE email=?",
        (hashed, user["email"])
    )
    return set_flash(RedirectResponse("/admin/account"), "Admin password updated.")

