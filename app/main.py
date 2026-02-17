import os, hashlib, hmac, secrets
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Dict, Optional, Tuple

from fastapi import FastAPI, Request, Form, Depends, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from jinja2 import Environment, FileSystemLoader, select_autoescape
from contextlib import contextmanager

import jwt

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
# Database Pooling
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

def get_token_from_request(request: Request) -> Optional[str]:
    token = request.cookies.get("jwt_token")
    return token

def create_jwt_token(email: str):
    expire = datetime.utcnow() + timedelta(minutes=JWT_EXPIRE_MINUTES)
    to_encode = {"sub": email, "exp": expire.isoformat()}
    return jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)

def decode_jwt(token: str):
    try:
        return jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
    except Exception:
        return None

def get_current_user(request: Request):
    token = get_token_from_request(request)
    if not token:
        return None
    data = decode_jwt(token)
    if not data or "sub" not in data:
        return None
    email = data["sub"]
    with db.session() as conn:
        cur = conn.cursor()
        q = "SELECT email, role FROM users WHERE email=%s" if db.is_pg else "SELECT email, role FROM users WHERE email=?"
        cur.execute(q,(email,))
        r = cur.fetchone()
        return {"email":r[0],"role":r[1]} if r else None

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
        calc = _pbkdf_hash(password, salt_hex)
        return hmac.compare_digest(calc, hash_hex)
    except Exception:
        return False

# ----------------------
# Database Initialization
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

        # seed admin & principal
        principal_hash = _make_password(PRINCIPAL_PASSWORD)
        admin_hash = _make_password(ADMIN_PASSWORD)
        if db.is_pg:
            cur.execute(
                "INSERT INTO users(email,role,password_hash) VALUES (%s,%s,%s) ON CONFLICT (email) DO NOTHING;",
                (PRINCIPAL_EMAIL,"principal",principal_hash)
            )
            cur.execute(
                "INSERT INTO users(email,role,password_hash) VALUES (%s,%s,%s) ON CONFLICT (email) DO NOTHING;",
                (ADMIN_EMAIL,"admin",admin_hash)
            )
        else:
            cur.execute(
                "INSERT OR IGNORE INTO users(email,role,password_hash) VALUES (?,?,?);",
                (PRINCIPAL_EMAIL,"principal",principal_hash)
            )
            cur.execute(
                "INSERT OR IGNORE INTO users(email,role,password_hash) VALUES (?,?,?);",
                (ADMIN_EMAIL,"admin",admin_hash)
            )

        # default term
        if db.is_pg:
            cur.execute(
                "INSERT INTO terms(name,is_active,locked) VALUES (%s,TRUE,FALSE) ON CONFLICT (name) DO NOTHING;",
                (DEFAULT_TERM,)
            )
            cur.execute(
                "UPDATE terms SET is_active = (name = %s);",
                (DEFAULT_TERM,)
            )
        else:
            cur.execute(
                "INSERT OR IGNORE INTO terms(name,is_active,locked) VALUES (?,?,?);",
                (DEFAULT_TERM,1,0)
            )
            cur.execute(
                "UPDATE terms SET is_active = CASE WHEN name=? THEN 1 ELSE 0 END;",
                (DEFAULT_TERM,)
            )

        conn.commit()

init_db()

# ----------------------
# Metrics & Scoring
# ----------------------
# ----------------------
# Additional Helper Functions
# ----------------------

def get_terms():
    with db.session() as conn:
        cur = conn.cursor()
        q = "SELECT name, locked FROM terms ORDER BY id"
        cur.execute(q)
        return cur.fetchall()

def get_active_term():
    with db.session() as conn:
        cur = conn.cursor()
        if db.is_pg:
            cur.execute("SELECT name FROM terms WHERE is_active=TRUE LIMIT 1")
        else:
            cur.execute("SELECT name FROM terms WHERE is_active=1 LIMIT 1")
        r = cur.fetchone()
        return r[0] if r else DEFAULT_TERM

def term_locked(term):
    with db.session() as conn:
        cur = conn.cursor()
        if db.is_pg:
            cur.execute("SELECT locked FROM terms WHERE name=%s", (term,))
        else:
            cur.execute("SELECT locked FROM terms WHERE name=?", (term,))
        r = cur.fetchone()
        return bool(r[0]) if r else False

# ----------------------
# Routes
# ----------------------

@app.get("/", response_class=HTMLResponse)
def root(request:Request):
    user = get_current_user(request)
    if user:
        return RedirectResponse("/dashboard")
    return RedirectResponse("/login")

# ------ Authentication ------
@app.get("/login", response_class=HTMLResponse)
def login_get(request:Request):
    return render(request,"login.html",title="Login")

@app.post("/login")
def login_post(request: Request, email:str=Form(...), password:str=Form(...)):
    e = email.strip().lower()
    with db.session() as conn:
        cur = conn.cursor()
        if db.is_pg:
            cur.execute("SELECT email, role, password_hash FROM users WHERE email=%s",(e,))
        else:
            cur.execute("SELECT email, role, password_hash FROM users WHERE email=?",(e,))
        r = cur.fetchone()
    if not r or not _verify_password(password, r[2]):
        return set_flash(RedirectResponse("/login"), "Invalid email or password.")
    token = create_jwt_token(r[0])
    resp = RedirectResponse("/dashboard")
    resp.set_cookie("jwt_token", token, httponly=True)
    return resp

@app.get("/logout")
def logout():
    resp = RedirectResponse("/login")
    resp.delete_cookie("jwt_token")
    return resp

# ------ Dashboard ------
@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request, term:Optional[str]=None):
    user = get_current_user(request)
    if not user:
        return RedirectResponse("/login")
    terms = get_terms()
    selected = term or get_active_term()
    locked = term_locked(selected)

    with db.session() as conn:
        cur = conn.cursor()
        cur.execute("SELECT id, name, email, phase, notes FROM vps ORDER BY name")
        rows = cur.fetchall()
    vps = []
    for r in rows:
        vps.append({"id":r[0],"name":r[1],"email":r[2],"phase":r[3],"notes":r[4]})
    return render(request,"dashboard.html",title="Dashboard",term=selected,terms=terms,vps=vps,term_locked=locked)

# ------ VP Details ------
@app.get("/vp/{vp_id}", response_class=HTMLResponse)
def vp_detail(request: Request, vp_id:str, term:Optional[str]=None):
    user = get_current_user(request)
    if not user:
        return RedirectResponse("/login")
    selected = term or get_active_term()
    locked = term_locked(selected)
    disable_edit = locked and user["role"]!="admin"

    with db.session() as conn:
        cur = conn.cursor()
        if db.is_pg:
            cur.execute("SELECT id,name,email,phase,notes FROM vps WHERE id=%s",(vp_id,))
        else:
            cur.execute("SELECT id,name,email,phase,notes FROM vps WHERE id=?",(vp_id,))
        r = cur.fetchone()
    if not r:
        return set_flash(RedirectResponse("/dashboard"), "VP not found.")
    vp = {"id":r[0],"name":r[1],"email":r[2],"phase":r[3],"notes":r[4]}

    # load metric table
    vals = {}
    with db.session() as conn:
        cur = conn.cursor()
        if db.is_pg:
            cur.execute("SELECT metric_id,actual,auto_score,override_score,override_reason,notes,updated_at FROM metric_values WHERE term=%s AND vp_id=%s",(selected,vp_id))
        else:
            cur.execute("SELECT metric_id,actual,auto_score,override_score,override_reason,notes,updated_at FROM metric_values WHERE term=? AND vp_id=?",(selected,vp_id))
        for row in cur.fetchall():
            vals[row[0]] = row

    rows = []
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

    return render(request,"vp.html",
                  title=vp["name"],vp=vp,term=selected,
                  terms=get_terms(),rows=rows,
                  term_locked=locked,disable_edit=disable_edit)

# ------ Update Metric Actual Values ------
@app.post("/vp/{vp_id}/metric/{metric_id}/actual")
def set_actual(request:Request,vp_id:str,metric_id:str,
               term:str=Form(...),actual:Optional[float]=Form(None)):
    user = get_current_user(request)
    if not user:
        return RedirectResponse("/login")
    if term_locked(term) and user["role"]!="admin":
        return set_flash(RedirectResponse(f"/vp/{vp_id}?term={term}"), "Term locked. Editing disabled.")
    m = next((mm for mm in METRICS if mm.id==metric_id),None)
    if not m:
        return set_flash(RedirectResponse(f"/vp/{vp_id}?term={term}"), "Metric not found.")
    upsert(term,vp_id,metric_id,actual=actual,auto_score=compute_auto(m,actual))
    return RedirectResponse(f"/vp/{vp_id}?term={term}",status_code=303)

# ------ Update Override Scores ------
@app.post("/vp/{vp_id}/metric/{metric_id}/override")
def set_override(request:Request,vp_id:str,metric_id:str,
                 term:str=Form(...),override:Optional[int]=Form(None)):
    user = get_current_user(request)
    if not user:
        return RedirectResponse("/login")
    if term_locked(term) and user["role"]!="admin":
        return set_flash(RedirectResponse(f"/vp/{vp_id}?term={term}"), "Term locked. Editing disabled.")
    upsert(term,vp_id,metric_id,override_score=override)
    return RedirectResponse(f"/vp/{vp_id}?term={term}",status_code=303)

# ------ Update Notes ------
@app.post("/vp/{vp_id}/metric/{metric_id}/notes")
def set_notes(request:Request,vp_id:str,metric_id:str,
              term:str=Form(...),notes:str=Form("")):
    user = get_current_user(request)
    if not user:
        return RedirectResponse("/login")
    if term_locked(term) and user["role"]!="admin":
        return set_flash(RedirectResponse(f"/vp/{vp_id}?term={term}"), "Term locked. Editing disabled.")
    upsert(term,vp_id,metric_id,notes=notes)
    return RedirectResponse(f"/vp/{vp_id}?term={term}",status_code=303)
# ----------------------
# Admin: VPs
# ----------------------
@app.get("/admin/vps", response_class=HTMLResponse)
def admin_vps(request:Request, user=Depends(require_role("admin"))):
    with db.session() as conn:
        cur = conn.cursor()
        cur.execute("SELECT id,name,email,phase,notes FROM vps ORDER BY name")
        rows = cur.fetchall()
    vps_list = [{"id": r[0], "name": r[1], "email": r[2], "phase": r[3], "notes": r[4]} for r in rows]
    return render(request, "admin_vps.html", title="Admin • VPs", vps=vps_list)

@app.post("/admin/vps/add")
def admin_vps_add(request:Request,
                  vp_id:str=Form(...),
                  name:str=Form(...),
                  email:str=Form(""),
                  phase:str=Form(""),
                  notes:str=Form(""),
                  user=Depends(require_role("admin"))):
    try:
        with db.session() as conn:
            cur = conn.cursor()
            if db.is_pg:
                cur.execute(
                    "INSERT INTO vps(id,name,email,phase,notes) VALUES(%s,%s,%s,%s,%s)",
                    (vp_id.strip(), name.strip(), email.strip(), phase.strip(), notes.strip())
                )
            else:
                cur.execute(
                    "INSERT INTO vps(id,name,email,phase,notes) VALUES(?,?,?,?,?)",
                    (vp_id.strip(), name.strip(), email.strip(), phase.strip(), notes.strip())
                )
            conn.commit()
        return set_flash(RedirectResponse("/admin/vps"), "VP added.")
    except Exception:
        return set_flash(RedirectResponse("/admin/vps"), "VP ID already exists.")

@app.post("/admin/vps/delete/{vp_id}")
def admin_vps_delete(request:Request, vp_id:str, user=Depends(require_role("admin"))):
    with db.session() as conn:
        cur = conn.cursor()
        if db.is_pg:
            cur.execute("DELETE FROM vps WHERE id=%s",(vp_id,))
        else:
            cur.execute("DELETE FROM vps WHERE id=?",(vp_id,))
        conn.commit()
    return set_flash(RedirectResponse("/admin/vps"), "VP deleted.")

# ----------------------
# Admin: Terms
# ----------------------
@app.get("/admin/terms", response_class=HTMLResponse)
def admin_terms(request:Request, user=Depends(require_role("admin"))):
    return render(request,"admin_terms.html",title="Admin • Terms",terms=get_terms())

@app.post("/admin/terms/add")
def admin_terms_add(request:Request,
                    name:str=Form(...),
                    make_active:str=Form("no"),
                    user=Depends(require_role("admin"))):
    name = name.strip()
    try:
        with db.session() as conn:
            cur = conn.cursor()
            if db.is_pg:
                cur.execute("INSERT INTO terms(name,is_active,locked) VALUES(%s,FALSE,FALSE)",(name,))
            else:
                cur.execute("INSERT INTO terms(name,is_active,locked) VALUES(?,?,?)",(name,0,0))
            conn.commit()
    except Exception:
        return set_flash(RedirectResponse("/admin/terms"), "Term exists.")

    if make_active=="yes":
        with db.session() as conn:
            cur = conn.cursor()
            if db.is_pg:
                cur.execute("UPDATE terms SET is_active=FALSE")
                cur.execute("UPDATE terms SET is_active=TRUE WHERE name=%s",(name,))
            else:
                cur.execute("UPDATE terms SET is_active=0")
                cur.execute("UPDATE terms SET is_active=1 WHERE name=?",(name,))
            conn.commit()
    return set_flash(RedirectResponse("/admin/terms"), "Term added.")

@app.post("/admin/terms/activate")
def admin_terms_activate(request:Request,
                         name:str=Form(...),
                         user=Depends(require_role("admin"))):
    with db.session() as conn:
        cur = conn.cursor()
        if db.is_pg:
            cur.execute("UPDATE terms SET is_active=FALSE")
            cur.execute("UPDATE terms SET is_active=TRUE WHERE name=%s",(name,))
        else:
            cur.execute("UPDATE terms SET is_active=0")
            cur.execute("UPDATE terms SET is_active=1 WHERE name=?",(name,))
        conn.commit()
    return set_flash(RedirectResponse("/admin/terms"), "Term activated.")

@app.post("/admin/terms/lock")
def admin_terms_lock(request:Request,
                     name:str=Form(...),
                     user=Depends(require_role("admin"))):
    with db.session() as conn:
        cur = conn.cursor()
        if db.is_pg:
            cur.execute("UPDATE terms SET locked=NOT locked WHERE name=%s",(name,))
        else:
            cur.execute("UPDATE terms SET locked=CASE WHEN locked=1 THEN 0 ELSE 1 END WHERE name=?",(name,))
        conn.commit()
    return set_flash(RedirectResponse("/admin/terms"), "Term lock toggled.")

# ----------------------
# Admin: Account
# ----------------------
@app.get("/admin/account", response_class=HTMLResponse)
def admin_account(request:Request, user=Depends(require_role("admin"))):
    return render(request,"admin_account.html",title="Admin • Account")

@app.post("/admin/account")
def admin_account_update(request:Request,
                         password:str=Form(...),
                         user=Depends(require_role("admin"))):
    hashed = _make_password(password)
    with db.session() as conn:
        cur = conn.cursor()
        if db.is_pg:
            cur.execute("UPDATE users SET password_hash=%s WHERE email=%s",(hashed,user["email"]))
        else:
            cur.execute("UPDATE users SET password_hash=? WHERE email=?",(hashed,user["email"]))
        conn.commit()
    return set_flash(RedirectResponse("/admin/account"), "Admin password updated.")

# ----------------------
# End of File
# ----------------------



