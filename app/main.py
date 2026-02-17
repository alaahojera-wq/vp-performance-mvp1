import os, hashlib, hmac, secrets
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Optional, Tuple, Any, List

from fastapi import FastAPI, Request, Form, Depends, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from jinja2 import Environment, FileSystemLoader, select_autoescape
from contextlib import contextmanager

import jwt

# ======================
# 🔐 CONFIG (SAFE DEFAULTS)
# ======================

# ✅ Put DB + JWT in env (recommended), OR put them here TEMPORARILY for testing.
# ⚠️ DO NOT commit real secrets to GitHub.
DATABASE_URL = os.getenv("DATABASE_URL", "").strip()
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "").strip()

JWT_ALGORITHM = "HS256"
JWT_EXPIRE_MINUTES = 2880  # 2 days
BRAND_NAME = "Evalistics"
DEFAULT_TERM = "2025-26 Term 1"

# ✅ Hardcoded login accounts (you requested this)
ADMIN_EMAIL = "admin@evalistics.com"
ADMIN_PASSWORD = "Admin@1234"

PRINCIPAL_EMAIL = "principal@evalistics.com"
PRINCIPAL_PASSWORD = "Principal@1234"

# ======================
# DB (Supabase/Postgres ONLY)
# ======================

if not DATABASE_URL:
    # You can leave it empty in GitHub, and set it in Render env vars.
    # Or temporarily paste your Supabase connection string locally.
    raise RuntimeError("DATABASE_URL is missing. Set it in Render environment variables.")

try:
    import psycopg
except Exception as e:
    raise RuntimeError("psycopg is not installed. Add psycopg[binary] to requirements.txt") from e


class DB:
    def connect(self):
        return psycopg.connect(DATABASE_URL)

    def release(self, conn):
        conn.close()

    @contextmanager
    def session(self):
        conn = self.connect()
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            self.release(conn)

    def execute(self, query: str, params: Tuple = ()):
        with self.session() as conn:
            cur = conn.cursor()
            cur.execute(query, params)
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

# ======================
# Password Helpers
# ======================

def _pbkdf_hash(password: str, salt_hex: str) -> str:
    salt = bytes.fromhex(salt_hex)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 120000)
    return dk.hex()

def _make_password(password: str) -> str:
    salt_hex = secrets.token_hex(16)
    return f"{salt_hex}${_pbkdf_hash(password, salt_hex)}"

def _verify_password(password: str, stored: str) -> bool:
    try:
        salt_hex, hash_hex = stored.split("$", 1)
        return hmac.compare_digest(_pbkdf_hash(password, salt_hex), hash_hex)
    except Exception:
        return False

# ======================
# Auth Helpers
# ======================

def get_token_from_request(request: Request) -> Optional[str]:
    return request.cookies.get("jwt_token")

def create_jwt_token(email: str) -> str:
    expire = datetime.utcnow() + timedelta(minutes=JWT_EXPIRE_MINUTES)
    payload = {"sub": email, "exp": int(expire.timestamp())}
    if not JWT_SECRET_KEY:
        raise RuntimeError("JWT_SECRET_KEY is missing. Set it in Render environment variables.")
    return jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)

def decode_jwt(token: str) -> Optional[dict]:
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
    email = str(data["sub"]).strip().lower()

    row = db.fetchone("SELECT email, role FROM users WHERE email=%s", (email,))
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

# ======================
# DB Init + Seed (Postgres-correct)
# ======================

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
                id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
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
                updated_at TIMESTAMPTZ DEFAULT NOW(),
                PRIMARY KEY (term, vp_id, metric_id)
            );
        """)

        # Seed users
        cur.execute("""
            INSERT INTO users(email, role, password_hash)
            VALUES (%s, %s, %s)
            ON CONFLICT (email) DO NOTHING;
        """, (PRINCIPAL_EMAIL.lower(), "principal", _make_password(PRINCIPAL_PASSWORD)))

        cur.execute("""
            INSERT INTO users(email, role, password_hash)
            VALUES (%s, %s, %s)
            ON CONFLICT (email) DO NOTHING;
        """, (ADMIN_EMAIL.lower(), "admin", _make_password(ADMIN_PASSWORD)))

        # Seed default term
        cur.execute("""
            INSERT INTO terms(name, is_active, locked)
            VALUES (%s, TRUE, FALSE)
            ON CONFLICT (name) DO NOTHING;
        """, (DEFAULT_TERM,))

def get_terms():
    return db.fetchall("SELECT name, locked, is_active FROM terms ORDER BY id")

def get_active_term() -> str:
    row = db.fetchone("SELECT name FROM terms WHERE is_active=TRUE ORDER BY id DESC LIMIT 1")
    return row[0] if row else DEFAULT_TERM

def term_locked(term: str) -> bool:
    row = db.fetchone("SELECT locked FROM terms WHERE name=%s", (term,))
    return bool(row[0]) if row else False

# ======================
# Metrics (same as before)
# ======================
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
PILLAR_WEIGHTS = {1: 0.60, 2: 0.20, 3: 0.20}

def compute_auto(metric: Metric, actual: Optional[float]) -> Optional[int]:
    if actual is None:
        return None
    if metric.target_type == "gte":
        return 1 if actual >= metric.target_value else 0
    if metric.target_type == "lte":
        return 1 if actual <= metric.target_value else 0
    return None

def upsert(term: str, vp_id: str, metric_id: str,
           actual: Optional[float] = None,
           auto_score: Optional[int] = None,
           override_score: Optional[int] = None,
           override_reason: Optional[str] = None,
           notes: Optional[str] = None):
    now = datetime.utcnow().isoformat()

    existing = db.fetchone(
        "SELECT 1 FROM metric_values WHERE term=%s AND vp_id=%s AND metric_id=%s",
        (term, vp_id, metric_id)
    )

    if existing:
        sets = []
        params: List[Any] = []

        def add(field, value):
            sets.append(f"{field}=%s")
            params.append(value)

        add("actual", actual)
        add("auto_score", auto_score)
        add("override_score", override_score)
        if override_reason is not None:
            add("override_reason", override_reason)
        if notes is not None:
            add("notes", notes)
        add("updated_at", now)

        params.extend([term, vp_id, metric_id])
        q = f"UPDATE metric_values SET {', '.join(sets)} WHERE term=%s AND vp_id=%s AND metric_id=%s"
        db.execute(q, tuple(params))
    else:
        db.execute(
            "INSERT INTO metric_values(term,vp_id,metric_id,actual,auto_score,override_score,override_reason,notes,updated_at) "
            "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)",
            (term, vp_id, metric_id, actual, auto_score, override_score, override_reason, notes, now)
        )

# ======================
# App + Templates
# ======================
app = FastAPI()

@app.on_event("startup")
def _startup():
    init_db()

app.mount("/static", StaticFiles(directory="app/static"), name="static")
jinja = Environment(
    loader=FileSystemLoader("app/templates"),
    autoescape=select_autoescape(["html"])
)

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

# ======================
# Routes (core)
# ======================

@app.get("/", response_class=HTMLResponse)
def root(request: Request):
    user = get_current_user(request)
    return RedirectResponse("/dashboard" if user else "/login")

@app.get("/login", response_class=HTMLResponse)
def login_get(request: Request):
    return render(request, "login.html", title="Login")

@app.post("/login")
def login_post(request: Request, email: str = Form(...), password: str = Form(...)):
    email = email.strip().lower()
    user = db.fetchone("SELECT email,role,password_hash FROM users WHERE email=%s", (email,))
    if not user or not _verify_password(password, user[2]):
        return set_flash(RedirectResponse("/login"), "Invalid email or password.")

    token = create_jwt_token(user[0])
    resp = RedirectResponse("/dashboard", status_code=303)
    resp.delete_cookie("jwt_token")
    resp.set_cookie("jwt_token", token, httponly=True)
    return resp

@app.post("/logout")
def logout_post(request: Request):
    resp = RedirectResponse("/login", status_code=303)
    resp.delete_cookie("jwt_token")
    return resp

@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request, term: Optional[str] = None):
    user = get_current_user(request)
    if not user:
        return RedirectResponse("/login")

    selected = term or get_active_term()
    terms = get_terms()
    rows = db.fetchall("SELECT id,name,email,phase,notes FROM vps ORDER BY name")
    vps = [{"id": r[0], "name": r[1], "email": r[2], "phase": r[3], "notes": r[4]} for r in rows]
    return render(request, "dashboard.html", title="Dashboard", term=selected, terms=terms, vps=vps)
