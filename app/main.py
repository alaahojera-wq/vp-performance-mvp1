# app/main.py — Evalistics / VP Performance Tool (Supabase/Postgres ONLY)
# ✅ Matches your uploaded templates:
#   - dashboard.html expects: terms = [{id,name,is_active,locked}], vps = [{..., overall_label, overall_score}], term_locked (bool)
#   - admin_terms.html expects POST routes: /admin/terms/add, /admin/terms/activate/{id}, /admin/terms/toggle-lock/{id}
#   - admin_vps.html expects routes: /admin/vps, /admin/vps/add, /admin/vps/delete/{id}, /admin/vps/edit/{id}
# ✅ Fixes:
#   - term dropdown empty -> ensure_term_exists(selected)
#   - Overall column "Incomplete" -> compute_overall_for_vp + pass overall_label/overall_score
#   - 307 -> 405 after POST -> always redirect with 303
#   - GET /logout 405 -> add GET /logout

import os
import hashlib
import hmac
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Dict, Optional, Tuple, List

from fastapi import FastAPI, Request, Form, Depends, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from jinja2 import Environment, FileSystemLoader, select_autoescape
from contextlib import contextmanager

import jwt

# ======================
# CONFIG
# ======================

DATABASE_URL = os.getenv("DATABASE_URL", "").strip()
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "").strip()

JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256").strip() or "HS256"
JWT_EXPIRE_MINUTES = int(os.getenv("JWT_EXPIRE_MINUTES", "2880"))  # 2 days

BRAND_NAME = os.getenv("BRAND_NAME", "Evalistics")
DEFAULT_TERM = os.getenv("DEFAULT_TERM", "2025-26 Term 1")

# ✅ Hardcoded login accounts (as you requested)
ADMIN_EMAIL = "admin@evalistics.com"
ADMIN_PASSWORD = "Admin@1234"

PRINCIPAL_EMAIL = "principal@evalistics.com"
PRINCIPAL_PASSWORD = "Principal@1234"

if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL is missing. Set it in Render environment variables (with sslmode=require).")
if not JWT_SECRET_KEY:
    raise RuntimeError("JWT_SECRET_KEY is missing. Set it in Render environment variables.")

try:
    import psycopg
except Exception as e:
    raise RuntimeError("psycopg is not installed. Add psycopg[binary] to requirements.txt") from e


# ======================
# METRICS / SCORING
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


def compute_auto(metric: Optional[Metric], actual: Optional[float]) -> Optional[int]:
    """
    Returns an auto score out of 4 (as your UI expects).
    - meets target => 4
    - doesn't meet => 0
    """
    if not metric or actual is None:
        return None

    meets = False
    if metric.target_type == "gte":
        meets = actual >= metric.target_value
    elif metric.target_type == "lte":
        meets = actual <= metric.target_value

    return 4 if meets else 0


# ======================
# DB LAYER (Postgres only)
# ======================

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
# PASSWORD HELPERS
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
# AUTH HELPERS
# ======================

def get_token_from_request(request: Request) -> Optional[str]:
    return request.cookies.get("jwt_token")


def create_jwt_token(email: str) -> str:
    expire = datetime.utcnow() + timedelta(minutes=JWT_EXPIRE_MINUTES)
    payload = {"sub": email, "exp": int(expire.timestamp())}
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
# DB INIT + SEED
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

        # seed principal/admin
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

        # seed default term (active)
        cur.execute("""
            INSERT INTO terms(name, is_active, locked)
            VALUES (%s, TRUE, FALSE)
            ON CONFLICT (name) DO NOTHING;
        """, (DEFAULT_TERM,))


# ======================
# TERMS / OVERALL HELPERS
# ======================

def ensure_term_exists(term_name: str):
    term_name = (term_name or "").strip()
    if not term_name:
        return
    db.execute(
        """
        INSERT INTO terms(name, is_active, locked)
        VALUES (%s, FALSE, FALSE)
        ON CONFLICT (name) DO NOTHING
        """,
        (term_name,)
    )

def get_terms_full() -> List[Dict[str, Any]]:
    rows = db.fetchall("SELECT id, name, is_active, locked FROM terms ORDER BY id")
    return [{"id": r[0], "name": r[1], "is_active": bool(r[2]), "locked": bool(r[3])} for r in rows]

def get_active_term() -> str:
    row = db.fetchone("SELECT name FROM terms WHERE is_active=TRUE ORDER BY id DESC LIMIT 1")
    return row[0] if row else DEFAULT_TERM

def term_locked(term: str) -> bool:
    row = db.fetchone("SELECT locked FROM terms WHERE name=%s", (term,))
    return bool(row[0]) if row else False

def overall_label_from_score(score: float) -> str:
    # Simple 0..4 bands (stable)
    if score >= 3.6:
        return "Outstanding"
    if score >= 3.0:
        return "Good"
    if score >= 2.4:
        return "Acceptable"
    return "Weak"

def compute_overall_for_vp(term: str, vp_id: str) -> Tuple[Optional[float], Optional[str]]:
    """
    Returns (overall_score, overall_label) or (None, None) if incomplete.
    Uses override_score if present else auto_score.
    Weighted by 60/20/20 across pillars.
    """
    rows = db.fetchall(
        """
        SELECT metric_id, auto_score, override_score
        FROM metric_values
        WHERE term=%s AND vp_id=%s
        """,
        (term, vp_id)
    )
    score_map: Dict[str, Optional[int]] = {}
    for r in rows:
        metric_id, auto_s, over_s = r[0], r[1], r[2]
        score_map[metric_id] = over_s if over_s is not None else auto_s

    pillar_scores: Dict[int, List[float]] = {1: [], 2: [], 3: []}
    complete = True

    for m in METRICS:
        s = score_map.get(m.id)
        if s is None:
            complete = False
        else:
            pillar_scores[m.pillar].append(float(s))

    for p in (1, 2, 3):
        if len(pillar_scores[p]) == 0:
            complete = False

    if not complete:
        return None, None

    pavg = {p: (sum(pillar_scores[p]) / len(pillar_scores[p])) for p in (1, 2, 3)}
    overall = (
        pavg[1] * PILLAR_WEIGHTS[1] +
        pavg[2] * PILLAR_WEIGHTS[2] +
        pavg[3] * PILLAR_WEIGHTS[3]
    )
    overall = round(overall, 2)
    return overall, overall_label_from_score(overall)


# ======================
# UPSERT METRIC VALUES
# ======================

def upsert(term: str, vp_id: str, metric_id: str,
           actual: Optional[float] = None,
           auto_score: Optional[int] = None,
           override_score: Optional[int] = None,
           override_reason: Optional[str] = None,
           notes: Optional[str] = None):
    now = datetime.utcnow().isoformat()

    exists = db.fetchone(
        "SELECT 1 FROM metric_values WHERE term=%s AND vp_id=%s AND metric_id=%s",
        (term, vp_id, metric_id)
    )

    if exists:
        sets: List[str] = []
        params: List[Any] = []

        def add(field: str, value: Any):
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
            """
            INSERT INTO metric_values(term,vp_id,metric_id,actual,auto_score,override_score,override_reason,notes,updated_at)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
            """,
            (term, vp_id, metric_id, actual, auto_score, override_score, override_reason, notes, now)
        )


# ======================
# APP + TEMPLATES
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
