# app/main.py — Evalistics / VP Performance Tool (Supabase/Postgres ONLY)
# ✅ Matches your uploaded templates:
# - dashboard.html expects: terms[*].name/is_active/locked and vps[*].overall_label/overall_score, and term_locked boolean
# - admin_terms.html expects POST routes: /admin/terms/add, /admin/terms/activate/{id}, /admin/terms/toggle-lock/{id}
# - admin_vps.html expects routes: /admin/vps, /admin/vps/add, /admin/vps/delete/{id}, /admin/vps/edit/{id}
#
# ✅ Fixes:
# - Term dropdown empty => ensure_term_exists(term)
# - Overall shows Incomplete => compute overall + label and pass to dashboard template
# - 307->405 on POST redirects => always RedirectResponse(..., status_code=303)
# - GET /logout 405 => added GET /logout

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
    raise RuntimeError("DATABASE_URL is missing. Set it in Render environment variables.")
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
    Returns auto score OUT OF 4 (matches your "overall out of 4" requirement):
      meets target => 4
      doesn't meet => 0
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
# TEMPLATE-FRIENDLY TERM HELPERS
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

def get_terms_full():
    # dashboard.html expects t.name, t.is_active, t.locked
    rows = db.fetchall("SELECT id, name, is_active, locked FROM terms ORDER BY id")
    return [{"id": r[0], "name": r[1], "is_active": bool(r[2]), "locked": bool(r[3])} for r in rows]

def get_active_term() -> str:
    row = db.fetchone("SELECT name FROM terms WHERE is_active=TRUE ORDER BY id DESC LIMIT 1")
    return row[0] if row else DEFAULT_TERM

def term_locked(term: str) -> bool:
    row = db.fetchone("SELECT locked FROM terms WHERE name=%s", (term,))
    return bool(row[0]) if row else False


# ======================
# OVERALL SCORING (Dashboard + VP header)
# ======================

def overall_label_from_score(score: float) -> str:
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
            continue
        pillar_scores[m.pillar].append(float(s))

    # if any pillar has zero scored metrics -> incomplete
    for p in (1, 2, 3):
        if len(pillar_scores[p]) == 0:
            complete = False

    if not complete:
        return None, None

    pillar_avg = {p: (sum(pillar_scores[p]) / len(pillar_scores[p])) for p in (1, 2, 3)}
    overall = (
        pillar_avg[1] * PILLAR_WEIGHTS[1] +
        pillar_avg[2] * PILLAR_WEIGHTS[2] +
        pillar_avg[3] * PILLAR_WEIGHTS[3]
    )
    overall = round(overall, 2)
    return overall, overall_label_from_score(overall)


# ======================
# UPSERT METRIC VALUES
# ======================

def upsert(
    term: str,
    vp_id: str,
    metric_id: str,
    actual: Optional[float] = None,
    auto_score: Optional[int] = None,
    override_score: Optional[int] = None,
    override_reason: Optional[str] = None,
    notes: Optional[str] = None
):
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


# ======================
# ROUTES
# ======================

@app.get("/", response_class=HTMLResponse)
def root(request: Request):
    user = get_current_user(request)
    return RedirectResponse("/dashboard", status_code=303) if user else RedirectResponse("/login", status_code=303)

@app.get("/login", response_class=HTMLResponse)
def login_get(request: Request):
    return render(request, "login.html", title="Login")

@app.post("/login")
def login_post(request: Request, email: str = Form(...), password: str = Form(...)):
    email = email.strip().lower()
    user = db.fetchone("SELECT email, role, password_hash FROM users WHERE email=%s", (email,))
    if not user or not _verify_password(password, user[2]):
        return set_flash(RedirectResponse("/login", status_code=303), "Invalid email or password.")

    token = create_jwt_token(user[0])
    resp = RedirectResponse("/dashboard", status_code=303)
    resp.delete_cookie("jwt_token")
    resp.set_cookie("jwt_token", token, httponly=True)
    return resp

# ✅ GET logout (fixes GET /logout 405)
@app.get("/logout")
def logout_get():
    resp = RedirectResponse("/login", status_code=303)
    resp.delete_cookie("jwt_token")
    return resp

@app.post("/logout")
def logout_post(request: Request):
    resp = RedirectResponse("/login", status_code=303)
    resp.delete_cookie("jwt_token")
    return resp


# ----------------------
# DASHBOARD (matches dashboard.html)
# ----------------------
@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request, term: Optional[str] = None):
    user = get_current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)

    selected = term or get_active_term()
    ensure_term_exists(selected)

    terms = get_terms_full()
    locked = term_locked(selected)

    rows = db.fetchall("SELECT id, name, email, phase, notes FROM vps ORDER BY name")
    vps: List[Dict[str, Any]] = []
    for r in rows:
        vp_id = r[0]
        overall_score, overall_label = compute_overall_for_vp(selected, vp_id)
        vps.append({
            "id": vp_id,
            "name": r[1],
            "email": r[2],
            "phase": r[3],
            "notes": r[4],
            # template expects these
            "overall_score": overall_score,
            "overall_label": overall_label
        })

    return render(
        request,
        "dashboard.html",
        title="Dashboard",
        term=selected,
        terms=terms,
        vps=vps,
        term_locked=locked
    )


# ----------------------
# VP DETAIL
# ----------------------
@app.get("/vp/{vp_id}", response_class=HTMLResponse)
def vp_detail(request: Request, vp_id: str, term: Optional[str] = None):
    user = get_current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)

    selected = term or get_active_term()
    ensure_term_exists(selected)

    terms = get_terms_full()
    locked = term_locked(selected)
    disable_edit = locked and user["role"] != "admin"

    r = db.fetchone("SELECT id, name, email, phase, notes FROM vps WHERE id=%s", (vp_id,))
    if not r:
        return set_flash(RedirectResponse("/dashboard", status_code=303), "VP not found.")

    vp = {"id": r[0], "name": r[1], "email": r[2], "phase": r[3], "notes": r[4]}

    vals = {
        row[0]: row for row in db.fetchall(
            """
            SELECT metric_id, actual, auto_score, override_score, override_reason, notes, updated_at
            FROM metric_values
            WHERE term=%s AND vp_id=%s
            """,
            (selected, vp_id)
        )
    }

    rows_out: List[Dict[str, Any]] = []
    for p in (1, 2, 3):
        rows_out.append({"is_header": True, "title": f"Pillar {p} ({int(PILLAR_WEIGHTS[p] * 100)}%)"})
        for m in [mm for mm in METRICS if mm.pillar == p]:
            mv = vals.get(m.id)
            rows_out.append({
                "is_header": False,
                "id": m.id,
                "name": m.name,
                "desc": m.desc,
                "target_text": m.target_text,
                "actual": None if not mv else mv[1],
                "auto_score": None if not mv else mv[2],
                "override_score": None if not mv else mv[3],
                "notes": None if not mv else mv[5],
                "updated_at": None if not mv else mv[6],
            })

    overall_score, overall_label = compute_overall_for_vp(selected, vp_id)

    return render(
        request,
        "vp.html",
        title=vp["name"],
        vp=vp,
        term=selected,
        terms=terms,
        rows=rows_out,
        term_locked=locked,
        disable_edit=disable_edit,
        overall_score=overall_score,
        overall_label=overall_label
    )

# ----------------------
# VP METRIC UPDATES (auto-save per row)
# ----------------------
@app.post("/vp/{vp_id}/metric/{metric_id}/actual")
def set_actual(request: Request, vp_id: str, metric_id: str,
               term: str = Form(...), actual: Optional[float] = Form(None)):
    user = get_current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)

    if term_locked(term) and user["role"] != "admin":
        return set_flash(RedirectResponse(f"/vp/{vp_id}?term={term}", status_code=303), "Term locked.")

    m = next((mm for mm in METRICS if mm.id == metric_id), None)
    upsert(term, vp_id, metric_id, actual=actual, auto_score=compute_auto(m, actual))
    return RedirectResponse(f"/vp/{vp_id}?term={term}", status_code=303)

@app.post("/vp/{vp_id}/metric/{metric_id}/override")
def set_override(request: Request, vp_id: str, metric_id: str,
                 term: str = Form(...), override: Optional[int] = Form(None)):
    user = get_current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)

    if term_locked(term) and user["role"] != "admin":
        return set_flash(RedirectResponse(f"/vp/{vp_id}?term={term}", status_code=303), "Term locked.")

    upsert(term, vp_id, metric_id, override_score=override)
    return RedirectResponse(f"/vp/{vp_id}?term={term}", status_code=303)

@app.post("/vp/{vp_id}/metric/{metric_id}/notes")
def set_notes(request: Request, vp_id: str, metric_id: str,
              term: str = Form(...), notes: str = Form("")):
    user = get_current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)

    if term_locked(term) and user["role"] != "admin":
        return set_flash(RedirectResponse(f"/vp/{vp_id}?term={term}", status_code=303), "Term locked.")

    upsert(term, vp_id, metric_id, notes=notes)
    return RedirectResponse(f"/vp/{vp_id}?term={term}", status_code=303)


# ----------------------
# ADMIN: VPs (matches admin_vps.html)
# ----------------------
@app.get("/admin/vps", response_class=HTMLResponse)
def admin_vps(request: Request, user=Depends(require_role("admin"))):
    rows = db.fetchall("SELECT id, name, email, phase, notes FROM vps ORDER BY name")
    vps = [{"id": r[0], "name": r[1], "email": r[2], "phase": r[3], "notes": r[4]} for r in rows]
    return render(request, "admin_vps.html", title="Admin • Manage VPs", vps=vps)

@app.post("/admin/vps/add")
def admin_vps_add(
    request: Request,
    vp_id: str = Form(...),
    name: str = Form(...),
    email: str = Form(""),
    phase: str = Form(""),
    notes: str = Form(""),
    user=Depends(require_role("admin"))
):
    try:
        db.execute(
            "INSERT INTO vps(id, name, email, phase, notes) VALUES (%s,%s,%s,%s,%s)",
            (vp_id.strip(), name.strip(), email.strip(), phase.strip(), notes.strip())
        )
        return set_flash(RedirectResponse("/admin/vps", status_code=303), "VP added.")
    except Exception:
        return set_flash(RedirectResponse("/admin/vps", status_code=303), "VP ID exists or invalid.")

@app.post("/admin/vps/delete/{vp_id}")
def admin_vps_delete(request: Request, vp_id: str, user=Depends(require_role("admin"))):
    db.execute("DELETE FROM vps WHERE id=%s", (vp_id,))
    return set_flash(RedirectResponse("/admin/vps", status_code=303), "VP deleted.")

# Edit routes (admin_vps.html links here)
@app.get("/admin/vps/edit/{vp_id}", response_class=HTMLResponse)
def admin_vps_edit_get(request: Request, vp_id: str, user=Depends(require_role("admin"))):
    r = db.fetchone("SELECT id, name, email, phase, notes FROM vps WHERE id=%s", (vp_id,))
    if not r:
        return set_flash(RedirectResponse("/admin/vps", status_code=303), "VP not found.")
    vp = {"id": r[0], "name": r[1], "email": r[2], "phase": r[3], "notes": r[4]}
    # expects you have app/templates/admin_vps_edit.html
    return render(request, "admin_vps_edit.html", title=f"Edit • {vp['name']}", vp=vp)

@app.post("/admin/vps/edit/{vp_id}")
def admin_vps_edit_post(
    request: Request,
    vp_id: str,
    name: str = Form(...),
    email: str = Form(""),
    phase: str = Form(""),
    notes: str = Form(""),
    user=Depends(require_role("admin"))
):
    db.execute(
        "UPDATE vps SET name=%s, email=%s, phase=%s, notes=%s WHERE id=%s",
        (name.strip(), email.strip(), phase.strip(), notes.strip(), vp_id)
    )
    return set_flash(RedirectResponse("/admin/vps", status_code=303), "VP updated.")


# ----------------------
# ADMIN: TERMS (matches admin_terms.html)
# ----------------------
@app.get("/admin/terms", response_class=HTMLResponse)
def admin_terms(request: Request, user=Depends(require_role("admin"))):
    terms = get_terms_full()
    return render(request, "admin_terms.html", title="Admin • Terms", terms=terms)

@app.post("/admin/terms/add")
def admin_terms_add(
    request: Request,
    name: str = Form(...),
    make_active: str = Form("no"),
    user=Depends(require_role("admin"))
):
    name = name.strip()

    db.execute(
        "INSERT INTO terms(name, is_active, locked) VALUES (%s, FALSE, FALSE) ON CONFLICT (name) DO NOTHING",
        (name,)
    )

    if make_active == "yes":
        db.execute("UPDATE terms SET is_active=FALSE")
        db.execute("UPDATE terms SET is_active=TRUE WHERE name=%s", (name,))

    return set_flash(RedirectResponse("/admin/terms", status_code=303), "Term added.")

@app.post("/admin/terms/activate/{term_id}")
def admin_terms_activate(request: Request, term_id: int, user=Depends(require_role("admin"))):
    db.execute("UPDATE terms SET is_active=FALSE")
    db.execute("UPDATE terms SET is_active=TRUE WHERE id=%s", (term_id,))
    return set_flash(RedirectResponse("/admin/terms", status_code=303), "Term activated.")

@app.post("/admin/terms/toggle-lock/{term_id}")
def admin_terms_toggle_lock(request: Request, term_id: int, user=Depends(require_role("admin"))):
    db.execute("UPDATE terms SET locked = NOT locked WHERE id=%s", (term_id,))
    return set_flash(RedirectResponse("/admin/terms", status_code=303), "Lock toggled.")


# ----------------------
# ADMIN: ACCOUNT
# ----------------------
@app.get("/admin/account", response_class=HTMLResponse)
def admin_account(request: Request, user=Depends(require_role("admin"))):
    return render(request, "admin_account.html", title="Admin • Account")

@app.post("/admin/account")
def admin_account_update(request: Request, password: str = Form(...), user=Depends(require_role("admin"))):
    hashed = _make_password(password)
    db.execute("UPDATE users SET password_hash=%s WHERE email=%s", (hashed, user["email"]))
    return set_flash(RedirectResponse("/admin/account", status_code=303), "Admin password updated.")
