import os
import sqlite3
import hashlib
import hmac
import secrets
from dataclasses import dataclass
from datetime import datetime
from typing import Optional, Dict, Any, List

from fastapi import FastAPI, Request, Form, Depends
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from jinja2 import Environment, FileSystemLoader, select_autoescape

APP_DIR = os.path.dirname(__file__)
TEMPL_DIR = os.path.join(APP_DIR, "templates")
STATIC_DIR = os.path.join(APP_DIR, "static")

DATA_DIR = os.getenv("DATA_DIR", ".")
DB_PATH = os.path.join(DATA_DIR, "vp_perf.db")

ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "admin@local")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin123")
PRINCIPAL_EMAIL = os.getenv("PRINCIPAL_EMAIL", "principal@local")
PRINCIPAL_PASSWORD = os.getenv("PRINCIPAL_PASSWORD", "principal123")

SESSION_SECRET = os.getenv("SESSION_SECRET", secrets.token_hex(16))
DEFAULT_TERM = os.getenv("DEFAULT_TERM", "2025-26 Term 1")

app = FastAPI()
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

jinja = Environment(
    loader=FileSystemLoader(TEMPL_DIR),
    autoescape=select_autoescape(["html", "xml"])
)

def _connect():
    os.makedirs(DATA_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def _pbkdf_hash(password: str, salt_hex: str) -> str:
    salt = bytes.fromhex(salt_hex)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 120_000)
    return dk.hex()

def _make_password(password: str) -> str:
    salt_hex = secrets.token_hex(16)
    return f"{salt_hex}${_pbkdf_hash(password, salt_hex)}"

def _verify_password(password: str, stored: str) -> bool:
    try:
        salt_hex, hash_hex = stored.split("$", 1)
        calc = _pbkdf_hash(password, salt_hex)
        return hmac.compare_digest(calc, hash_hex)
    except Exception:
        return False

def init_db():
    conn = _connect()
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        email TEXT PRIMARY KEY,
        role TEXT NOT NULL,
        password_hash TEXT NOT NULL
    )
    """)

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

    # Seed users (admin + principal) if missing
    cur.execute("SELECT COUNT(1) AS c FROM users WHERE email = ?", (ADMIN_EMAIL,))
    if cur.fetchone()["c"] == 0:
        cur.execute(
            "INSERT INTO users (email, role, password_hash) VALUES (?, ?, ?)",
            (ADMIN_EMAIL, "admin", _make_password(ADMIN_PASSWORD))
        )

    cur.execute("SELECT COUNT(1) AS c FROM users WHERE email = ?", (PRINCIPAL_EMAIL,))
    if cur.fetchone()["c"] == 0:
        cur.execute(
            "INSERT INTO users (email, role, password_hash) VALUES (?, ?, ?)",
            (PRINCIPAL_EMAIL, "principal", _make_password(PRINCIPAL_PASSWORD))
        )

    # Seed one VP if none exist
    cur.execute("SELECT COUNT(1) AS c FROM vps")
    if cur.fetchone()["c"] == 0:
        cur.execute(
            "INSERT INTO vps (id, name, email, phase, notes) VALUES (?, ?, ?, ?, ?)",
            ("demo_vp", "Demo VP", "", "", "")
        )

    conn.commit()
    conn.close()

init_db()

def _sign(value: str) -> str:
    sig = hmac.new(SESSION_SECRET.encode("utf-8"), value.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"{value}.{sig}"

def _unsign(signed: str) -> Optional[str]:
    try:
        value, sig = signed.rsplit(".", 1)
        expected = hmac.new(SESSION_SECRET.encode("utf-8"), value.encode("utf-8"), hashlib.sha256).hexdigest()
        if hmac.compare_digest(sig, expected):
            return value
        return None
    except Exception:
        return None

def _get_user_from_request(request: Request) -> Optional[Dict[str, Any]]:
    token = request.cookies.get("session")
    if not token:
        return None
    email = _unsign(token)
    if not email:
        return None
    conn = _connect()
    cur = conn.cursor()
    cur.execute("SELECT email, role FROM users WHERE email = ?", (email,))
    row = cur.fetchone()
    conn.close()
    if not row:
        return None
    return {"email": row["email"], "role": row["role"]}

def render(request: Request, template: str, **ctx):
    user = _get_user_from_request(request)
    flash = request.cookies.get("flash")
    t = jinja.get_template(template)
    html = t.render(user=user, flash=flash, **ctx)
    resp = HTMLResponse(html)
    if flash:
        resp.delete_cookie("flash")
    return resp

def redirect(url: str, flash: Optional[str] = None):
    resp = RedirectResponse(url, status_code=303)
    if flash:
        resp.set_cookie("flash", flash, max_age=10, httponly=False)
    return resp

def require_role(role: str):
    def _dep(request: Request):
        user = _get_user_from_request(request)
        if not user:
            raise RedirectResponse("/login", status_code=303)
        if user["role"] != role:
            raise RedirectResponse("/dashboard", status_code=303)
        return user
    return _dep

@dataclass
class Metric:
    id: str
    name: str
    desc: str
    pillar: int
    target_type: str  # "gte", "lte"
    target_value: float
    target_text: str

METRICS: List[Metric] = [
    Metric("p1_internal", "Internal assessments achievement (%)", "Achievement percentage based on internal assessments.", 1, "gte", 80.0, "≥80%"),
    Metric("p1_pass", "Pass rate (%)", "Overall pass rate for the phase.", 1, "gte", 97.0, "≥97%"),
    Metric("p1_benchmark", "Benchmark improvement (%)", "Benchmark improvement percentage.", 1, "gte", 80.0, "≥80%"),
    Metric("p2_staff_att", "Staff attendance (%)", "Staff attendance percentage (excluding approved leaves).", 2, "gte", 96.0, "≥96%"),
    Metric("p2_parent_sla", "Parent response within 48h (%)", "Percentage of parent communications responded to within 48 hours.", 2, "gte", 100.0, "100%"),
    Metric("p2_plans", "Weekly plans submitted on time (%)", "Weekly plans submitted on or before deadline.", 2, "gte", 100.0, "100%"),
    Metric("p3_turnover", "Staff turnover (%)", "Annual turnover rate (lower is better).", 3, "lte", 25.0, "≤25%"),
    Metric("p3_pd", "PD participation (%)", "Participation in professional development activities.", 3, "gte", 90.0, "≥90%"),
    Metric("p3_culture", "School culture initiatives delivered (%)", "Completion rate of planned culture initiatives.", 3, "gte", 90.0, "≥90%"),
]

PILLAR_WEIGHTS = {1: 0.60, 2: 0.20, 3: 0.20}

def compute_auto_score(metric: Metric, actual: Optional[float]) -> Optional[int]:
    if actual is None:
        return None
    if metric.id == "p3_turnover":
        if actual <= 15:
            return 4
        if actual <= 25:
            return 3
        if actual <= 35:
            return 2
        return 1
    if metric.target_type == "gte":
        if actual >= metric.target_value + 10:
            return 4
        if actual >= metric.target_value:
            return 3
        if actual >= metric.target_value - 10:
            return 2
        return 1
    if metric.target_type == "lte":
        if actual <= metric.target_value - 10:
            return 4
        if actual <= metric.target_value:
            return 3
        if actual <= metric.target_value + 10:
            return 2
        return 1
    return None

def rating_label(score: float) -> str:
    if score >= 3.6:
        return "Outstanding"
    if score >= 3.0:
        return "Very Good"
    if score >= 2.0:
        return "Satisfactory"
    return "Unsatisfactory"

def load_metric_values(term: str, vp_id: str) -> Dict[str, sqlite3.Row]:
    conn = _connect()
    cur = conn.cursor()
    cur.execute("SELECT * FROM metric_values WHERE term = ? AND vp_id = ?", (term, vp_id))
    rows = cur.fetchall()
    conn.close()
    return {r["metric_id"]: r for r in rows}

def vp_overall(term: str, vp_id: str) -> Dict[str, Any]:
    values = load_metric_values(term, vp_id)
    pillar_scores: Dict[int, List[int]] = {1: [], 2: [], 3: []}

    for m in METRICS:
        r = values.get(m.id)
        if not r:
            continue
        score = r["override_score"] if r["override_score"] is not None else r["auto_score"]
        if score is not None:
            pillar_scores[m.pillar].append(int(score))

    p_avgs: Dict[int, Optional[float]] = {}
    for p in (1, 2, 3):
        p_avgs[p] = (sum(pillar_scores[p]) / len(pillar_scores[p])) if pillar_scores[p] else None

    if all(p_avgs[p] is not None for p in (1, 2, 3)):
        overall = sum(p_avgs[p] * PILLAR_WEIGHTS[p] for p in (1, 2, 3))
        return {"p1": round(p_avgs[1], 2), "p2": round(p_avgs[2], 2), "p3": round(p_avgs[3], 2),
                "overall_score": overall, "overall_label": rating_label(overall)}
    return {"p1": p_avgs[1], "p2": p_avgs[2], "p3": p_avgs[3], "overall_score": None, "overall_label": None}

def _upsert_metric(term: str, vp_id: str, metric_id: str, **fields):
    conn = _connect()
    cur = conn.cursor()
    cur.execute(
        "INSERT OR IGNORE INTO metric_values (term, vp_id, metric_id, updated_at) VALUES (?, ?, ?, ?)",
        (term, vp_id, metric_id, datetime.utcnow().isoformat(timespec="seconds"))
    )
    sets, vals = [], []
    for k, v in fields.items():
        sets.append(f"{k} = ?")
        vals.append(v)
    sets.append("updated_at = ?")
    vals.append(datetime.utcnow().isoformat(timespec="seconds"))
    vals.extend([term, vp_id, metric_id])
    cur.execute(f"UPDATE metric_values SET {', '.join(sets)} WHERE term = ? AND vp_id = ? AND metric_id = ?", vals)
    conn.commit()
    conn.close()

@app.get("/", response_class=HTMLResponse)
def root(request: Request):
    user = _get_user_from_request(request)
    return RedirectResponse("/dashboard", status_code=303) if user else RedirectResponse("/login", status_code=303)

@app.get("/login", response_class=HTMLResponse)
def login_get(request: Request):
    return render(request, "login.html", title="Login")

@app.post("/login")
def login_post(email: str = Form(...), password: str = Form(...)):
    conn = _connect()
    cur = conn.cursor()
    cur.execute("SELECT email, role, password_hash FROM users WHERE email = ?", (email.strip().lower(),))
    row = cur.fetchone()
    conn.close()
    if not row or not _verify_password(password, row["password_hash"]):
        return redirect("/login", flash="Invalid email or password.")
    resp = redirect("/dashboard")
    resp.set_cookie("session", _sign(row["email"]), httponly=True, samesite="lax")
    return resp

@app.get("/logout")
def logout():
    resp = redirect("/login", flash="Logged out.")
    resp.delete_cookie("session")
    return resp

@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request, term: str = DEFAULT_TERM):
    user = _get_user_from_request(request)
    if not user:
        return RedirectResponse("/login", status_code=303)

    conn = _connect()
    cur = conn.cursor()
    cur.execute("SELECT * FROM vps ORDER BY name")
    vps = [dict(r) for r in cur.fetchall()]
    conn.close()

    for vp in vps:
        o = vp_overall(term, vp["id"])
        vp["overall_score"] = o["overall_score"] or 0.0
        vp["overall_label"] = o["overall_label"]
    return render(request, "dashboard.html", title="Dashboard", term=term, vps=vps)

@app.get("/vp/{vp_id}", response_class=HTMLResponse)
def vp_page(request: Request, vp_id: str, term: str = DEFAULT_TERM):
    user = _get_user_from_request(request)
    if not user:
        return RedirectResponse("/login", status_code=303)

    conn = _connect()
    cur = conn.cursor()
    cur.execute("SELECT * FROM vps WHERE id = ?", (vp_id,))
    vp = cur.fetchone()
    conn.close()
    if not vp:
        return redirect("/dashboard", flash="VP not found.")

    values = load_metric_values(term, vp_id)
    overall = vp_overall(term, vp_id)

    rows = []
    for p in (1, 2, 3):
        rows.append({"is_header": True, "title": f"Pillar {p} ({int(PILLAR_WEIGHTS[p]*100)}%)"})
        for m in [mm for mm in METRICS if mm.pillar == p]:
            r = values.get(m.id)
            rows.append({
                "is_header": False,
                "id": m.id,
                "name": m.name,
                "desc": m.desc,
                "target_text": m.target_text,
                "actual": None if not r else r["actual"],
                "auto_score": None if not r else r["auto_score"],
                "override_score": None if not r else r["override_score"],
                "override_reason": None if not r else r["override_reason"],
                "notes": None if not r else r["notes"],
                "updated_at": None if not r else r["updated_at"],
            })

    return render(
        request, "vp.html", title=vp["name"], vp=dict(vp), term=term, rows=rows,
        overall_label=overall["overall_label"], overall_score=overall["overall_score"] or 0.0,
        p1=overall["p1"], p2=overall["p2"], p3=overall["p3"]
    )

@app.post("/vp/{vp_id}/metric/{metric_id}/actual")
def set_actual(request: Request, vp_id: str, metric_id: str, term: str = Form(...), actual: Optional[float] = Form(None)):
    user = _get_user_from_request(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    m = next((mm for mm in METRICS if mm.id == metric_id), None)
    if not m:
        return redirect(f"/vp/{vp_id}?term={term}", flash="Metric not found.")
    auto = compute_auto_score(m, actual)
    _upsert_metric(term, vp_id, metric_id, actual=actual, auto_score=auto)
    return redirect(f"/vp/{vp_id}?term={term}")

@app.post("/vp/{vp_id}/metric/{metric_id}/override")
def set_override(request: Request, vp_id: str, metric_id: str, term: str = Form(...), override: Optional[int] = Form(None)):
    user = _get_user_from_request(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    if override is not None and (override < 1 or override > 4):
        return redirect(f"/vp/{vp_id}?term={term}", flash="Override must be 1–4.")
    _upsert_metric(term, vp_id, metric_id, override_score=override)
    return redirect(f"/vp/{vp_id}?term={term}", flash="Override set. Add reason in Notes (first line).")

@app.post("/vp/{vp_id}/metric/{metric_id}/notes")
def set_notes(request: Request, vp_id: str, metric_id: str, term: str = Form(...), notes: str = Form("")):
    user = _get_user_from_request(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    reason = notes.strip().splitlines()[0][:240] if notes.strip() else None
    conn = _connect()
    cur = conn.cursor()
    cur.execute("SELECT override_score FROM metric_values WHERE term=? AND vp_id=? AND metric_id=?", (term, vp_id, metric_id))
    row = cur.fetchone()
    conn.close()
    fields = {"notes": notes}
    if row and row["override_score"] is not None:
        fields["override_reason"] = reason
    _upsert_metric(term, vp_id, metric_id, **fields)
    return redirect(f"/vp/{vp_id}?term={term}")

# Admin routes
@app.get("/admin/vps", response_class=HTMLResponse)
def admin_vps(request: Request, user=Depends(require_role("admin"))):
    conn = _connect()
    cur = conn.cursor()
    cur.execute("SELECT * FROM vps ORDER BY name")
    vps = [dict(r) for r in cur.fetchall()]
    conn.close()
    return render(request, "admin_vps.html", title="Admin • VPs", vps=vps)

@app.post("/admin/vps/add")
def admin_vps_add(
    request: Request,
    user=Depends(require_role("admin")),
    vp_id: str = Form(...),
    name: str = Form(...),
    email: str = Form(""),
    phase: str = Form(""),
    notes: str = Form("")
):
    conn = _connect()
    cur = conn.cursor()
    try:
        cur.execute(
            "INSERT INTO vps (id, name, email, phase, notes) VALUES (?, ?, ?, ?, ?)",
            (vp_id.strip(), name.strip(), email.strip(), phase.strip(), notes.strip())
        )
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        return redirect("/admin/vps", flash="VP ID already exists. Choose a unique ID.")
    conn.close()
    return redirect("/admin/vps", flash="VP added.")

@app.get("/admin/vps/edit/{vp_id}", response_class=HTMLResponse)
def admin_vps_edit_get(request: Request, vp_id: str, user=Depends(require_role("admin"))):
    conn = _connect()
    cur = conn.cursor()
    cur.execute("SELECT * FROM vps WHERE id = ?", (vp_id,))
    vp = cur.fetchone()
    conn.close()
    if not vp:
        return redirect("/admin/vps", flash="VP not found.")
    return render(request, "admin_vp_edit.html", title="Edit VP", vp=dict(vp))

@app.post("/admin/vps/edit/{vp_id}")
def admin_vps_edit_post(
    request: Request,
    vp_id: str,
    user=Depends(require_role("admin")),
    name: str = Form(...),
    email: str = Form(""),
    phase: str = Form(""),
    notes: str = Form("")
):
    conn = _connect()
    cur = conn.cursor()
    cur.execute(
        "UPDATE vps SET name=?, email=?, phase=?, notes=? WHERE id=?",
        (name.strip(), email.strip(), phase.strip(), notes.strip(), vp_id)
    )
    conn.commit()
    conn.close()
    return redirect("/admin/vps", flash="VP updated.")

@app.post("/admin/vps/delete/{vp_id}")
def admin_vps_delete(request: Request, vp_id: str, user=Depends(require_role("admin"))):
    conn = _connect()
    cur = conn.cursor()
    cur.execute("DELETE FROM vps WHERE id = ?", (vp_id,))
    conn.commit()
    conn.close()
    return redirect("/admin/vps", flash="VP deleted.")

@app.get("/admin/account", response_class=HTMLResponse)
def admin_account_get(request: Request, user=Depends(require_role("admin"))):
    return render(request, "admin_account.html", title="Admin • Account")

@app.post("/admin/account")
def admin_account_post(request: Request, password: str = Form(...), user=Depends(require_role("admin"))):
    conn = _connect()
    cur = conn.cursor()
    cur.execute("UPDATE users SET password_hash = ? WHERE email = ?", (_make_password(password), user["email"]))
    conn.commit()
    conn.close()
    return redirect("/admin/account", flash="Admin password updated.")
