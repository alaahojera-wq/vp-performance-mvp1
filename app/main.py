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
# App Initialization
# ----------------------
app = FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")
jinja = Environment(
    loader=FileSystemLoader("app/templates"), autoescape=select_autoescape(["html"])
)


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
        salt_hex, hash_hex = stored.split("$", 1)
        calc = _pbkdf_hash(password, salt_hex)
        return hmac.compare_digest(calc, hash_hex)
    except Exception:
        return False


# ----------------------
# Metrics + Scoring Logic
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
    Metric("p1_internal", "Internal assessments achievement (%)", "Achievement percentage based on internal assessments.", 1, "gte", 80.0, "≥80%"),
    Metric("p1_pass", "Pass rate (%)", "Overall pass rate for the phase.", 1, "gte", 97.0, "≥97%"),
    Metric("p1_benchmark", "Benchmark improvement (%)", "Benchmark improvement percentage.", 1, "gte", 80.0, "≥80%"),
    Metric("p2_staff_att", "Staff attendance (%)", "Staff attendance percentage (excluding approved leaves).", 2, "gte", 96.0, "≥96%"),
    Metric("p2_parent_sla", "Parent response within 48h (%)", "Parent communications responded to within 48 hours.", 2, "gte", 100.0, "100%"),
    Metric("p2_plans", "Weekly plans submitted on time (%)", "Weekly plans submitted on or before deadline.", 2, "gte", 100.0, "100%"),
    Metric("p3_turnover", "Staff turnover (%)", "Annual turnover rate (lower is better).", 3, "lte", 25.0, "≤25%"),
    Metric("p3_pd", "PD participation (%)", "Participation in professional development activities.", 3, "gte", 90.0, "≥90%"),
    Metric("p3_culture", "School culture initiatives delivered (%)", "Completion rate of planned culture initiatives.", 3, "gte", 90.0, "≥90%"),
]

PILLAR_WEIGHTS = {1: 0.60, 2: 0.20, 3: 0.20}


def compute_auto(m: Metric, actual: Optional[float]) -> Optional[int]:
    if actual is None:
        return None
    if m.id == "p3_turnover":
        if actual <= 15:
            return 4
        if actual <= 25:
            return 3
        if actual <= 35:
            return 2
        return 1
    if m.target_type == "gte":
        if actual >= m.target_value + 10:
            return 4
        if actual >= m.target_value:
            return 3
        if actual >= m.target_value - 10:
            return 2
        return 1
    if m.target_type == "lte":
        if actual <= m.target_value - 10:
            return 4
        if actual <= m.target_value:
            return 3
        if actual <= m.target_value + 10:
            return 2
        return 1
    return None


def label(score: float) -> str:
    if score >= 3.6:
        return "Outstanding"
    if score >= 3.0:
        return "Very Good"
    if score >= 2.0:
        return "Satisfactory"
    return "Unsatisfactory"


def load_values(term: str, vp_id: str) -> Dict[str, Tuple]:
    q = "SELECT metric_id, actual, auto_score, override_score, override_reason, notes, updated_at FROM metric_values WHERE term=%s AND vp_id=%s" if db.is_pg else "SELECT metric_id, actual, auto_score, override_score, override_reason, notes, updated_at FROM metric_values WHERE term=? AND vp_id=?"
    rows = db.fetchall(q, (term, vp_id))
    return {r[0]: r for r in rows}


def upsert(term: str, vp_id: str, metric_id: str, actual=None, auto_score=None, override_score=None, override_reason=None, notes=None):
    updated = datetime.utcnow().isoformat(timespec="seconds")
    if db.is_pg:
        sql = """INSERT INTO metric_values(term,vp_id,metric_id,actual,auto_score,override_score,override_reason,notes,updated_at)
                 VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s)
                 ON CONFLICT(term,vp_id,metric_id) DO UPDATE SET
                 actual=EXCLUDED.actual, auto_score=EXCLUDED.auto_score, override_score=EXCLUDED.override_score,
                 override_reason=EXCLUDED.override_reason, notes=EXCLUDED.notes, updated_at=EXCLUDED.updated_at"""
        with db.session() as conn:
            cur = conn.cursor()
            cur.execute(sql, (term, vp_id, metric_id, actual, auto_score, override_score, override_reason, notes, updated))
    else:
        with db.session() as conn:
            cur = conn.cursor()
            cur.execute("INSERT OR IGNORE INTO metric_values(term,vp_id,metric_id,updated_at) VALUES(?,?,?,?)", (term, vp_id, metric_id, updated))
            cur.execute("""UPDATE metric_values SET actual=?, auto_score=?, override_score=?, override_reason=?, notes=?, updated_at=?
                           WHERE term=? AND vp_id=? AND metric_id=?""", (actual, auto_score, override_score, override_reason, notes, updated, term, vp_id, metric_id))

