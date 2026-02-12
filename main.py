
from __future__ import annotations

import os
import sqlite3
from dataclasses import dataclass
from typing import Optional, Dict, List, Tuple

from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from starlette.middleware.sessions import SessionMiddleware

APP_TITLE = "VP Performance System (MVP)"
TERM_LABEL = "2025-26 Term 1"

# --- Auth (demo) ---
# --- Auth (demo) ---
def build_users() -> dict:
    # You can change ONLY the admin login via environment variables on Render:
    # ADMIN_EMAIL, ADMIN_PASSWORD
    admin_email = os.getenv("ADMIN_EMAIL", "admin@local").strip().lower()
    admin_password = os.getenv("ADMIN_PASSWORD", "admin123")
    return {
        admin_email: {"password": admin_password, "role": "admin"},
        "principal@local": {"password": os.getenv("PRINCIPAL_PASSWORD", "principal123"), "role": "principal"},
        "vp@local": {"password": os.getenv("VP_PASSWORD", "vp123"), "role": "vp"},
    }

USERS = build_users()

def get_secret_key() -> str:
    # Render: set SECRET_KEY env var in service settings for production
    return os.environ.get("SECRET_KEY", "dev-secret-change-me")

# --- Data model ---
@dataclass
class Metric:
    id: str
    pillar: int
    pillar_name: str
    name: str
    target_text: str
    target_value: Optional[float]  # numeric target where applicable (e.g., 80 for 80%)

PILLARS = {
    1: ("Academic Outcomes (60%)", 0.60),
    2: ("VP Responsibilities (20%)", 0.20),
    3: ("School Culture & Professionalism (20%)", 0.20),
}

# Minimal metric set (extend anytime)
METRICS: List[Metric] = [
    Metric("p1_internal", 1, PILLARS[1][0], "Internal assessments achievement (%)", "Target: ≥80%", 80.0),
    Metric("p1_passrate", 1, PILLARS[1][0], "Pass rate (%)", "Target: ≥97%", 97.0),
    Metric("p1_benchmark", 1, PILLARS[1][0], "Benchmark improvement (%)", "Target: ≥80%", 80.0),

    Metric("p2_attendance", 2, PILLARS[2][0], "Student attendance (%)", "Target: ≥92%", 92.0),
    Metric("p2_parent_sla", 2, PILLARS[2][0], "Parent communication SLA (%)", "Target: 100% within 48h", 100.0),

    Metric("p3_staff_att", 3, PILLARS[3][0], "Staff attendance (%)", "Target: ≥96%", 96.0),
    Metric("p3_turnover", 3, PILLARS[3][0], "Staff turnover (%)", "Target: ≤25%", None),  # special (lower is better) later
]

# --- SQLite storage ---
DB_PATH = os.environ.get("DB_PATH", "vp_perf.db")

def db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = db()
    cur = conn.cursor()
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
    cur.execute("""
    CREATE TABLE IF NOT EXISTS vps (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        email TEXT,
        phase TEXT,
        notes TEXT
    )
""")
# Seed a demo VP if none exist
cur.execute("SELECT COUNT(1) AS c FROM vps")
if cur.fetchone()["c"] == 0:
    cur.execute(
        "INSERT INTO vps (id, name, email, phase, notes) VALUES (?, ?, ?, ?, ?)",
        ("demo_vp", "Demo VP", "", "", "")
    )

conn.commit()
    conn.close()

# --- Scoring ---
def compute_auto_score(metric: Metric, actual: Optional[float]) -> Optional[int]:
    if actual is None:
        return None
    # Special case: turnover lower is better (simple rule for now)
    if metric.id == "p3_turnover":
        # Target ≤25% : 3, ≤15% : 4, 26–35% : 2, >35% : 1
        if actual <= 15:
            return 4
        if actual <= 25:
            return 3
        if actual <= 35:
            return 2
        return 1

    if metric.target_value is None:
        return None

    tgt = metric.target_value
    # Generic % rubric:
    # >= tgt+10 => 4, >= tgt => 3, >= tgt-10 => 2, else 1
    if actual >= tgt + 10:
        return 4
    if actual >= tgt:
        return 3
    if actual >= max(0, tgt - 10):
        return 2
    return 1

def rating_from_score(score: Optional[float]) -> str:
    if score is None:
        return "Incomplete"
    if score >= 3.6:
        return "Outstanding"
    if score >= 3.0:
        return "Very Good"
    if score >= 2.0:
        return "Satisfactory"
    return "Unsatisfactory"

# --- HTML helpers ---
def html_page(title: str, body: str, user: Optional[dict] = None) -> HTMLResponse:
    topbar = ""
    if user:
        topbar = f"""
        <div class="topbar">
          <div class="brand">{APP_TITLE}</div>
          <div class="userbox">{user['email']} • {user['role']} &nbsp; <a href="/dashboard">Dashboard</a>{' &nbsp; <a href="/admin/vps">Admin</a>' if user.get('role')=='admin' else ''} &nbsp; <a href="/logout">Logout</a></div>
        </div>
        """
    html = f"""<!doctype html>
<html>
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>{title}</title>
  <style>
    body{{font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial; margin:0; background:#fafafa; color:#111;}}
    .topbar{{display:flex; justify-content:space-between; align-items:center; padding:14px 18px; background:#fff; border-bottom:1px solid #e5e5e5;}}
    .brand{{font-weight:700;}}
    .container{{max-width:1100px; margin:24px auto; padding:0 16px;}}
    .card{{background:#fff; border:1px solid #e8e8e8; border-radius:14px; padding:16px; box-shadow:0 1px 2px rgba(0,0,0,.03);}}
    .grid{{display:grid; grid-template-columns: 1fr 1fr; gap:14px;}}
    @media (max-width: 860px){{ .grid{{grid-template-columns:1fr;}} }}
    h1,h2{{margin:0 0 12px 0;}}
    .muted{{color:#666; font-size:14px;}}
    table{{width:100%; border-collapse:collapse;}}
    th, td{{padding:10px 8px; border-bottom:1px solid #eee; vertical-align:top;}}
    th{{text-align:left; font-size:13px; color:#444;}}
    .pill{{display:inline-block; padding:2px 10px; border-radius:999px; border:1px solid #ddd; font-size:12px; background:#fff;}}
    input[type="number"], input[type="text"], textarea{{width:100%; padding:10px 10px; border:1px solid #ddd; border-radius:10px; font-size:14px; background:#fff;}}
    textarea{{min-height:60px; resize:vertical;}}
    .btn{{display:inline-block; padding:9px 12px; border-radius:10px; border:1px solid #111; background:#111; color:#fff; cursor:pointer; font-size:14px;}}
    .btn.secondary{{background:#fff; color:#111;}}
    .rowform{{display:grid; grid-template-columns: 130px 110px 1fr 120px; gap:8px; align-items:center;}}
    @media (max-width: 860px){{ .rowform{{grid-template-columns:1fr;}} }}
    .small{{font-size:12px; color:#666;}}
    .danger{{color:#b00020;}}
    .success{{color:#137333;}}
    .spacer{{height:10px;}}
  </style>
</head>
<body>
{topbar}
<div class="container">
{body}
</div>
</body>
</html>"""
    return HTMLResponse(html)

def require_login(request: Request) -> Optional[dict]:
    user = request.session.get("user")
    return user

def redirect(to: str) -> RedirectResponse:
    return RedirectResponse(to, status_code=303)

# --- App ---
app = FastAPI()
app.add_middleware(SessionMiddleware, secret_key=get_secret_key())

@app.on_event("startup")
def _startup():
    init_db()

@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    user = require_login(request)
    if user:
        return redirect("/dashboard")
    return redirect("/login")

@app.get("/login", response_class=HTMLResponse)
def login_get(request: Request):
    msg = request.query_params.get("msg", "")
    body = f"""
    <div class="card">
      <h1>Login</h1>
      <div class="muted">Use demo accounts: principal@local / principal123, vp@local / vp123, admin@local / admin123</div>
      <div class="spacer"></div>
      {"<div class='danger'>"+msg+"</div>" if msg else ""}
      <form method="post" action="/login">
        <div style="display:grid; gap:10px; max-width:420px;">
          <label>Email <input type="text" name="email" placeholder="principal@local" required></label>
          <label>Password <input type="text" name="password" placeholder="principal123" required></label>
          <button class="btn" type="submit">Sign in</button>
        </div>
      </form>
    </div>
    """
    return html_page("Login", body)

@app.post("/login")
def login_post(request: Request, email: str = Form(...), password: str = Form(...)):
    rec = USERS.get(email.strip().lower())
    if not rec or rec["password"] != password:
        return redirect("/login?msg=Invalid%20credentials")
    request.session["user"] = {"email": email.strip().lower(), "role": rec["role"]}
    return redirect("/dashboard")

@app.get("/logout")
def logout(request: Request):
    request.session.clear()
    return redirect("/login?msg=Logged%20out")

# --- Views ---
def list_vps() -> List[Dict[str, str]]:
    conn = db()
    cur = conn.cursor()
    cur.execute("SELECT id, name, email, phase, notes FROM vps ORDER BY name")
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows

def get_vp(vp_id: str) -> Optional[Dict[str, str]]:
    conn = db()
    cur = conn.cursor()
    cur.execute("SELECT id, name, email, phase, notes FROM vps WHERE id=?", (vp_id,))
    row = cur.fetchone()
    conn.close()
    return dict(row) if row else None


def fetch_metric_rows(term: str, vp_id: str) -> Dict[str, sqlite3.Row]:
    conn = db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM metric_values WHERE term=? AND vp_id=?", (term, vp_id))
    rows = {r["metric_id"]: r for r in cur.fetchall()}
    conn.close()
    return rows

def upsert_metric(term: str, vp_id: str, metric_id: str, **kwargs):
    conn = db()
    cur = conn.cursor()
    cur.execute("SELECT 1 FROM metric_values WHERE term=? AND vp_id=? AND metric_id=?", (term, vp_id, metric_id))
    exists = cur.fetchone() is not None
    if not exists:
        cur.execute("""
            INSERT INTO metric_values(term, vp_id, metric_id, actual, auto_score, override_score, override_reason, notes, updated_at)
            VALUES(?,?,?,?,?,?,?,?,datetime('now'))
        """, (term, vp_id, metric_id,
              kwargs.get("actual"),
              kwargs.get("auto_score"),
              kwargs.get("override_score"),
              kwargs.get("override_reason"),
              kwargs.get("notes")))
    else:
        sets = []
        params = []
        for k, v in kwargs.items():
            sets.append(f"{k}=?")
            params.append(v)
        sets.append("updated_at=datetime('now')")
        sql = f"UPDATE metric_values SET {', '.join(sets)} WHERE term=? AND vp_id=? AND metric_id=?"
        params.extend([term, vp_id, metric_id])
        cur.execute(sql, params)
    conn.commit()
    conn.close()

def effective_score(row: Optional[sqlite3.Row]) -> Optional[int]:
    if not row:
        return None
    if row["override_score"] is not None:
        return int(row["override_score"])
    if row["auto_score"] is not None:
        return int(row["auto_score"])
    return None

def compute_summaries(term: str, vp_id: str) -> Tuple[Dict[int, Optional[float]], Optional[float]]:
    rows = fetch_metric_rows(term, vp_id)
    pillar_scores: Dict[int, List[int]] = {1: [], 2: [], 3: []}
    for m in METRICS:
        sc = effective_score(rows.get(m.id))
        if sc is not None:
            pillar_scores[m.pillar].append(sc)

    pillar_avg: Dict[int, Optional[float]] = {}
    overall_parts = []
    for p, scores in pillar_scores.items():
        avg = sum(scores) / len(scores) if scores else None
        pillar_avg[p] = avg
        if avg is not None:
            overall_parts.append(avg * PILLARS[p][1])

    overall = sum(overall_parts) if overall_parts else None
    return pillar_avg, overall

@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request):
    user = require_login(request)
    if not user:
        return redirect("/login")
    items = []
    for vp in list_vps():
        pillar_avg, overall = compute_summaries(TERM_LABEL, vp["id"])
        items.append(f"""
          <tr>
            <td><a href="/vp/{vp['id']}">{vp['name']}</a></td>
            <td>{TERM_LABEL}</td>
            <td><span class="pill">{rating_from_score(overall)}</span></td>
          </tr>
        """)
    body = f"""
    <div class="card">
      <h1>Dashboard</h1>
      <div class="muted">Select a VP to enter actual values, evidence, and finalize a term score.</div>
      <div class="spacer"></div>
      <table>
        <thead><tr><th>VP</th><th>Term</th><th>Overall</th></tr></thead>
        <tbody>
          {''.join(items)}
        </tbody>
      </table>
    </div>
    """
    return html_page("Dashboard", body, user=user)

@app.get("/admin/vps", response_class=HTMLResponse)
def admin_vps(request: Request):
    user = require_login(request)
    if not user:
        return redirect("/login")
    if user["role"] != "admin":
        return html_page("Forbidden", "<div class='card'>Admin only.</div>", user=user)

    rows = list_vps()
    items = []
    for vp in rows:
        items.append(f"""
        <tr>
          <td><code>{vp['id']}</code></td>
          <td>
            <form method="post" action="/admin/vps/{vp['id']}/update" style="display:flex; gap:8px; flex-wrap:wrap; align-items:center;">
              <input name="name" value="{vp.get('name','')}" style="min-width:180px;" />
              <input name="email" value="{vp.get('email','') or ''}" placeholder="email (optional)" style="min-width:180px;" />
              <input name="phase" value="{vp.get('phase','') or ''}" placeholder="phase" style="min-width:120px;" />
              <input name="notes" value="{vp.get('notes','') or ''}" placeholder="notes" style="min-width:220px;" />
              <button class="btn" type="submit">Save</button>
            </form>
          </td>
          <td>
            <form method="post" action="/admin/vps/{vp['id']}/delete" onsubmit="return confirm('Delete this VP?');">
              <button class="btn danger" type="submit">Delete</button>
            </form>
          </td>
        </tr>
        """)

    body = f"""
    <div class="card">
      <h2>Manage VPs</h2>
      <p class="muted">Add/edit VP names and basic info. Principal can view these details.</p>

      <h3>Add VP</h3>
      <form method="post" action="/admin/vps/add" style="display:flex; gap:8px; flex-wrap:wrap; align-items:center;">
        <input name="id" placeholder="id (e.g., vp_primary)" required style="min-width:160px;" />
        <input name="name" placeholder="name" required style="min-width:200px;" />
        <input name="email" placeholder="email (optional)" style="min-width:200px;" />
        <input name="phase" placeholder="phase" style="min-width:120px;" />
        <input name="notes" placeholder="notes" style="min-width:240px;" />
        <button class="btn" type="submit">Add</button>
      </form>

      <h3 style="margin-top:18px;">Existing VPs</h3>
      <table>
        <thead><tr><th>ID</th><th>Details</th><th>Action</th></tr></thead>
        <tbody>
          {''.join(items) if items else '<tr><td colspan="3" class="muted">No VPs yet.</td></tr>'}
        </tbody>
      </table>
    </div>
    """
    return html_page("Admin • VPs", body, user=user)

@app.post("/admin/vps/add")
def admin_add_vp(
    request: Request,
    id: str = Form(...),
    name: str = Form(...),
    email: str = Form(""),
    phase: str = Form(""),
    notes: str = Form(""),
):
    user = require_login(request)
    if not user:
        return redirect("/login")
    if user["role"] != "admin":
        return redirect("/dashboard")

    conn = db()
    cur = conn.cursor()
    cur.execute(
        "INSERT OR REPLACE INTO vps (id, name, email, phase, notes) VALUES (?, ?, ?, ?, ?)",
        (id.strip(), name.strip(), email.strip(), phase.strip(), notes.strip()),
    )
    conn.commit()
    conn.close()
    return redirect("/admin/vps")

@app.post("/admin/vps/{vp_id}/update")
def admin_update_vp(
    request: Request,
    vp_id: str,
    name: str = Form(...),
    email: str = Form(""),
    phase: str = Form(""),
    notes: str = Form(""),
):
    user = require_login(request)
    if not user:
        return redirect("/login")
    if user["role"] != "admin":
        return redirect("/dashboard")

    conn = db()
    cur = conn.cursor()
    cur.execute(
        "UPDATE vps SET name=?, email=?, phase=?, notes=? WHERE id=?",
        (name.strip(), email.strip(), phase.strip(), notes.strip(), vp_id),
    )
    conn.commit()
    conn.close()
    return redirect("/admin/vps")

@app.post("/admin/vps/{vp_id}/delete")
def admin_delete_vp(request: Request, vp_id: str):
    user = require_login(request)
    if not user:
        return redirect("/login")
    if user["role"] != "admin":
        return redirect("/dashboard")

    conn = db()
    cur = conn.cursor()
    cur.execute("DELETE FROM vps WHERE id=?", (vp_id,))
    conn.commit()
    conn.close()
    return redirect("/admin/vps")

@app.get("/vp/{vp_id}", response_class=HTMLResponse)
def vp_view(request: Request, vp_id: str):
    user = require_login(request)
    if not user:
        return redirect("/login")

    vp = get_vp(vp_id)
    if not vp:
        return html_page("Not found", "<div class='card'>VP not found</div>", user=user)

    rows = fetch_metric_rows(TERM_LABEL, vp_id)
    pillar_avg, overall = compute_summaries(TERM_LABEL, vp_id)

    # Summary cards
    pill_lines = []
    for p in (1,2,3):
        avg = pillar_avg.get(p)
        pill_lines.append(f"<div><span class='pill'>Pillar {p}: {PILLARS[p][0]}</span> &nbsp; avg: <b>{'—' if avg is None else f'{avg:.2f}'}</b> &nbsp; weight: {int(PILLARS[p][1]*100)}%</div>")

    summary = f"""
    <div class="card">
      <h1>{vp['name']}</h1>
      <div class="muted">Term: <b>{TERM_LABEL}</b></div>
      <div class="muted">VP info: {vp.get("email","") or "-"} • {vp.get("phase","") or "-"} • {vp.get("notes","") or "-"}</div>
      <div class="spacer"></div>
      <div class="grid">
        <div class="card" style="border-radius:12px;">
          <div class="muted">Overall</div>
          <div style="font-size:28px; font-weight:800;">{rating_from_score(overall)}</div>
          <div class="muted">{'' if overall is None else f'Score: {overall:.2f} / 4.00'}</div>
        </div>
        <div class="card" style="border-radius:12px;">
          <div class="muted">Pillars</div>
          {''.join(pill_lines)}
        </div>
      </div>
    </div>
    """

    # Metrics table with working forms
    table_rows = []
    current_pillar = None
    for m in METRICS:
        if current_pillar != m.pillar:
            current_pillar = m.pillar
            table_rows.append(f"<tr><th colspan='6' style='background:#fafafa'>{PILLARS[m.pillar][0]}</th></tr>")

        r = rows.get(m.id)
        actual = "" if not r or r["actual"] is None else str(r["actual"])
        auto_score = "" if not r or r["auto_score"] is None else str(r["auto_score"])
        override_score = "" if not r or r["override_score"] is None else str(r["override_score"])
        override_reason = "" if not r or r["override_reason"] is None else str(r["override_reason"])
        notes = "" if not r or r["notes"] is None else str(r["notes"])
        updated = "" if not r or r["updated_at"] is None else str(r["updated_at"])[:10]

        table_rows.append(f"""
        <tr>
          <td style="width:260px;">
            <b>{m.name}</b><div class="small">{m.target_text}</div>
          </td>
          <td style="width:170px;">
            <form method="post" action="/vp/{vp_id}/metric/{m.id}/actual" style="display:grid; gap:6px;">
              <input type="number" step="0.1" name="actual" value="{actual}" placeholder="e.g., 85" />
              <button class="btn" type="submit">Save actual</button>
            </form>
          </td>
          <td style="width:90px;">
            <div class="pill">{auto_score or "—"}</div>
            <div class="small">Auto score</div>
          </td>
          <td style="width:220px;">
            <form method="post" action="/vp/{vp_id}/metric/{m.id}/override" style="display:grid; gap:6px;">
              <input type="number" min="1" max="4" name="override_score" value="{override_score}" placeholder="1-4" />
              <input type="text" name="override_reason" value="{override_reason}" placeholder="Reason (required if override)" />
              <button class="btn secondary" type="submit">Set override</button>
            </form>
          </td>
          <td>
            <form method="post" action="/vp/{vp_id}/metric/{m.id}/notes" style="display:grid; gap:6px;">
              <textarea name="notes" placeholder="Evidence / notes">{notes}</textarea>
              <button class="btn secondary" type="submit">Save notes</button>
            </form>
          </td>
          <td style="width:110px;" class="muted">{updated}</td>
        </tr>
        """)

    metrics_card = f"""
    <div class="card" style="margin-top:14px;">
      <h2>Metrics</h2>
      <div class="muted">Enter actual values to auto-calculate scores. Principal/Admin can override (1–4) with a reason.</div>
      <div class="spacer"></div>
      <table>
        <thead>
          <tr>
            <th>Metric</th>
            <th>Actual</th>
            <th>Auto Score</th>
            <th>Override</th>
            <th>Evidence / Notes</th>
            <th>Updated</th>
          </tr>
        </thead>
        <tbody>
          {''.join(table_rows)}
        </tbody>
      </table>
      <div class="spacer"></div>
      <div class="muted">Tip: After saving several metrics, refresh to see pillar averages and overall rating update.</div>
    </div>
    """

    return html_page(vp["name"], summary + metrics_card, user=user)

# --- Mutations ---
@app.post("/vp/{vp_id}/metric/{metric_id}/actual")
def set_actual(request: Request, vp_id: str, metric_id: str, actual: Optional[float] = Form(None)):
    user = require_login(request)
    if not user:
        return redirect("/login")
    metric = next((m for m in METRICS if m.id == metric_id), None)
    if not metric:
        return redirect(f"/vp/{vp_id}")

    # Compute auto score
    auto = compute_auto_score(metric, actual)

    upsert_metric(TERM_LABEL, vp_id, metric_id, actual=actual, auto_score=auto)
    return redirect(f"/vp/{vp_id}")

@app.post("/vp/{vp_id}/metric/{metric_id}/override")
def set_override(request: Request, vp_id: str, metric_id: str, override_score: Optional[int] = Form(None), override_reason: str = Form("")):
    user = require_login(request)
    if not user:
        return redirect("/login")

    # Role guard: only principal/admin
    if user["role"] not in ("principal", "admin"):
        return redirect(f"/vp/{vp_id}")

    # If score set, require reason
    if override_score is not None and (override_reason or "").strip() == "":
        return redirect(f"/vp/{vp_id}")

    upsert_metric(TERM_LABEL, vp_id, metric_id,
                  override_score=override_score,
                  override_reason=(override_reason or "").strip() if override_score is not None else None)
    return redirect(f"/vp/{vp_id}")

@app.post("/vp/{vp_id}/metric/{metric_id}/notes")
def set_notes(request: Request, vp_id: str, metric_id: str, notes: str = Form("")):
    user = require_login(request)
    if not user:
        return redirect("/login")
    upsert_metric(TERM_LABEL, vp_id, metric_id, notes=notes)
    return redirect(f"/vp/{vp_id}")

@app.get("/healthz")
def healthz():
    return {"ok": True}
