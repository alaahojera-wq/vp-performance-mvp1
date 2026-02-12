from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from starlette.middleware.sessions import SessionMiddleware
import sqlite3, os, hashlib, secrets, time

APP_NAME = "VP Performance System (MVP)"
DB_PATH = os.environ.get("VP_DB_PATH", "vp.db")

def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = db()
    cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL
    )""")
    cur.execute("""
    CREATE TABLE IF NOT EXISTS vps(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT UNIQUE
    )""")
    cur.execute("""
    CREATE TABLE IF NOT EXISTS terms(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        label TEXT UNIQUE NOT NULL
    )""")
    cur.execute("""
    CREATE TABLE IF NOT EXISTS metrics(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        pillar TEXT NOT NULL,
        name TEXT NOT NULL,
        target TEXT,
        weight REAL NOT NULL DEFAULT 1.0
    )""")
    cur.execute("""
    CREATE TABLE IF NOT EXISTS entries(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        vp_id INTEGER NOT NULL,
        term_id INTEGER NOT NULL,
        metric_id INTEGER NOT NULL,
        actual REAL,
        score INTEGER,
        override_score INTEGER,
        override_reason TEXT,
        notes TEXT,
        updated_at INTEGER NOT NULL,
        UNIQUE(vp_id, term_id, metric_id),
        FOREIGN KEY(vp_id) REFERENCES vps(id),
        FOREIGN KEY(term_id) REFERENCES terms(id),
        FOREIGN KEY(metric_id) REFERENCES metrics(id)
    )""")
    conn.commit()

    # Seed demo users and data if empty
    if cur.execute("SELECT COUNT(*) c FROM users").fetchone()["c"] == 0:
        def ph(pw:str)->str:
            return hashlib.sha256(pw.encode("utf-8")).hexdigest()
        cur.execute("INSERT INTO users(email,password_hash,role) VALUES(?,?,?)", ("admin@local", ph("admin123"), "admin"))
        cur.execute("INSERT INTO users(email,password_hash,role) VALUES(?,?,?)", ("principal@local", ph("principal123"), "principal"))
        cur.execute("INSERT INTO users(email,password_hash,role) VALUES(?,?,?)", ("vp@local", ph("vp123"), "vp"))
        conn.commit()

    if cur.execute("SELECT COUNT(*) c FROM vps").fetchone()["c"] == 0:
        cur.execute("INSERT INTO vps(name,email) VALUES(?,?)", ("Demo VP", "vp@local"))
        conn.commit()

    if cur.execute("SELECT COUNT(*) c FROM terms").fetchone()["c"] == 0:
        cur.execute("INSERT INTO terms(label) VALUES(?)", ("2025-26 Term 1",))
        conn.commit()

    if cur.execute("SELECT COUNT(*) c FROM metrics").fetchone()["c"] == 0:
        # Minimal metric set aligned with 3 pillars & 60/20/20.
        # You can edit/add later.
        metrics = [
            ("Pillar 1: Academic Outcomes (60%)", "Internal assessments achievement (%)", ">=80%", 1.0),
            ("Pillar 1: Academic Outcomes (60%)", "Pass rate (%)", ">=97%", 1.0),
            ("Pillar 1: Academic Outcomes (60%)", "Benchmark improvement (%)", ">=80%", 1.0),

            ("Pillar 2: VP Responsibilities (20%)", "Weekly plans submitted on time (%)", "100%", 1.0),
            ("Pillar 2: VP Responsibilities (20%)", "Meetings conducted (count)", ">=2 / month", 1.0),
            ("Pillar 2: VP Responsibilities (20%)", "Classroom observations completed (count)", ">=X", 1.0),

            ("Pillar 3: School Culture & Professionalism (20%)", "Staff attendance (%)", ">=96%", 1.0),
            ("Pillar 3: School Culture & Professionalism (20%)", "Behaviour incidents resolved (%)", "100%", 1.0),
            ("Pillar 3: School Culture & Professionalism (20%)", "Parent queries responded within 48h (%)", "100%", 1.0),
        ]
        cur.executemany("INSERT INTO metrics(pillar,name,target,weight) VALUES(?,?,?,?)", metrics)
        conn.commit()
    conn.close()

def get_user(request: Request):
    email = request.session.get("user_email")
    if not email:
        return None
    conn = db()
    u = conn.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    conn.close()
    return u

def require_login(request: Request):
    u = get_user(request)
    if not u:
        return RedirectResponse("/login", status_code=302)
    return u

def compute_score_from_actual(actual: float|None):
    """Simple default rubric for percentage-like metrics.
    You can override per metric later; for MVP we keep it consistent:
    >=100 -> 4, >=90 -> 3, >=80 -> 2, else 1
    If None -> None
    """
    if actual is None:
        return None
    if actual >= 100:
        return 4
    if actual >= 90:
        return 3
    if actual >= 80:
        return 2
    return 1

PILLAR_WEIGHTS = {
    "Pillar 1: Academic Outcomes (60%)": 0.60,
    "Pillar 2: VP Responsibilities (20%)": 0.20,
    "Pillar 3: School Culture & Professionalism (20%)": 0.20,
}

def overall_rating(score: float|None):
    if score is None:
        return ("Incomplete", "")
    if score >= 3.6:
        return ("Outstanding", "🏆")
    if score >= 3.0:
        return ("Very Good", "✅")
    if score >= 2.0:
        return ("Satisfactory", "⚠️")
    return ("Unsatisfactory", "❌")

def layout(title:str, body:str, user=None):
    nav = ""
    if user:
        nav = f"""
        <div style="display:flex; gap:12px; align-items:center; justify-content:space-between; padding:10px 0;">
          <div><b>{APP_NAME}</b></div>
          <div style="display:flex; gap:10px; align-items:center;">
            <span style="color:#555">{user['email']} • {user['role']}</span>
            <a href="/dashboard">Dashboard</a>
            <a href="/logout">Logout</a>
          </div>
        </div>
        <hr/>
        """
    return f"""<!doctype html>
<html>
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>{title}</title>
  <style>
    body {{ font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial; max-width: 1050px; margin: 0 auto; padding: 18px; }}
    a {{ color: #0b57d0; text-decoration: none; }}
    a:hover {{ text-decoration: underline; }}
    .card {{ border:1px solid #eee; border-radius: 14px; padding: 14px; margin: 12px 0; box-shadow: 0 1px 3px rgba(0,0,0,0.04); }}
    .grid {{ display:grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 12px; }}
    table {{ width:100%; border-collapse: collapse; }}
    th, td {{ padding: 10px; border-bottom: 1px solid #eee; vertical-align: top; }}
    th {{ text-align:left; background:#fafafa; }}
    .pill {{ display:inline-block; padding:4px 10px; border-radius: 999px; background:#f3f6ff; }}
    .muted {{ color:#666; }}
    input, textarea, select {{ width:100%; padding:10px; border:1px solid #ddd; border-radius: 10px; }}
    button {{ padding:10px 12px; border:0; border-radius: 10px; background:#111; color:#fff; cursor:pointer; }}
    button.secondary {{ background:#f3f3f3; color:#111; }}
    .row {{ display:grid; grid-template-columns: 1fr 1fr; gap: 12px; }}
    @media (max-width:700px) {{ .row {{ grid-template-columns: 1fr; }} }}
  </style>
</head>
<body>
{nav}
{body}
</body>
</html>"""

app = FastAPI()
app.add_middleware(SessionMiddleware, secret_key=os.environ.get("SESSION_SECRET", "dev-secret-change-me"))

@app.on_event("startup")
def _startup():
    init_db()

@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    u = get_user(request)
    if u:
        return RedirectResponse("/dashboard", status_code=302)
    return RedirectResponse("/login", status_code=302)

@app.get("/login", response_class=HTMLResponse)
def login_get():
    body = """
    <div class="card">
      <h2>Login</h2>
      <form method="post">
        <label>Email</label>
        <input name="email" placeholder="principal@local" required/>
        <div style="height:10px"></div>
        <label>Password</label>
        <input name="password" type="password" placeholder="••••••••" required/>
        <div style="height:14px"></div>
        <button type="submit">Sign in</button>
      </form>
      <p class="muted" style="margin-top:14px">
        Demo accounts:<br/>
        admin@local / admin123<br/>
        principal@local / principal123<br/>
        vp@local / vp123
      </p>
    </div>
    """
    return layout("Login", body, None)

@app.post("/login")
def login_post(request: Request, email: str = Form(...), password: str = Form(...)):
    conn = db()
    u = conn.execute("SELECT * FROM users WHERE email=?", (email.strip().lower(),)).fetchone()
    conn.close()
    if not u:
        return HTMLResponse(layout("Login", "<p>Invalid login. <a href='/login'>Try again</a>.</p>"))
    ph = hashlib.sha256(password.encode("utf-8")).hexdigest()
    if ph != u["password_hash"]:
        return HTMLResponse(layout("Login", "<p>Invalid login. <a href='/login'>Try again</a>.</p>"))
    request.session["user_email"] = u["email"]
    return RedirectResponse("/dashboard", status_code=302)

@app.get("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/login", status_code=302)

@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request):
    u = require_login(request)
    if isinstance(u, RedirectResponse):
        return u
    conn = db()
    vps = conn.execute("SELECT * FROM vps ORDER BY name").fetchall()
    terms = conn.execute("SELECT * FROM terms ORDER BY id DESC").fetchall()
    conn.close()

    term_options = "".join([f"<option value='{t['id']}'>{t['label']}</option>" for t in terms])
    body = f"""
    <div class="card">
      <h2>Dashboard</h2>
      <div class="row">
        <div>
          <label class="muted">Select term</label>
          <select id="term">{term_options}</select>
        </div>
        <div style="display:flex; align-items:end; gap:10px;">
          <button onclick="go()">Open term</button>
          <a class="muted" href="/admin" style="margin-left:8px;">Admin</a>
        </div>
      </div>
      <script>
        function go(){{
          const term = document.getElementById('term').value;
          window.location = `/term/${{term}}`;
        }}
      </script>
    </div>

    <div class="card">
      <h3>VPS</h3>
      <table>
        <tr><th>Name</th><th>Action</th></tr>
        {''.join([f"<tr><td>{vp['name']}</td><td><a href='#' onclick='openVp({vp['id']});return false;'>Open</a></td></tr>" for vp in vps])}
      </table>
      <script>
        function openVp(id){{
          const term = document.getElementById('term').value;
          window.location = `/vp/${{id}}?term_id=${{term}}`;
        }}
      </script>
    </div>
    """
    return layout("Dashboard", body, u)

@app.get("/term/{term_id}", response_class=HTMLResponse)
def term_summary(request: Request, term_id: int):
    u = require_login(request)
    if isinstance(u, RedirectResponse):
        return u
    conn = db()
    term = conn.execute("SELECT * FROM terms WHERE id=?", (term_id,)).fetchone()
    vps = conn.execute("SELECT * FROM vps ORDER BY name").fetchall()
    metrics = conn.execute("SELECT * FROM metrics").fetchall()

    # compute overall per VP
    rows = []
    for vp in vps:
        # gather entry scores
        entries = conn.execute("""
            SELECT e.*, m.pillar, m.weight FROM entries e
            JOIN metrics m ON m.id=e.metric_id
            WHERE e.vp_id=? AND e.term_id=?
        """, (vp["id"], term_id)).fetchall()
        # for metrics without entries, treat as missing
        pillar_scores = {}
        pillar_counts = {}
        for e in entries:
            s = e["override_score"] if e["override_score"] is not None else e["score"]
            if s is None:
                continue
            pillar = e["pillar"]
            pillar_scores[pillar] = pillar_scores.get(pillar, 0.0) + float(s)
            pillar_counts[pillar] = pillar_counts.get(pillar, 0) + 1
        overall = 0.0
        has_any = False
        for pillar, w in PILLAR_WEIGHTS.items():
            if pillar_counts.get(pillar, 0) > 0:
                has_any = True
                avg = pillar_scores[pillar] / pillar_counts[pillar]
                overall += avg * w
        ov = overall if has_any else None
        r, emoji = overall_rating(ov)
        rows.append((vp["id"], vp["name"], ov, r, emoji))

    conn.close()

    body = f"""
    <div class="card">
      <h2>Term Summary</h2>
      <div class="muted">Term: <b>{term['label']}</b></div>
    </div>
    <div class="card">
      <table>
        <tr><th>VP</th><th>Overall (0–4)</th><th>Rating</th><th>Open</th></tr>
        {''.join([f"<tr><td>{name}</td><td>{'' if ov is None else f'{ov:.2f}'}</td><td>{emoji} {rating}</td><td><a href='/vp/{vp_id}?term_id={term_id}'>View</a></td></tr>" for vp_id,name,ov,rating,emoji in rows])}
      </table>
      <div style="margin-top:10px"><a href="/dashboard">← Back</a></div>
    </div>
    """
    return layout("Term Summary", body, u)

@app.get("/vp/{vp_id}", response_class=HTMLResponse)
def vp_view(request: Request, vp_id: int, term_id: int):
    u = require_login(request)
    if isinstance(u, RedirectResponse):
        return u
    conn = db()
    vp = conn.execute("SELECT * FROM vps WHERE id=?", (vp_id,)).fetchone()
    term = conn.execute("SELECT * FROM terms WHERE id=?", (term_id,)).fetchone()
    metrics = conn.execute("SELECT * FROM metrics ORDER BY pillar, id").fetchall()

    # ensure entry rows exist
    now = int(time.time())
    for m in metrics:
        conn.execute("""
        INSERT OR IGNORE INTO entries(vp_id,term_id,metric_id,updated_at) VALUES(?,?,?,?)
        """, (vp_id, term_id, m["id"], now))
    conn.commit()

    entries = conn.execute("""
      SELECT e.*, m.pillar, m.name as metric_name, m.target
      FROM entries e JOIN metrics m ON m.id=e.metric_id
      WHERE e.vp_id=? AND e.term_id=?
      ORDER BY m.pillar, m.id
    """, (vp_id, term_id)).fetchall()

    # compute pillar & overall
    pillar_scores = {}
    pillar_counts = {}
    for e in entries:
        s = e["override_score"] if e["override_score"] is not None else e["score"]
        if s is None:
            continue
        pillar = e["pillar"]
        pillar_scores[pillar] = pillar_scores.get(pillar, 0.0) + float(s)
        pillar_counts[pillar] = pillar_counts.get(pillar, 0) + 1

    overall = 0.0
    has_any = False
    pillar_lines = []
    for pillar, w in PILLAR_WEIGHTS.items():
        if pillar_counts.get(pillar, 0) > 0:
            has_any = True
            avg = pillar_scores[pillar] / pillar_counts[pillar]
            overall += avg * w
            pillar_lines.append(f"<div><span class='pill'>{pillar}</span> <span class='muted'>avg:</span> <b>{avg:.2f}</b> <span class='muted'>weight:</span> {int(w*100)}%</div>")
        else:
            pillar_lines.append(f"<div><span class='pill'>{pillar}</span> <span class='muted'>avg:</span> — <span class='muted'>weight:</span> {int(w*100)}%</div>")

    ov = overall if has_any else None
    rating, emoji = overall_rating(ov)

    # Build table rows grouped by pillar
    rows_html = ""
    current_pillar = None
    for e in entries:
        if e["pillar"] != current_pillar:
            current_pillar = e["pillar"]
            rows_html += f"<tr><th colspan='7'>{current_pillar}</th></tr>"
        actual = "" if e["actual"] is None else str(e["actual"])
        score = "" if e["score"] is None else str(e["score"])
        ovr = "" if e["override_score"] is None else str(e["override_score"])
        rows_html += f"""
        <tr>
          <td style="width:22%"><b>{e['metric_name']}</b><div class="muted">Target: {e['target'] or '-'}</div></td>
          <td style="width:10%">
            <form method="post" action="/vp/{vp_id}/actual?term_id={term_id}" style="display:flex; gap:8px;">
              <input name="entry_id" type="hidden" value="{e['id']}"/>
              <input name="actual" placeholder="e.g. 92" value="{actual}"/>
              <button type="submit">Save</button>
            </form>
          </td>
          <td style="width:8%">{score}</td>
          <td style="width:10%">
            <form method="post" action="/vp/{vp_id}/override?term_id={term_id}" style="display:flex; gap:8px;">
              <input name="entry_id" type="hidden" value="{e['id']}"/>
              <input name="override_score" placeholder="1-4" value="{ovr}" {'disabled' if u['role']=='vp' else ''}/>
              <button type="submit" {'disabled' if u['role']=='vp' else ''}>Set</button>
            </form>
          </td>
          <td style="width:18%">
            <form method="post" action="/vp/{vp_id}/override_reason?term_id={term_id}">
              <input name="entry_id" type="hidden" value="{e['id']}"/>
              <input name="override_reason" placeholder="Reason (required if override)" value="{(e['override_reason'] or '')}" {'disabled' if u['role']=='vp' else ''}/>
              <button type="submit" class="secondary" {'disabled' if u['role']=='vp' else ''}>Save</button>
            </form>
          </td>
          <td style="width:22%">
            <form method="post" action="/vp/{vp_id}/notes?term_id={term_id}">
              <input name="entry_id" type="hidden" value="{e['id']}"/>
              <input name="notes" placeholder="Evidence / notes" value="{(e['notes'] or '')}"/>
              <button type="submit" class="secondary">Save</button>
            </form>
          </td>
          <td style="width:10%" class="muted">{time.strftime('%Y-%m-%d', time.localtime(e['updated_at']))}</td>
        </tr>
        """

    conn.close()

    body = f"""
    <div class="card">
      <h2>{vp['name']}</h2>
      <div class="muted">Term: <b>{term['label']}</b></div>
      <div style="margin-top:10px" class="grid">
        <div class="card">
          <div class="muted">Overall</div>
          <div style="font-size:34px; font-weight:800;">{'' if ov is None else f'{ov:.2f}'} {emoji}</div>
          <div class="muted">{rating}</div>
        </div>
        <div class="card">
          <div class="muted">Pillars</div>
          {''.join(pillar_lines)}
        </div>
      </div>
      <div style="margin-top:10px"><a href="/term/{term_id}">← Term summary</a> • <a href="/dashboard">Dashboard</a></div>
    </div>

    <div class="card">
      <h3>Metrics</h3>
      <div class="muted">Enter actual values to auto-calculate scores. Principal/Admin can override score with reason.</div>
      <table>
        <tr>
          <th>Metric</th><th>Actual</th><th>Auto Score</th><th>Override</th><th>Override Reason</th><th>Notes</th><th>Updated</th>
        </tr>
        {rows_html}
      </table>
    </div>
    """
    return layout(f"{vp['name']} • {term['label']}", body, u)

@app.post("/vp/{vp_id}/actual")
def set_actual(request: Request, vp_id: int, term_id: int, entry_id: int = Form(...), actual: str = Form(...)):
    u = require_login(request)
    if isinstance(u, RedirectResponse):
        return u
    actual_val = None
    try:
        actual_val = float(actual) if actual.strip() != "" else None
    except:
        actual_val = None
    score = compute_score_from_actual(actual_val)
    conn = db()
    conn.execute("UPDATE entries SET actual=?, score=?, updated_at=? WHERE id=?",
                 (actual_val, score, int(time.time()), entry_id))
    conn.commit()
    conn.close()
    return RedirectResponse(f"/vp/{vp_id}?term_id={term_id}", status_code=302)

@app.post("/vp/{vp_id}/override")
def set_override(request: Request, vp_id: int, term_id: int, entry_id: int = Form(...), override_score: str = Form(...)):
    u = require_login(request)
    if isinstance(u, RedirectResponse):
        return u
    if u["role"] == "vp":
        return RedirectResponse(f"/vp/{vp_id}?term_id={term_id}", status_code=302)
    val = None
    try:
        v = int(override_score)
        if v in (1,2,3,4):
            val = v
    except:
        val = None
    conn = db()
    conn.execute("UPDATE entries SET override_score=?, updated_at=? WHERE id=?",
                 (val, int(time.time()), entry_id))
    conn.commit()
    conn.close()
    return RedirectResponse(f"/vp/{vp_id}?term_id={term_id}", status_code=302)

@app.post("/vp/{vp_id}/override_reason")
def set_override_reason(request: Request, vp_id: int, term_id: int, entry_id: int = Form(...), override_reason: str = Form(...)):
    u = require_login(request)
    if isinstance(u, RedirectResponse):
        return u
    if u["role"] == "vp":
        return RedirectResponse(f"/vp/{vp_id}?term_id={term_id}", status_code=302)
    conn = db()
    conn.execute("UPDATE entries SET override_reason=?, updated_at=? WHERE id=?",
                 (override_reason.strip(), int(time.time()), entry_id))
    conn.commit()
    conn.close()
    return RedirectResponse(f"/vp/{vp_id}?term_id={term_id}", status_code=302)

@app.post("/vp/{vp_id}/notes")
def set_notes(request: Request, vp_id: int, term_id: int, entry_id: int = Form(...), notes: str = Form(...)):
    u = require_login(request)
    if isinstance(u, RedirectResponse):
        return u
    conn = db()
    conn.execute("UPDATE entries SET notes=?, updated_at=? WHERE id=?",
                 (notes.strip(), int(time.time()), entry_id))
    conn.commit()
    conn.close()
    return RedirectResponse(f"/vp/{vp_id}?term_id={term_id}", status_code=302)

@app.get("/admin", response_class=HTMLResponse)
def admin_page(request: Request):
    u = require_login(request)
    if isinstance(u, RedirectResponse):
        return u
    if u["role"] not in ("admin","principal"):
        return RedirectResponse("/dashboard", status_code=302)

    conn = db()
    terms = conn.execute("SELECT * FROM terms ORDER BY id DESC").fetchall()
    vps = conn.execute("SELECT * FROM vps ORDER BY name").fetchall()
    conn.close()

    body = f"""
    <div class="card">
      <h2>Admin</h2>
      <div class="muted">Quick setup for MVP. (User management + imports can be added next.)</div>
    </div>

    <div class="grid">
      <div class="card">
        <h3>Add Term</h3>
        <form method="post" action="/admin/add_term">
          <input name="label" placeholder="e.g. 2025-26 Term 2" required/>
          <div style="height:10px"></div>
          <button type="submit">Add</button>
        </form>
        <div style="margin-top:10px" class="muted">Existing terms: {", ".join([t["label"] for t in terms])}</div>
      </div>

      <div class="card">
        <h3>Add VP</h3>
        <form method="post" action="/admin/add_vp">
          <input name="name" placeholder="VP name" required/>
          <div style="height:10px"></div>
          <input name="email" placeholder="VP email (optional)"/>
          <div style="height:10px"></div>
          <button type="submit">Add</button>
        </form>
        <div style="margin-top:10px" class="muted">Existing VPs: {", ".join([vp["name"] for vp in vps])}</div>
      </div>
    </div>

    <div class="card"><a href="/dashboard">← Back</a></div>
    """
    return layout("Admin", body, u)

@app.post("/admin/add_term")
def add_term(request: Request, label: str = Form(...)):
    u = require_login(request)
    if isinstance(u, RedirectResponse):
        return u
    if u["role"] not in ("admin","principal"):
        return RedirectResponse("/dashboard", status_code=302)
    conn = db()
    conn.execute("INSERT OR IGNORE INTO terms(label) VALUES(?)", (label.strip(),))
    conn.commit()
    conn.close()
    return RedirectResponse("/admin", status_code=302)

@app.post("/admin/add_vp")
def add_vp(request: Request, name: str = Form(...), email: str = Form(None)):
    u = require_login(request)
    if isinstance(u, RedirectResponse):
        return u
    if u["role"] not in ("admin","principal"):
        return RedirectResponse("/dashboard", status_code=302)
    conn = db()
    conn.execute("INSERT INTO vps(name,email) VALUES(?,?)", (name.strip(), (email or "").strip() or None))
    conn.commit()
    conn.close()
    return RedirectResponse("/admin", status_code=302)
