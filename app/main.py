import os, hashlib, hmac, secrets
from dataclasses import dataclass
from datetime import datetime
from typing import Optional, Dict, Any, List, Tuple

from fastapi import FastAPI, Request, Form, Depends
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from jinja2 import Environment, FileSystemLoader, select_autoescape

DATABASE_URL = os.getenv("DATABASE_URL","").strip()
BRAND_NAME   = os.getenv("BRAND_NAME","Elite VP Performance Hub")

ADMIN_EMAIL     = os.getenv("ADMIN_EMAIL","admin@local").strip().lower()
ADMIN_PASSWORD  = os.getenv("ADMIN_PASSWORD","admin123")
PRINCIPAL_EMAIL = os.getenv("PRINCIPAL_EMAIL","principal@local").strip().lower()
PRINCIPAL_PASSWORD = os.getenv("PRINCIPAL_PASSWORD","principal123")

SESSION_SECRET = os.getenv("SESSION_SECRET", secrets.token_hex(16))
DEFAULT_TERM   = os.getenv("DEFAULT_TERM","2025-26 Term 1")
from contextlib import contextmanager
APP_DIR   = os.path.dirname(__file__)
TEMPL_DIR = os.path.join(APP_DIR,"templates")
STATIC_DIR= os.path.join(APP_DIR,"static")

# ---------------- DB (Postgres if DATABASE_URL set; else SQLite fallback) ----------------
class DB:
    def __init__(self):
        self.is_pg = bool(DATABASE_URL)
        if self.is_pg:
            import psycopg2
            self.pg = psycopg2

    def connect(self):
        if self.is_pg:
            return self.pg.connect(DATABASE_URL)
        import sqlite3
        data_dir = os.getenv("DATA_DIR",".")
        os.makedirs(data_dir, exist_ok=True)
        conn = sqlite3.connect(os.path.join(data_dir,"vp_perf.db"))
        conn.row_factory = sqlite3.Row
        return conn

    def fetchone(self, sql:str, params:Tuple=()):
        with self.connect() as conn:
            cur = conn.cursor()
            cur.execute(sql, params)
            return cur.fetchone()

    def fetchall(self, sql:str, params:Tuple=()):
        with self.connect() as conn:
            cur = conn.cursor()
            cur.execute(sql, params)
            return cur.fetchall()

    def execute(self, sql:str, params:Tuple=()):
        with self.connect() as conn:
            cur = conn.cursor()
            cur.execute(sql, params)
            conn.commit()

db = DB()

def now_iso():
    return datetime.utcnow().isoformat(timespec="seconds")

# --------------- Password hashing (PBKDF2) ---------------
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

# --------------- Schema init ---------------
def init_db():
    if db.is_pg:
        db.execute("""CREATE TABLE IF NOT EXISTS users(
            email TEXT PRIMARY KEY, role TEXT NOT NULL, password_hash TEXT NOT NULL
        );""")
        db.execute("""CREATE TABLE IF NOT EXISTS vps(
            id TEXT PRIMARY KEY, name TEXT NOT NULL, email TEXT, phase TEXT, notes TEXT
        );""")
        db.execute("""CREATE TABLE IF NOT EXISTS terms(
            id SERIAL PRIMARY KEY, name TEXT NOT NULL UNIQUE,
            is_active BOOLEAN NOT NULL DEFAULT FALSE,
            locked BOOLEAN NOT NULL DEFAULT FALSE
        );""")
        db.execute("""CREATE TABLE IF NOT EXISTS metric_values(
            term TEXT NOT NULL, vp_id TEXT NOT NULL, metric_id TEXT NOT NULL,
            actual DOUBLE PRECISION, auto_score INTEGER, override_score INTEGER,
            override_reason TEXT, notes TEXT, updated_at TEXT,
            PRIMARY KEY(term,vp_id,metric_id)
        );""")
    else:
        db.execute("""CREATE TABLE IF NOT EXISTS users(
            email TEXT PRIMARY KEY, role TEXT NOT NULL, password_hash TEXT NOT NULL
        );""")
        db.execute("""CREATE TABLE IF NOT EXISTS vps(
            id TEXT PRIMARY KEY, name TEXT NOT NULL, email TEXT, phase TEXT, notes TEXT
        );""")
        db.execute("""CREATE TABLE IF NOT EXISTS terms(
            id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE,
            is_active INTEGER NOT NULL DEFAULT 0,
            locked INTEGER NOT NULL DEFAULT 0
        );""")
        db.execute("""CREATE TABLE IF NOT EXISTS metric_values(
            term TEXT NOT NULL, vp_id TEXT NOT NULL, metric_id TEXT NOT NULL,
            actual REAL, auto_score INTEGER, override_score INTEGER,
            override_reason TEXT, notes TEXT, updated_at TEXT,
            PRIMARY KEY(term,vp_id,metric_id)
        );""")

    # seed users
    q = "SELECT COUNT(1) FROM users WHERE email=%s" if db.is_pg else "SELECT COUNT(1) FROM users WHERE email=?"
    c = db.fetchone(q,(ADMIN_EMAIL,))[0]
    if c == 0:
        ins = "INSERT INTO users(email,role,password_hash) VALUES(%s,%s,%s)" if db.is_pg else "INSERT INTO users(email,role,password_hash) VALUES(?,?,?)"
        db.execute(ins,(ADMIN_EMAIL,"admin",_make_password(ADMIN_PASSWORD)))
    c = db.fetchone(q,(PRINCIPAL_EMAIL,))[0]
    if c == 0:
        ins = "INSERT INTO users(email,role,password_hash) VALUES(%s,%s,%s)" if db.is_pg else "INSERT INTO users(email,role,password_hash) VALUES(?,?,?)"
        db.execute(ins,(PRINCIPAL_EMAIL,"principal",_make_password(PRINCIPAL_PASSWORD)))

    # seed vp
    c = db.fetchone("SELECT COUNT(1) FROM vps")[0]
    if c == 0:
        ins = "INSERT INTO vps(id,name,email,phase,notes) VALUES(%s,%s,%s,%s,%s)" if db.is_pg else "INSERT INTO vps(id,name,email,phase,notes) VALUES(?,?,?,?,?)"
        db.execute(ins,("demo_vp","Demo VP","","",""))

    # seed term
    c = db.fetchone("SELECT COUNT(1) FROM terms")[0]
    if c == 0:
        ins = "INSERT INTO terms(name,is_active,locked) VALUES(%s,TRUE,FALSE)" if db.is_pg else "INSERT INTO terms(name,is_active,locked) VALUES(?,1,0)"
        db.execute(ins,(DEFAULT_TERM,))
    else:
        active = db.fetchone("SELECT COUNT(1) FROM terms WHERE is_active=" + ("TRUE" if db.is_pg else "1"))[0]
        if active == 0:
            # activate first
            row = db.fetchone("SELECT id FROM terms ORDER BY id ASC LIMIT 1")
            if row:
                db.execute("UPDATE terms SET is_active=" + ("FALSE" if db.is_pg else "0"))
                db.execute("UPDATE terms SET is_active=" + ("TRUE" if db.is_pg else "1") + " WHERE id=" + ("%s" if db.is_pg else "?"), (row[0],))

init_db()

# --------------- sessions (signed cookie) ---------------
def _sign(value:str)->str:
    sig = hmac.new(SESSION_SECRET.encode(), value.encode(), hashlib.sha256).hexdigest()
    return f"{value}.{sig}"

def _unsign(signed:str)->Optional[str]:
    try:
        value, sig = signed.rsplit(".",1)
        exp = hmac.new(SESSION_SECRET.encode(), value.encode(), hashlib.sha256).hexdigest()
        return value if hmac.compare_digest(sig, exp) else None
    except Exception:
        return None

def get_user(request:Request)->Optional[Dict[str,Any]]:
    tok = request.cookies.get("session")
    if not tok: return None
    email = _unsign(tok)
    if not email: return None
    q = "SELECT email, role FROM users WHERE email=%s" if db.is_pg else "SELECT email, role FROM users WHERE email=?"
    r = db.fetchone(q,(email,))
    if not r: return None
    return {"email": r[0], "role": r[1]}

def require_role(role:str):
    def dep(request:Request):
        u = get_user(request)
        if not u: return RedirectResponse("/login", status_code=303)
        if u["role"] != role: return RedirectResponse("/dashboard", status_code=303)
        return u
    return dep

# --------------- templates ---------------
app = FastAPI()
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
jinja = Environment(loader=FileSystemLoader(TEMPL_DIR), autoescape=select_autoescape(["html","xml"]))

def render(request:Request, template:str, **ctx):
    u = get_user(request)
    flash = request.cookies.get("flash")
    html = jinja.get_template(template).render(user=u, flash=flash, brand_name=BRAND_NAME, **ctx)
    resp = HTMLResponse(html)
    if flash: resp.delete_cookie("flash")
    return resp

def redirect(url:str, flash:Optional[str]=None):
    resp = RedirectResponse(url, status_code=303)
    if flash: resp.set_cookie("flash", flash, max_age=10)
    return resp

# --------------- term helpers ---------------
def get_terms():
    rows = db.fetchall("SELECT id,name,is_active,locked FROM terms ORDER BY is_active DESC, id ASC")
    out=[]
    for r in rows:
        out.append({"id":r[0],"name":r[1],
                    "is_active": bool(r[2]) if db.is_pg else bool(int(r[2])),
                    "locked": bool(r[3]) if db.is_pg else bool(int(r[3]))})
    return out

def get_active_term():
    r = db.fetchone("SELECT name FROM terms WHERE is_active=" + ("TRUE" if db.is_pg else "1") + " LIMIT 1")
    return r[0] if r else DEFAULT_TERM

def term_locked(term_name:str)->bool:
    q = "SELECT locked FROM terms WHERE name=%s" if db.is_pg else "SELECT locked FROM terms WHERE name=?"
    r = db.fetchone(q,(term_name,))
    if not r: return False
    return bool(r[0]) if db.is_pg else bool(int(r[0]))

# --------------- framework metrics ---------------
@dataclass
class Metric:
    id:str; name:str; desc:str; pillar:int; target_type:str; target_value:float; target_text:str

METRICS=[
    Metric("p1_internal","Internal assessments achievement (%)","Achievement percentage based on internal assessments.",1,"gte",80.0,"≥80%"),
    Metric("p1_pass","Pass rate (%)","Overall pass rate for the phase.",1,"gte",97.0,"≥97%"),
    Metric("p1_benchmark","Benchmark improvement (%)","Benchmark improvement percentage.",1,"gte",80.0,"≥80%"),
    Metric("p2_staff_att","Staff attendance (%)","Staff attendance percentage (excluding approved leaves).",2,"gte",96.0,"≥96%"),
    Metric("p2_parent_sla","Parent response within 48h (%)","Parent communications responded to within 48 hours.",2,"gte",100.0,"100%"),
    Metric("p2_plans","Weekly plans submitted on time (%)","Weekly plans submitted on or before deadline.",2,"gte",100.0,"100%"),
    Metric("p3_turnover","Staff turnover (%)","Annual turnover rate (lower is better).",3,"lte",25.0,"≤25%"),
    Metric("p3_pd","PD participation (%)","Participation in professional development activities.",3,"gte",90.0,"≥90%"),
    Metric("p3_culture","School culture initiatives delivered (%)","Completion rate of planned culture initiatives.",3,"gte",90.0,"≥90%"),
]
PILLAR_WEIGHTS={1:0.60,2:0.20,3:0.20}

def compute_auto(m:Metric, actual:Optional[float])->Optional[int]:
    if actual is None: return None
    if m.id=="p3_turnover":
        if actual<=15: return 4
        if actual<=25: return 3
        if actual<=35: return 2
        return 1
    if m.target_type=="gte":
        if actual>=m.target_value+10: return 4
        if actual>=m.target_value: return 3
        if actual>=m.target_value-10: return 2
        return 1
    if m.target_type=="lte":
        if actual<=m.target_value-10: return 4
        if actual<=m.target_value: return 3
        if actual<=m.target_value+10: return 2
        return 1
    return None

def label(score:float)->str:
    if score>=3.6: return "Outstanding"
    if score>=3.0: return "Very Good"
    if score>=2.0: return "Satisfactory"
    return "Unsatisfactory"

def load_values(term:str, vp_id:str)->Dict[str,Tuple]:
    q = "SELECT metric_id, actual, auto_score, override_score, override_reason, notes, updated_at FROM metric_values WHERE term=%s AND vp_id=%s" if db.is_pg else         "SELECT metric_id, actual, auto_score, override_score, override_reason, notes, updated_at FROM metric_values WHERE term=? AND vp_id=?"
    rows = db.fetchall(q,(term,vp_id))
    return {r[0]: r for r in rows}

def upsert(term:str, vp_id:str, metric_id:str, actual=None, auto_score=None, override_score=None, override_reason=None, notes=None):
    updated = now_iso()
    if db.is_pg:
        sql = """INSERT INTO metric_values(term,vp_id,metric_id,actual,auto_score,override_score,override_reason,notes,updated_at)
                 VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s)
                 ON CONFLICT(term,vp_id,metric_id) DO UPDATE SET
                 actual=EXCLUDED.actual, auto_score=EXCLUDED.auto_score, override_score=EXCLUDED.override_score,
                 override_reason=EXCLUDED.override_reason, notes=EXCLUDED.notes, updated_at=EXCLUDED.updated_at"""
        db.execute(sql,(term,vp_id,metric_id,actual,auto_score,override_score,override_reason,notes,updated))
    else:
        db.execute("INSERT OR IGNORE INTO metric_values(term,vp_id,metric_id,updated_at) VALUES(?,?,?,?)",(term,vp_id,metric_id,updated))
        db.execute("""UPDATE metric_values SET actual=?, auto_score=?, override_score=?, override_reason=?, notes=?, updated_at=?
                      WHERE term=? AND vp_id=? AND metric_id=?""",(actual,auto_score,override_score,override_reason,notes,updated,term,vp_id,metric_id))

def overall(term:str, vp_id:str)->Dict[str,Any]:
    vals = load_values(term,vp_id)
    p_scores={1:[],2:[],3:[]}
    for m in METRICS:
        r = vals.get(m.id)
        if not r: continue
        score = r[3] if r[3] is not None else r[2]
        if score is not None:
            p_scores[m.pillar].append(int(score))
    p_avg={p:(sum(p_scores[p])/len(p_scores[p])) if p_scores[p] else None for p in (1,2,3)}
    if all(p_avg[p] is not None for p in (1,2,3)):
        s = sum(p_avg[p]*PILLAR_WEIGHTS[p] for p in (1,2,3))
        return {"overall_score":s, "overall_label":label(s)}
    return {"overall_score":None, "overall_label":None}

# --------------- routes ---------------
@app.get("/", response_class=HTMLResponse)
def root(request:Request):
    return RedirectResponse("/dashboard",status_code=303) if get_user(request) else RedirectResponse("/login",status_code=303)

@app.get("/login", response_class=HTMLResponse)
def login_get(request:Request):
    return render(request,"login.html",title="Login")

@app.post("/login")
def login_post(email:str=Form(...), password:str=Form(...)):
    e = email.strip().lower()
    q = "SELECT email, role, password_hash FROM users WHERE email=%s" if db.is_pg else "SELECT email, role, password_hash FROM users WHERE email=?"
    r = db.fetchone(q,(e,))
    if (not r) or (not _verify_password(password, r[2])):
        return redirect("/login", flash="Invalid email or password.")
    resp = redirect("/dashboard")
    resp.set_cookie("session", _sign(r[0]), httponly=True, samesite="lax")
    return resp

@app.get("/logout")
def logout():
    resp = redirect("/login", flash="Logged out.")
    resp.delete_cookie("session")
    return resp

@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request:Request, term:Optional[str]=None):
    u = get_user(request)
    if not u: return RedirectResponse("/login", status_code=303)
    terms = get_terms()
    selected = term or get_active_term()
    locked = term_locked(selected)

    rows = db.fetchall("SELECT id,name,email,phase,notes FROM vps ORDER BY name")
    vps=[{"id":r[0],"name":r[1],"email":r[2],"phase":r[3],"notes":r[4]} for r in rows]
    for vp in vps:
        o=overall(selected,vp["id"])
        vp["overall_score"]=o["overall_score"] or 0.0
        vp["overall_label"]=o["overall_label"]
    return render(request,"dashboard.html",title="Dashboard",term=selected,terms=terms,vps=vps,term_locked=locked)

@app.get("/vp/{vp_id}", response_class=HTMLResponse)
def vp_page(request:Request, vp_id:str, term:Optional[str]=None):
    u = get_user(request)
    if not u: return RedirectResponse("/login", status_code=303)
    selected = term or get_active_term()
    locked = term_locked(selected)
    disable_edit = locked and u["role"]!="admin"

    q = "SELECT id,name,email,phase,notes FROM vps WHERE id=%s" if db.is_pg else "SELECT id,name,email,phase,notes FROM vps WHERE id=?"
    r = db.fetchone(q,(vp_id,))
    if not r: return redirect("/dashboard", flash="VP not found.")
    vp={"id":r[0],"name":r[1],"email":r[2],"phase":r[3],"notes":r[4]}

    terms=get_terms()
    vals=load_values(selected,vp_id)
    rows=[]
    for p in (1,2,3):
        rows.append({"is_header":True,"title":f"Pillar {p} ({int(PILLAR_WEIGHTS[p]*100)}%)"})
        for m in [mm for mm in METRICS if mm.pillar==p]:
            mv=vals.get(m.id)
            rows.append({
                "is_header":False,"id":m.id,"name":m.name,"desc":m.desc,"target_text":m.target_text,
                "actual": None if not mv else mv[1],
                "auto_score": None if not mv else mv[2],
                "override_score": None if not mv else mv[3],
                "notes": None if not mv else mv[5],
                "updated_at": None if not mv else mv[6],
            })
    return render(request,"vp.html",title=vp["name"],vp=vp,term=selected,terms=terms,rows=rows,term_locked=locked,disable_edit=disable_edit)

@app.post("/vp/{vp_id}/metric/{metric_id}/actual")
def set_actual(request:Request, vp_id:str, metric_id:str, term:str=Form(...), actual:Optional[float]=Form(None)):
    u=get_user(request)
    if not u: return RedirectResponse("/login", status_code=303)
    if term_locked(term) and u["role"]!="admin":
        return redirect(f"/vp/{vp_id}?term={term}", flash="Term is locked. Editing is disabled.")
    m = next((mm for mm in METRICS if mm.id==metric_id), None)
    if not m: return redirect(f"/vp/{vp_id}?term={term}", flash="Metric not found.")
    upsert(term,vp_id,metric_id,actual=actual,auto_score=compute_auto(m,actual))
    return redirect(f"/vp/{vp_id}?term={term}")

@app.post("/vp/{vp_id}/metric/{metric_id}/override")
def set_override(request:Request, vp_id:str, metric_id:str, term:str=Form(...), override:Optional[int]=Form(None)):
    u=get_user(request)
    if not u: return RedirectResponse("/login", status_code=303)
    if term_locked(term) and u["role"]!="admin":
        return redirect(f"/vp/{vp_id}?term={term}", flash="Term is locked. Editing is disabled.")
    upsert(term,vp_id,metric_id,override_score=override)
    return redirect(f"/vp/{vp_id}?term={term}")

@app.post("/vp/{vp_id}/metric/{metric_id}/notes")
def set_notes(request:Request, vp_id:str, metric_id:str, term:str=Form(...), notes:str=Form("")):
    u=get_user(request)
    if not u: return RedirectResponse("/login", status_code=303)
    if term_locked(term) and u["role"]!="admin":
        return redirect(f"/vp/{vp_id}?term={term}", flash="Term is locked. Editing is disabled.")
    upsert(term,vp_id,metric_id,notes=notes)
    return redirect(f"/vp/{vp_id}?term={term}")

# -------- Admin: VPs / Terms / Account --------
@app.get("/admin/vps", response_class=HTMLResponse)
def admin_vps(request:Request, user=Depends(require_role("admin"))):
    rows=db.fetchall("SELECT id,name,email,phase,notes FROM vps ORDER BY name")
    vps=[{"id":r[0],"name":r[1],"email":r[2],"phase":r[3],"notes":r[4]} for r in rows]
    return render(request,"admin_vps.html",title="Admin • VPs",vps=vps)

@app.post("/admin/vps/add")
def admin_vps_add(request:Request, user=Depends(require_role("admin")),
    vp_id:str=Form(...), name:str=Form(...), email:str=Form(""), phase:str=Form(""), notes:str=Form("")
):
    try:
        ins="INSERT INTO vps(id,name,email,phase,notes) VALUES(%s,%s,%s,%s,%s)" if db.is_pg else "INSERT INTO vps(id,name,email,phase,notes) VALUES(?,?,?,?,?)"
        db.execute(ins,(vp_id.strip(),name.strip(),email.strip(),phase.strip(),notes.strip()))
    except Exception:
        return redirect("/admin/vps", flash="VP ID already exists.")
    return redirect("/admin/vps", flash="VP added.")

@app.post("/admin/vps/delete/{vp_id}")
def admin_vps_del(request:Request, vp_id:str, user=Depends(require_role("admin"))):
    q="DELETE FROM vps WHERE id=%s" if db.is_pg else "DELETE FROM vps WHERE id=?"
    db.execute(q,(vp_id,))
    return redirect("/admin/vps", flash="VP deleted.")

@app.get("/admin/terms", response_class=HTMLResponse)
def admin_terms(request:Request, user=Depends(require_role("admin"))):
    return render(request,"admin_terms.html",title="Admin • Terms",terms=get_terms())

@app.post("/admin/terms/add")
def admin_terms_add(request:Request, user=Depends(require_role("admin")), name:str=Form(...), make_active:str=Form("no")):
    name=name.strip()
    try:
        ins="INSERT INTO terms(name,is_active,locked) VALUES(%s,FALSE,FALSE)" if db.is_pg else "INSERT INTO terms(name,is_active,locked) VALUES(?,0,0)"
        db.execute(ins,(name,))
    except Exception:
        return redirect("/admin/terms", flash="Term exists.")
    if make_active=="yes":
        db.execute("UPDATE terms SET is_active=" + ("FALSE" if db.is_pg else "0"))
        db.execute("UPDATE terms SET is_active=" + ("TRUE" if db.is_pg else "1") + " WHERE name=" + ("%s" if db.is_pg else "?"), (name,))
    return redirect("/admin/terms", flash="Term added.")

@app.get("/admin/account", response_class=HTMLResponse)
def admin_account_get(request:Request, user=Depends(require_role("admin"))):
    return render(request,"admin_account.html",title="Admin • Account")

@app.post("/admin/account")
def admin_account_post(request:Request, password:str=Form(...), user=Depends(require_role("admin"))):
    q="UPDATE users SET password_hash=%s WHERE email=%s" if db.is_pg else "UPDATE users SET password_hash=? WHERE email=?"
    db.execute(q,(_make_password(password),user["email"]))
    return redirect("/admin/account", flash="Admin password updated.")
