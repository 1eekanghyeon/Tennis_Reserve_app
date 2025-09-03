import os, sqlite3, secrets
from datetime import datetime, date, time, timedelta, timezone
from zoneinfo import ZoneInfo
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, abort, make_response
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from werkzeug.security import generate_password_hash
from functools import wraps

# .env 로드
try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

# Firebase Admin SDK
import firebase_admin
from firebase_admin import auth as fb_auth, credentials

# ----- Timezone & Config -----
try:
    KST = ZoneInfo("Asia/Seoul")
except Exception:
    KST = timezone(timedelta(hours=9), name="KST")

APP_NAME = "전남대 여수캠 테니스 코트 예약"
ALLOWED_EMAIL_DOMAIN = os.environ.get("ALLOWED_EMAIL_DOMAIN","jnu.ac.kr")
OPEN_HOUR = 6; CLOSE_HOUR = 22; SLOT_LENGTH_HOURS = 2
DB_PATH = os.path.join("instance", "app.db")

# 관리자 화이트리스트 (콤마 구분)
ADMIN_EMAILS = {e.strip().lower() for e in os.environ.get("ADMIN_EMAILS","").split(",") if e.strip()}
def is_admin_email(email: str) -> bool:
    return bool(email) and email.lower() in ADMIN_EMAILS

# ----- Firebase Admin init -----
def init_firebase_admin():
    if firebase_admin._apps: return
    fsa_json = os.environ.get("FIREBASE_SERVICE_ACCOUNT_JSON","")
    fsa_path = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS") or "instance/keys/serviceAccountKey.json"
    try:
        if fsa_json:
            cred = credentials.Certificate(eval(fsa_json))
        elif os.path.exists(fsa_path):
            cred = credentials.Certificate(fsa_path)
        else:
            cred = credentials.ApplicationDefault()
        firebase_admin.initialize_app(cred)
        print("[Firebase Admin] initialized")
    except Exception as e:
        print("[Firebase Admin] WARNING:", e)

# ----- DB -----
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def ensure_schema(conn: sqlite3.Connection):
    cur = conn.cursor()
    # users
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      is_admin INTEGER NOT NULL DEFAULT 0,
      created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
      affiliation TEXT NOT NULL DEFAULT 'student'
    );
    """)
    cur.execute("PRAGMA table_info(users)")
    cols = {r["name"] for r in cur.fetchall()}
    if "affiliation" not in cols:
        cur.execute("ALTER TABLE users ADD COLUMN affiliation TEXT NOT NULL DEFAULT 'student'")

    # courts
    cur.execute("""
    CREATE TABLE IF NOT EXISTS courts (
      id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE
    );
    """)

    # reservations
    cur.execute("""
    CREATE TABLE IF NOT EXISTS reservations (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL, court_id INTEGER NOT NULL,
      res_date DATE NOT NULL, slot_index INTEGER NOT NULL,
      created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
      UNIQUE (court_id, res_date, slot_index),
      FOREIGN KEY (user_id) REFERENCES users(id),
      FOREIGN KEY (court_id) REFERENCES courts(id)
    );
    """)
    cur.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='reservations'")
    row = cur.fetchone()
    if row and "UNIQUE (court_id, res_date, slot_index)" not in row["sql"].replace(" ", ""):
        cur.executescript("""
        BEGIN;
        CREATE TABLE reservations_new (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          user_id INTEGER NOT NULL, court_id INTEGER NOT NULL,
          res_date DATE NOT NULL, slot_index INTEGER NOT NULL,
          created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
          UNIQUE (court_id, res_date, slot_index)
        );
        INSERT INTO reservations_new(id,user_id,court_id,res_date,slot_index,created_at)
          SELECT id,user_id,court_id,res_date,slot_index,created_at FROM reservations;
        DROP TABLE reservations;
        ALTER TABLE reservations_new RENAME TO reservations;
        COMMIT;
        """)

    # participants (예약자 포함 1~4명)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS reservation_participants (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      reservation_id INTEGER NOT NULL,
      name TEXT NOT NULL,
      affiliation TEXT NOT NULL CHECK(affiliation IN ('student','staff')),
      created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (reservation_id) REFERENCES reservations(id) ON DELETE CASCADE
    );
    """)
    cur.execute("CREATE INDEX IF NOT EXISTS idx_participants_res ON reservation_participants(reservation_id)")

    # helpful index
    cur.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_user_date_slot ON reservations (user_id, res_date, slot_index)")
    conn.commit()

def init_db():
    os.makedirs("instance", exist_ok=True)
    conn=get_db(); ensure_schema(conn)
    # seed courts
    cur=conn.cursor(); cur.execute("SELECT COUNT(*) AS c FROM courts")
    if cur.fetchone()["c"]==0:
        cur.executemany("INSERT INTO courts(name) VALUES (?)",[("코트 1",),("코트 2",),("코트 3",)])
    conn.commit(); conn.close()

def seed_admin_from_env():
    # (선택) 단일 관리자 시드 — ADMIN_EMAILS 화이트리스트 운영 시 필수 아님
    admin_email=os.environ.get("ADMIN_EMAIL"); admin_password=os.environ.get("ADMIN_PASSWORD")
    if not admin_email or not admin_password: return
    conn=get_db(); cur=conn.cursor(); cur.execute("SELECT id FROM users WHERE email=?", (admin_email,))
    if not cur.fetchone():
        cur.execute("INSERT INTO users(name,email,password_hash,is_admin) VALUES (?,?,?,1)",
                    ("관리자", admin_email, generate_password_hash(admin_password)))
        conn.commit()
    conn.close()

# ----- Helpers -----
def slot_range():
    out=[]
    for start in range(OPEN_HOUR, CLOSE_HOUR, SLOT_LENGTH_HOURS):
        end = start + SLOT_LENGTH_HOURS
        if end <= CLOSE_HOUR: out.append((start,end))
    return out

def slot_to_times(res_date: date, slot_index: int):
    s,e = slot_range()[slot_index]
    start_dt = datetime.combine(res_date, time(hour=s), tzinfo=KST)
    end_dt = datetime.combine(res_date, time(hour=e), tzinfo=KST)
    return start_dt, end_dt

def weekday_ko(d: date): return "월화수목금토일"[d.weekday()]

def get_courts():
    conn=get_db(); cur=conn.cursor(); cur.execute("SELECT * FROM courts ORDER BY id"); rows=cur.fetchall(); conn.close(); return rows

def get_reservations_for_date(res_date: date):
    conn=get_db(); cur=conn.cursor()
    cur.execute("""
      SELECT r.*, u.name AS user_name, u.affiliation AS user_aff, c.name AS court_name
      FROM reservations r
      JOIN users u ON u.id=r.user_id
      JOIN courts c ON c.id=r.court_id
      WHERE r.res_date=? ORDER BY r.court_id, r.slot_index
    """,(res_date.isoformat(),))
    rows=cur.fetchall()
    if not rows:
        conn.close(); return []

    # 참가자 일괄 조회
    ids = [r["id"] for r in rows]
    qmarks = ",".join("?"*len(ids))
    cur.execute(f"""
      SELECT reservation_id, name, affiliation
      FROM reservation_participants
      WHERE reservation_id IN ({qmarks})
      ORDER BY id
    """, ids)
    pmap = {}
    for pr in cur.fetchall():
        pmap.setdefault(pr["reservation_id"], []).append({"name": pr["name"], "affiliation": pr["affiliation"]})

    out=[]
    for r in rows:
        d=dict(r)
        plist = pmap.get(r["id"])
        if not plist:
            plist=[{"name": r["user_name"], "affiliation": r["user_aff"]}]
        d["participants"]=plist
        out.append(d)
    conn.close()
    return out

def get_user_reservations_on_date(user_id:int, res_date:date):
    conn=get_db(); cur=conn.cursor()
    cur.execute("SELECT * FROM reservations WHERE user_id=? AND res_date=? ORDER BY slot_index", (user_id, res_date.isoformat()))
    rows=cur.fetchall(); conn.close(); return rows

# ======== Admin 권한 데코레이터 & 조회 헬퍼 ========
def admin_required(view):
    @wraps(view)
    @login_required
    def wrapped(*args, **kwargs):
        if not current_user.is_admin:
            abort(403)
        return view(*args, **kwargs)
    return wrapped

def count_users():
    conn=get_db(); cur=conn.cursor()
    cur.execute("SELECT COUNT(*) FROM users"); n=cur.fetchone()[0]
    conn.close(); return n

def count_reservations_between(d1:date, d2:date):
    conn=get_db(); cur=conn.cursor()
    cur.execute("SELECT COUNT(*) FROM reservations WHERE res_date BETWEEN ? AND ?", (d1.isoformat(), d2.isoformat()))
    n=cur.fetchone()[0]; conn.close(); return n

def get_recent_reservations(limit:int=20):
    conn=get_db(); cur=conn.cursor()
    cur.execute("""
      SELECT r.*, u.name AS user_name, u.affiliation AS user_aff, c.name AS court_name
      FROM reservations r
      JOIN users u ON u.id=r.user_id
      JOIN courts c ON c.id=r.court_id
      ORDER BY r.res_date DESC, r.slot_index DESC, r.id DESC
      LIMIT ?
    """,(limit,))
    rows=cur.fetchall()
    ids=[r["id"] for r in rows]
    pmap={}
    if ids:
        qmarks=",".join("?"*len(ids))
        cur.execute(f"SELECT reservation_id, name, affiliation FROM reservation_participants WHERE reservation_id IN ({qmarks}) ORDER BY id", ids)
        for pr in cur.fetchall():
            pmap.setdefault(pr["reservation_id"], []).append({"name":pr["name"], "affiliation":pr["affiliation"]})
    out=[]
    for r in rows:
        d=dict(r); d["participants"]=pmap.get(r["id"], [{"name":r["user_name"], "affiliation":r["user_aff"]}]); out.append(d)
    conn.close(); return out

def paged_users(page:int, page_size:int, q:str|None=None, aff:str|None=None):
    off=max(0,(page-1)*page_size)
    conn=get_db(); cur=conn.cursor()
    base="FROM users WHERE 1=1"
    params=[]
    if q:
        base+=" AND (name LIKE ? OR email LIKE ?)"
        like=f"%{q}%"; params.extend([like, like])
    if aff in ("student","staff"):
        base+=" AND affiliation=?"; params.append(aff)
    cur.execute(f"SELECT COUNT(*) {base}", params); total=cur.fetchone()[0]
    cur.execute(f"""
      SELECT id, name, email, affiliation, is_admin, created_at
      {base}
      ORDER BY created_at DESC, id DESC
      LIMIT ? OFFSET ?
    """, params+[page_size, off])
    rows=cur.fetchall(); conn.close()
    return total, rows

def paged_reservations(page:int, page_size:int, d_from:date|None, d_to:date|None, court_id:int|None, q:str|None):
    off=max(0,(page-1)*page_size)
    conn=get_db(); cur=conn.cursor()
    base="""
      FROM reservations r
      JOIN users u ON u.id=r.user_id
      JOIN courts c ON c.id=r.court_id
      WHERE 1=1
    """
    params=[]
    if d_from: base+=" AND r.res_date >= ?"; params.append(d_from.isoformat())
    if d_to:   base+=" AND r.res_date <= ?"; params.append(d_to.isoformat())
    if court_id: base+=" AND r.court_id = ?"; params.append(court_id)
    if q:
        base+=" AND (u.name LIKE ? OR u.email LIKE ?)"
        like=f"%{q}%"; params.extend([like, like])

    cur.execute(f"SELECT COUNT(*) {base}", params); total=cur.fetchone()[0]
    cur.execute(f"""
      SELECT r.*, u.name AS user_name, u.affiliation AS user_aff, c.name AS court_name
      {base}
      ORDER BY r.res_date DESC, r.slot_index DESC, r.id DESC
      LIMIT ? OFFSET ?
    """, params+[page_size, off])
    rows=cur.fetchall()

    ids=[r["id"] for r in rows]
    pmap={}
    if ids:
        qmarks=",".join("?"*len(ids))
        cur.execute(f"SELECT reservation_id, name, affiliation FROM reservation_participants WHERE reservation_id IN ({qmarks}) ORDER BY id", ids)
        for pr in cur.fetchall():
            pmap.setdefault(pr["reservation_id"], []).append({"name":pr["name"], "affiliation":pr["affiliation"]})
    out=[]
    for r in rows:
        d=dict(r); d["participants"]=pmap.get(r["id"], [{"name":r["user_name"], "affiliation":r["user_aff"]}]); out.append(d)
    conn.close(); return total, out

# ----- Flask -----
app = Flask(__name__, instance_relative_config=True, static_folder="static", template_folder="templates")
app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET","dev-secret-change-me")

login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.init_app(app)

class User(UserMixin):
    def __init__(self, id, name, email, password_hash, is_admin, affiliation):
        self.id=id; self.name=name; self.email=email; self.password_hash=password_hash; self.is_admin=bool(is_admin); self.affiliation=affiliation

@login_manager.user_loader
def load_user(user_id):
    conn=get_db(); cur=conn.cursor(); cur.execute("SELECT * FROM users WHERE id=?", (user_id,)); row=cur.fetchone(); conn.close()
    return User(row["id"],row["name"],row["email"],row["password_hash"],row["is_admin"],row["affiliation"]) if row else None

@app.context_processor
def inject_globals():
    return dict(APP_NAME=APP_NAME, weekday_ko=weekday_ko, slots=slot_range())

# ---------- 라우팅 ----------
@app.get("/")
def root():
    if current_user.is_authenticated:
        return redirect(url_for("reserve"))
    return redirect(url_for("login"))

@app.get("/login")
def login():
    if current_user.is_authenticated:
        return redirect(url_for("reserve"))
    return render_template("login.html")

@app.get("/signup")
def signup():
    if current_user.is_authenticated:
        return redirect(url_for("reserve"))
    return render_template("signup.html")

@app.get("/reserve")
@login_required
def reserve():
    q=request.args.get("date")
    if q:
        try: target_date=datetime.strptime(q,"%Y-%m-%d").date()
        except ValueError: target_date=datetime.now(KST).date()
    else:
        target_date=datetime.now(KST).date()
    slots=slot_range(); courts=get_courts(); rows=get_reservations_for_date(target_date)
    reserved_map={(r["court_id"], r["slot_index"]): r for r in rows}
    return render_template("reserve.html", target_date=target_date, target_wday=weekday_ko(target_date),
                           slots=slots, courts=courts, reserved_map=reserved_map)

@app.post("/auth/firebase")
def auth_firebase():
    from flask import abort
    data = request.get_json(force=True)
    id_token = data.get("idToken")
    if not id_token:
        return {"ok": False, "error": "토큰 없음"}, 400

    init_firebase_admin()
    try:
        decoded = fb_auth.verify_id_token(id_token)
    except Exception:
        return {"ok": False, "error": "토큰 검증 실패"}, 401

    email = decoded.get("email")
    verified = decoded.get("email_verified", False)
    uid = decoded.get("uid")
    if not email or not verified or not email.endswith("@"+ALLOWED_EMAIL_DOMAIN):
        return {"ok": False, "error": f"@{ALLOWED_EMAIL_DOMAIN} 인증만 허용됩니다."}, 403

    # 이름 후보(있을 때만 업데이트에 사용)
    display_name = ""
    try:
        rec = fb_auth.get_user(uid)
        display_name = rec.display_name or ""
    except Exception:
        pass
    client_name = (data.get("name") or "").strip()
    name_for_update = (display_name or client_name).strip()

    # 소속은 '회원가입 완료' 시에만 반영
    aff_in = data.get("affiliation")
    aff_in = (aff_in or "").lower().strip() if isinstance(aff_in, str) else None
    if aff_in not in ("student", "staff", None):
        aff_in = None

    admin_flag = 1 if is_admin_email(email) else 0

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE email=?", (email,))
    row = cur.fetchone()

    if not row:
        # 신규 가입: 여기서만 이메일 로컬파트 fallback 허용
        name_to_store = name_for_update or email.split("@")[0]
        aff_new = aff_in if aff_in in ("student", "staff") else "student"
        cur.execute(
            "INSERT INTO users(name,email,password_hash,affiliation,is_admin) VALUES (?,?,?,?,?)",
            (name_to_store, email, generate_password_hash(secrets.token_hex(16)), aff_new, admin_flag)
        )
        conn.commit()
        cur.execute("SELECT * FROM users WHERE email=?", (email,))
        row = cur.fetchone()
    else:
        updates = []
        # 🔒 로그인 시에는 명시적으로 전달된 이름이 있을 때만 변경
        if name_for_update and row["name"] != name_for_update:
            updates.append(("name", name_for_update))
        if aff_in in ("student", "staff") and row["affiliation"] != aff_in:
            updates.append(("affiliation", aff_in))
        if int(row["is_admin"]) != admin_flag:
            updates.append(("is_admin", admin_flag))
        for col, val in updates:
            cur.execute(f"UPDATE users SET {col}=? WHERE id=?", (val, row["id"]))
        if updates:
            conn.commit()
            cur.execute("SELECT * FROM users WHERE id=?", (row["id"],))
            row = cur.fetchone()

    conn.close()

    # 보조 claims
    try:
        fb_auth.set_custom_user_claims(uid, {"affiliation": row["affiliation"], "admin": bool(row["is_admin"])})
    except Exception:
        pass

    login_user(User(row["id"], row["name"], row["email"], row["password_hash"], row["is_admin"], row["affiliation"]))
    return {"ok": True}


@app.get("/logout", endpoint="logout")
@login_required
def logout_view():
    logout_user(); flash("로그아웃 되었습니다.","info"); return redirect(url_for("login"))

# ---------- 예약 API ----------
@app.post("/api/reserve")
@login_required
def api_reserve():
    d=request.get_json(force=True)
    court_id=int(d.get("court_id")); res_date=datetime.strptime(d.get("res_date"),"%Y-%m-%d").date(); slot_index=int(d.get("slot_index"))

    conn=get_db(); cur=conn.cursor(); cur.execute("SELECT 1 FROM courts WHERE id=?", (court_id,))
    if not cur.fetchone(): conn.close(); return jsonify({"ok":False,"error":"존재하지 않는 코트입니다."}), 400

    slots=slot_range()
    if not (0<=slot_index<len(slots)): conn.close(); return jsonify({"ok":False,"error":"잘못된 시간 슬롯입니다."}),400

    cur.execute("SELECT 1 FROM reservations WHERE court_id=? AND res_date=? AND slot_index=?", (court_id,res_date.isoformat(),slot_index))
    if cur.fetchone(): conn.close(); return jsonify({"ok":False,"error":"이미 예약된 시간입니다."}),409

    # Per-user rule
    user_rows = get_user_reservations_on_date(current_user.id, res_date)
    now = datetime.now(KST)
    if user_rows:
        active = any(now < slot_to_times(res_date,r["slot_index"])[1] for r in user_rows)
        if active:
            prev_exists = any(r["slot_index"] == slot_index-1 for r in user_rows)
            if not prev_exists:
                conn.close(); return jsonify({"ok":False,"error":"하루 1회만 사전 예약 가능합니다. (이전 슬롯 종료 후 바로 다음 슬롯만 예외)"}), 403
            _, prev_end = slot_to_times(res_date, slot_index-1)
            if now < prev_end:
                conn.close(); return jsonify({"ok":False,"error":"바로 연속 두 타임 예약은 불가합니다. 이전 슬롯 종료 후 시도해주세요."}), 403

    # 참가자 (본인 + 최대 3명)
    extras_in = (d.get("participants") or [])
    extras=[]
    for p in extras_in:
        name=(p.get("name") or "").strip()
        aff=(p.get("affiliation") or "").lower()
        if not name:  continue
        if aff not in ("student","staff"): continue
        extras.append((name, aff))
        if len(extras) >= 3: break

    try:
        cur.execute("INSERT INTO reservations(user_id,court_id,res_date,slot_index) VALUES (?,?,?,?)",
                    (current_user.id,court_id,res_date.isoformat(),slot_index))
        rid = cur.lastrowid

        participants = [(current_user.name, current_user.affiliation)] + extras
        for name, aff in participants:
            cur.execute(
                "INSERT INTO reservation_participants(reservation_id,name,affiliation) VALUES (?,?,?)",
                (rid, name, aff)
            )
        conn.commit()
    except sqlite3.IntegrityError:
        conn.rollback(); conn.close(); return jsonify({"ok":False,"error":"이미 예약된 시간입니다."}),409
    conn.close(); return jsonify({"ok":True})

@app.post("/api/cancel")
@login_required
def api_cancel():
    d=request.get_json(force=True); rid=int(d.get("reservation_id"))
    conn=get_db(); cur=conn.cursor(); cur.execute("SELECT user_id FROM reservations WHERE id=?", (rid,)); row=cur.fetchone()
    if not row: conn.close(); return jsonify({"ok":False,"error":"예약이 없습니다."}),404
    if row["user_id"] != current_user.id and not current_user.is_admin: conn.close(); return jsonify({"ok":False,"error":"본인 예약만 취소할 수 있습니다."}),403
    cur.execute("DELETE FROM reservations WHERE id=?", (rid,)); conn.commit(); conn.close(); return jsonify({"ok":True})

# ======== Admin 대시보드 & Export ========
@app.get("/admin")
@admin_required
def admin_dashboard():
    today=datetime.now(KST).date()
    week_ago=today - timedelta(days=6)
    month_ago=today - timedelta(days=29)

    stats={
        "users_total": count_users(),
        "res_today": count_reservations_between(today, today),
        "res_7d": count_reservations_between(week_ago, today),
        "res_30d": count_reservations_between(month_ago, today),
        "recent": get_recent_reservations(10)
    }

    page=int(request.args.get("page",1) or 1)
    page_size=min(100, int(request.args.get("page_size",20) or 20))
    tab=request.args.get("tab","reservations")
    q=(request.args.get("q") or "").strip()

    if tab=="users":
        aff=request.args.get("aff")
        total, users = paged_users(page, page_size, q=q or None, aff=aff)
        return render_template("admin.html", stats=stats, tab="users",
                               users=users, total=total, page=page, page_size=page_size, q=q, aff=aff)

    # 예약 탭(기본)
    d_from_str=request.args.get("from"); d_to_str=request.args.get("to"); court_str=request.args.get("court_id")
    d_from=datetime.strptime(d_from_str,"%Y-%m-%d").date() if d_from_str else (today - timedelta(days=29))
    d_to=datetime.strptime(d_to_str,"%Y-%m-%d").date() if d_to_str else today
    court_id=int(court_str) if court_str and court_str.isdigit() else None

    total, resv = paged_reservations(page, page_size, d_from, d_to, court_id, q or None)
    courts = get_courts()
    return render_template("admin.html", stats=stats, tab="reservations",
                           reservations=resv, total=total, page=page, page_size=page_size,
                           q=q, d_from=d_from, d_to=d_to, court_id=court_id, courts=courts, slots=slot_range())

@app.get("/admin/export/reservations.csv")
@admin_required
def admin_export_reservations_csv():
    q=(request.args.get("q") or "").strip()
    d_from_str=request.args.get("from"); d_to_str=request.args.get("to"); court_str=request.args.get("court_id")
    today=datetime.now(KST).date()
    d_from=datetime.strptime(d_from_str,"%Y-%m-%d").date() if d_from_str else (today - timedelta(days=29))
    d_to=datetime.strptime(d_to_str,"%Y-%m-%d").date() if d_to_str else today
    court_id=int(court_str) if court_str and court_str.isdigit() else None

    total, rows = paged_reservations(1, 100000, d_from, d_to, court_id, q or None)

    def esc(s: str) -> str:
        s=str(s)
        return '"' + s.replace('"','""') + '"'

    lines=["res_id,res_date,slot,court,participants"]
    sr = slot_range()
    for r in rows:
        slot = sr[r['slot_index']]
        slot_txt = f"{slot[0]:02d}:00-{slot[1]:02d}:00"
        plist = "; ".join([f"{p['name']}({'학생' if p['affiliation']=='student' else '교직원'})" for p in r["participants"]])
        lines.append(",".join([str(r["id"]), r["res_date"], slot_txt, esc(r["court_name"]), esc(plist)]))

    # ★ 핵심: BOM 붙여서 Excel이 UTF-8로 인식하도록
    csv_text = "\ufeff" + "\n".join(lines)

    resp = make_response(csv_text)
    resp.headers["Content-Type"] = "text/csv; charset=utf-8"
    # 한글 파일명도 안전하게
    resp.headers["Content-Disposition"] = "attachment; filename=reservations.csv; filename*=UTF-8''reservations.csv"
    return resp


@app.get("/admin/export/users.csv")
@admin_required
def admin_export_users_csv():
    total, rows = paged_users(1, 100000)

    def esc(s: str) -> str:
        s=str(s)
        return '"' + s.replace('"','""') + '"'

    lines=["user_id,name,email,affiliation,is_admin,created_at"]
    for r in rows:
        lines.append(",".join([
            str(r["id"]), esc(r["name"]), esc(r["email"]),
            r["affiliation"], str(int(r["is_admin"])), str(r["created_at"])
        ]))

    # ★ BOM
    csv_text = "\ufeff" + "\n".join(lines)

    resp = make_response(csv_text)
    resp.headers["Content-Type"] = "text/csv; charset=utf-8"
    resp.headers["Content-Disposition"] = "attachment; filename=users.csv; filename*=UTF-8''users.csv"
    return resp

def create_app():
    init_db(); seed_admin_from_env(); init_firebase_admin(); return app

if __name__=="__main__":
    create_app(); app.run(host="0.0.0.0", port=8000, debug=True)
