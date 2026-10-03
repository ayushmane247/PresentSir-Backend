"""PresentSir backend (local, no external services).

All data (sessions, scans, device bindings, plan) is stored in one SQLite file, presentsir.db,
next to this script. It survives restarts. Login tokens are signed (HMAC), so they stay valid too.
Run:  uvicorn main:app --host 0.0.0.0 --port 8000      (keep it to ONE process; do not use --workers)
Not for Vercel/serverless: those have no permanent disk, so run it on your own PC or server.
"""
import base64, hashlib, hmac, json, os, random, secrets, sqlite3, threading, time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path

import segno
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi import FastAPI, Header, Request
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel

BASE = Path(__file__).parent
DB_PATH = os.environ.get("PRESENTSIR_DB") or str(BASE / "presentsir.db")
SECRET = (os.environ.get("APP_SECRET") or "presentsir-demo-secret").encode()  # set APP_SECRET for real use
IST = timezone(timedelta(hours=5, minutes=30))
ON_VERCEL = bool(os.environ.get("VERCEL"))

# Student table (login id, name, roll no). Password for everyone: 1234
NAMES = [("ayush", "Ayush Mane", "A45"), ("ashish", "Ashish Warang", "A47"),
         ("pushkar", "Pushkar Mahadik", "A29"), ("arshad", "Arshad Mahalkari", "A03"),
         ("riya", "Riya Patil", "A12"), ("karan", "Karan Shah", "A31"),
         ("sneha", "Sneha Jadhav", "A07"), ("omkar", "Omkar Patil", "A22"),
         ("pooja", "Pooja Kulkarni", "A38"), ("neha", "Neha Shinde", "A16")]
USERS = {l: {"password": "1234", "name": n, "uid": u} for l, n, u in NAMES}
ROSTER = sorted(USERS.values(), key=lambda u: u["uid"])
LOGIN_BY_UID = {u["uid"]: l for l, u in USERS.items()}
COURSES = [{"id": 1, "name": "Android App Development", "code": "231CSEOECL302", "faculty": "Dr. Sunny Baburao Mohite"},
           {"id": 2, "name": "Cloud Computing", "code": "231AIMLPCCL303", "faculty": "Ms. Snehalata Krishnakant Choudhari"},
           {"id": 3, "name": "Database Engineering", "code": "231AIMLPCCL302", "faculty": "Ms. Priyanka Ramesh Bhatmare"}]

app = FastAPI(title="PresentSir demo")


# ---------------- storage (SQLite) ----------------
class SqliteStore:
    """Tiny key/hash/set/list store on SQLite. Every call is atomic (one lock, autocommit)."""

    def __init__(self, path):
        self.lock = threading.RLock()
        self.db = sqlite3.connect(path, check_same_thread=False, isolation_level=None, timeout=10)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS kv(k TEXT PRIMARY KEY, v TEXT);
            CREATE TABLE IF NOT EXISTS h(k TEXT, f TEXT, v TEXT, PRIMARY KEY(k, f));
            CREATE TABLE IF NOT EXISTS st(k TEXT, m TEXT, PRIMARY KEY(k, m));
            CREATE TABLE IF NOT EXISTS ls(id INTEGER PRIMARY KEY AUTOINCREMENT, k TEXT, v TEXT);""")

    def cmd(self, op, k, *r):
        with self.lock:
            q = self.db.execute
            if op == "GET":
                row = q("SELECT v FROM kv WHERE k=?", (k,)).fetchone()
                return row[0] if row else None
            if op == "SET":
                if "NX" in r:
                    return "OK" if q("INSERT OR IGNORE INTO kv VALUES(?,?)", (k, str(r[0]))).rowcount else None
                q("INSERT OR REPLACE INTO kv VALUES(?,?)", (k, str(r[0])))
                return "OK"
            if op == "DEL":
                return sum(q(f"DELETE FROM {t} WHERE k=?", (k,)).rowcount for t in ("kv", "h", "st", "ls"))
            if op == "HSET":
                q("INSERT OR REPLACE INTO h VALUES(?,?,?)", (k, r[0], str(r[1])))
                return 1
            if op == "HSETNX":
                return q("INSERT OR IGNORE INTO h VALUES(?,?,?)", (k, r[0], str(r[1]))).rowcount
            if op == "HGET":
                row = q("SELECT v FROM h WHERE k=? AND f=?", (k, r[0])).fetchone()
                return row[0] if row else None
            if op == "HEXISTS":
                return int(q("SELECT 1 FROM h WHERE k=? AND f=?", (k, r[0])).fetchone() is not None)
            if op == "HGETALL":
                return [x for row in q("SELECT f, v FROM h WHERE k=?", (k,)).fetchall() for x in row]
            if op == "SADD":
                return q("INSERT OR IGNORE INTO st VALUES(?,?)", (k, str(r[0]))).rowcount
            if op == "LPUSH":
                q("INSERT INTO ls(k, v) VALUES(?,?)", (k, str(r[0])))
                return q("SELECT COUNT(*) FROM ls WHERE k=?", (k,)).fetchone()[0]
            if op == "LRANGE":  # newest first; only used as "whole list"
                return [row[0] for row in q("SELECT v FROM ls WHERE k=? ORDER BY id DESC", (k,)).fetchall()]
        raise ValueError(op)


DB = None if ON_VERCEL else SqliteStore(DB_PATH)  # Vercel has no writable disk: do not crash, explain


class ApiError(Exception):
    def __init__(self, code, message, status=400):
        self.code, self.message, self.status = code, message, status


@app.exception_handler(ApiError)
async def _err(_: Request, e: ApiError):
    return JSONResponse(status_code=e.status, content={"code": e.code, "message": e.message})


def cmd(*a):
    if DB is None:
        raise ApiError("NOT_FOR_VERCEL", "This version keeps data in a local file, so it cannot run on Vercel. "
                       "Run it on your PC: uvicorn main:app --host 0.0.0.0 --port 8000", 503)
    try:
        return DB.cmd(*a)
    except sqlite3.Error:
        raise ApiError("STORE_ERROR", "Database error", 503)


def hgetall(k):
    f = cmd("HGETALL", k) or []
    return {f[i]: json.loads(f[i + 1]) for i in range(0, len(f), 2)}


def get_scans(sid):
    return sorted(hgetall(f"ps:scans:{sid}").values(), key=lambda x: x["time"])


def get_alerts(sid):
    return [json.loads(x) for x in cmd("LRANGE", f"ps:alerts:{sid}", 0, -1) or []]


def get_device(login):
    raw = cmd("HGET", "ps:devices", login)
    return json.loads(raw) if raw else None


# ---------------- sessions / plan live in one JSON document ----------------
def hms() -> str:
    return datetime.now(IST).strftime("%H:%M:%S")


def to_min(hhmm):
    h, m = hhmm.split(":")
    return int(h) * 60 + int(m)


def to_hhmm(mins):
    return f"{mins // 60:02d}:{mins % 60:02d}"


def new_session(M, cid, topic, date, plan_id=None, status="SCHEDULED", start="10:00", end="11:00", rot=10, win=120):
    M["nid"]["s"] += 1
    s = {"id": M["nid"]["s"], "course_id": cid, "topic": topic, "date": date, "plan_id": plan_id,
         "start_time": start, "end_time": end, "rotation_seconds": rot, "window_seconds": win,
         "status": status, "records": {}, "log": []}
    M["sessions"][str(s["id"])] = s
    return s


def seed():
    rnd = random.Random(7)
    M = {"sessions": {}, "plan": [], "nid": {"s": 4800, "p": 0}}
    topics = ["Introduction", "Activities and Intents", "Jetpack Compose basics", "Navigation", "Networking"]
    for cid in (1, 2, 3):
        for i, t in enumerate(topics):
            s = new_session(M, cid, t, f"2026-09-{8 + i * 3:02d}", status="SUBMITTED",
                            start=f"{8 + cid:02d}:00", end=f"{9 + cid:02d}:00")
            for u in ROSTER:
                p = rnd.random() < (0.55 if u["uid"] in ("A07", "A22") else 0.88)
                s["records"][u["uid"]] = {"status": "PRESENT" if p else "ABSENT",
                                          "source": "SCAN" if p else "SYSTEM", "reason": "", "at": "10:05:00"}
    for c in COURSES:
        for n, t in enumerate(["Unit 1 overview", "Unit 2 concepts", "Case study", "Revision"], 1):
            M["nid"]["p"] += 1
            M["plan"].append({"id": M["nid"]["p"], "course_id": c["id"], "no": n, "topic": t,
                              "planned_date": f"2026-10-{n * 4:02d}", "status": "DONE" if n == 1 else "PLANNED"})
    return M


def meta():
    raw = cmd("GET", "ps:meta")
    if not raw:
        cmd("SET", "ps:meta", json.dumps(seed()), "NX")
        raw = cmd("GET", "ps:meta")
    return json.loads(raw)


def save(M):
    cmd("SET", "ps:meta", json.dumps(M))


def course(cid):
    return next(c for c in COURSES if c["id"] == cid)


def sess(M, sid):
    s = M["sessions"].get(str(sid))
    if not s:
        raise ApiError("NOT_FOUND", "Session not found", 404)
    return s


def open_session(M):
    return next((s for s in M["sessions"].values() if s["status"] == "OPEN"), None)


def summary(s, scans=None, alerts_n=None):
    if s["records"]:
        pres = sum(r["status"] == "PRESENT" for r in s["records"].values())
    elif s["status"] == "OPEN":
        pres = len(scans if scans is not None else get_scans(s["id"]))
    else:
        pres = 0
    if s["status"] == "OPEN":
        n_alerts = alerts_n if alerts_n is not None else len(cmd("LRANGE", f"ps:alerts:{s['id']}", 0, -1) or [])
    else:
        n_alerts = s.get("alert_count", 0)
    c = course(s["course_id"])
    return {"id": s["id"], "course_id": c["id"], "course": c["name"], "code": c["code"], "date": s["date"],
            "topic": s["topic"], "status": s["status"], "present": pres, "total": len(ROSTER),
            "alerts": n_alerts,
            "start_time": s["start_time"], "end_time": s["end_time"],
            "rotation_seconds": s["rotation_seconds"], "window_seconds": s["window_seconds"]}


# ---------------- auth: signed stateless tokens ----------------
def b64(b):
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def make_token(login):
    msg = f"{login}.{int(time.time()) + 3 * 86400}"
    return f"{msg}.{b64(hmac.new(SECRET, msg.encode(), hashlib.sha256).digest()[:16])}"


def user_from(auth):
    tok = (auth or "").removeprefix("Bearer ").strip()
    try:
        msg, sig = tok.rsplit(".", 1)
        login, exp = msg.split(".")
        ok = hmac.compare_digest(sig, b64(hmac.new(SECRET, msg.encode(), hashlib.sha256).digest()[:16]))
        if ok and int(exp) > time.time() and login in USERS:
            return login
    except ValueError:
        pass
    raise ApiError("UNAUTHORIZED", "Please log in again", 401)


# ---------------- QR ----------------
def step(s):
    return int((time.time() - s["opened_at"]) // s["rotation_seconds"])


def qr_for(s, w):
    mac = b64(hmac.new(SECRET, f"{s['id']}.{w}".encode(), hashlib.sha256).digest()[:9])
    return f"A1.{s['id']}.{w}.{mac}"


def check_qr(s, token):
    p = token.split(".")
    if len(p) != 4 or p[0] != "A1" or not p[2].isdigit():
        raise ApiError("QR_INVALID", "This is not a PresentSir QR")
    w = int(p[2])
    if not hmac.compare_digest(qr_for(s, w), token):
        raise ApiError("QR_INVALID", "QR code is not valid for this session")
    if w not in (step(s), step(s) - 1):
        raise ApiError("QR_EXPIRED", "QR expired, scan the latest one")


# ---------------- models ----------------
class LoginReq(BaseModel):
    login_id: str
    password: str
    android_id: str


class RegisterReq(BaseModel):
    public_key: str
    android_id: str


class SubmitReq(BaseModel):
    session_id: int
    qr_token: str
    client_nonce: str
    android_id: str
    signature: str


class SessionReq(BaseModel):
    course_id: int
    topic: str
    date: str
    plan_id: int | None = None
    start_time: str = "10:00"
    duration_min: int = 60
    rotation_seconds: int = 10
    window_seconds: int = 120


class RecordReq(BaseModel):
    status: str
    reason: str


class PlanReq(BaseModel):
    course_id: int
    topic: str
    planned_date: str


# ---------------- student / device (Android app) ----------------
@app.post("/api/login")
def login(req: LoginReq):
    lid = req.login_id.strip().lower()
    u = USERS.get(lid)
    if not u or u["password"] != req.password:
        raise ApiError("INVALID_CREDENTIALS", "Wrong ID or password", 401)
    d = get_device(lid)
    st = "NONE" if not d else ("ACTIVE_THIS_DEVICE" if d["android_id"] == req.android_id else "BOUND_TO_OTHER_DEVICE")
    return {"access_token": make_token(lid), "name": u["name"], "uid": u["uid"], "device_status": st}


@app.post("/api/device/register")
def register(req: RegisterReq, authorization: str | None = Header(None)):
    lid = user_from(authorization)
    d = get_device(lid)
    if d and d["android_id"] != req.android_id:
        raise ApiError("DEVICE_ALREADY_BOUND", "This account is bound to another device", 409)
    try:
        serialization.load_der_public_key(base64.b64decode(req.public_key))
    except Exception:
        raise ApiError("VALIDATION_ERROR", "Invalid public key")
    cmd("HSET", "ps:devices", lid, json.dumps({"android_id": req.android_id, "public_key": req.public_key}))
    return {"status": "ACTIVE"}


@app.post("/api/attendance/submit")
def submit(req: SubmitReq, authorization: str | None = Header(None)):
    lid = user_from(authorization)
    s = open_session(meta())
    if not s:
        raise ApiError("SESSION_NOT_OPEN", "Attendance session is not open")
    if time.time() > s["opened_at"] + s["window_seconds"]:
        raise ApiError("WINDOW_CLOSED", "The attendance window has ended")
    if req.session_id != s["id"]:
        raise ApiError("QR_INVALID", "QR belongs to a different session")
    check_qr(s, req.qr_token)
    if not cmd("SADD", f"ps:nonce:{s['id']}", req.client_nonce):
        raise ApiError("REPLAY", "Request already used")
    d = get_device(lid)
    if not d:
        raise ApiError("DEVICE_NOT_REGISTERED", "Register this device first")
    u = USERS[lid]

    def alert(kind):
        cmd("LPUSH", f"ps:alerts:{s['id']}", json.dumps(
            {"time": hms(), "name": u["name"], "uid": u["uid"], "kind": kind,
             "attempted_device": req.android_id, "registered_device": d["android_id"]}))

    if req.android_id != d["android_id"]:
        alert("DEVICE_MISMATCH")
        raise ApiError("DEVICE_MISMATCH", "This is not your registered device", 403)
    payload = f"ATT1|{req.session_id}|{req.qr_token}|{req.android_id}|{req.client_nonce}"
    try:
        pub = serialization.load_der_public_key(base64.b64decode(d["public_key"]))
        pub.verify(base64.b64decode(req.signature), payload.encode(), ec.ECDSA(hashes.SHA256()))
    except (InvalidSignature, ValueError):
        alert("SIGNATURE_INVALID")
        raise ApiError("SIGNATURE_INVALID", "Device signature check failed", 403)
    cmd("HSETNX", f"ps:scans:{s['id']}", u["uid"],
        json.dumps({"name": u["name"], "uid": u["uid"], "time": hms(), "device": req.android_id}))
    return {"status": "MARKED", "message": "Attendance marked"}


@app.get("/api/student/attendance")
def student_attendance(authorization: str | None = Header(None)):
    """Open sessions count as present once the student has scanned; others use the official record."""
    uid = USERS[user_from(authorization)]["uid"]
    M = meta()
    out = []
    for c in COURSES:
        present = total = 0
        for s in M["sessions"].values():
            if s["course_id"] != c["id"]:
                continue
            if s["status"] == "OPEN":
                if cmd("HEXISTS", f"ps:scans:{s['id']}", uid):
                    present += 1
                    total += 1
            elif s["records"]:
                st = s["records"].get(uid, {}).get("status")
                if st == "EXCUSED":
                    continue
                total += 1
                present += st == "PRESENT"
        out.append({"name": c["name"], "code": c["code"], "faculty": c["faculty"], "present": present, "total": total})
    old = ["First Year Semester I", "First Year Semester II",
           "B. Tech. Second Year Semester III", "B. Tech. Second Year Semester IV"]
    return {"semesters": [{"name": n, "courses": []} for n in old]
            + [{"name": "B. Tech. Third Year Semester V", "courses": out}]}


# ---------------- faculty portal ----------------
@app.get("/api/courses")
def courses():
    return COURSES


@app.get("/api/sessions")
def list_sessions():
    M = meta()
    ss = sorted(M["sessions"].values(), key=lambda s: (s["date"], s["start_time"], s["id"]), reverse=True)
    return [summary(s) for s in ss]


@app.post("/api/sessions")
def create(req: SessionReq):
    if not req.topic.strip():
        raise ApiError("VALIDATION_ERROR", "Topic is required")
    if not (5 <= req.rotation_seconds <= 120) or not (30 <= req.window_seconds <= 3600) \
            or not (15 <= req.duration_min <= 240):
        raise ApiError("VALIDATION_ERROR", "Check rotation (5-120 s), QR time (30 s-60 min) and slot length")
    try:
        a = to_min(req.start_time)
    except ValueError:
        raise ApiError("VALIDATION_ERROR", "Start time must be HH:MM")
    b = a + req.duration_min
    if b > 24 * 60:
        raise ApiError("VALIDATION_ERROR", "Slot must end before midnight")
    M = meta()
    for o in M["sessions"].values():
        if o["date"] == req.date and o["status"] != "CANCELLED" and a < to_min(o["end_time"]) and to_min(o["start_time"]) < b:
            raise ApiError("SLOT_OVERLAP", f"Slot overlaps session {o['id']} ({o['start_time']}-{o['end_time']})")
    s = new_session(M, req.course_id, req.topic.strip(), req.date, req.plan_id, start=req.start_time,
                    end=to_hhmm(b), rot=req.rotation_seconds, win=req.window_seconds)
    save(M)
    return summary(s)


@app.get("/api/sessions/{sid}")
def detail(sid: int):
    s = sess(meta(), sid)
    rows = [{**u, **s["records"].get(u["uid"], {"status": None, "source": None, "reason": ""})} for u in ROSTER]
    return {**summary(s), "records": [{"uid": r["uid"], "name": r["name"], "status": r["status"],
                                       "source": r["source"], "reason": r["reason"]} for r in rows],
            "alerts": get_alerts(sid), "log": s["log"]}


@app.post("/api/sessions/{sid}/start")
def start(sid: int):
    M = meta()
    s = sess(M, sid)
    if s["status"] != "SCHEDULED":
        raise ApiError("INVALID_STATE", f"Cannot start a session that is {s['status']}")
    if open_session(M):
        raise ApiError("INVALID_STATE", "Another session is already open")
    s["status"] = "OPEN"
    s["opened_at"] = time.time()
    save(M)
    return summary(s)


@app.post("/api/sessions/{sid}/close")
def close(sid: int):
    M = meta()
    s = sess(M, sid)
    if s["status"] != "OPEN":
        raise ApiError("INVALID_STATE", "Only an open session can be closed")
    scanned = {x["uid"]: x["time"] for x in get_scans(sid)}
    for u in ROSTER:
        p = u["uid"] in scanned
        s["records"][u["uid"]] = {"status": "PRESENT" if p else "ABSENT", "source": "SCAN" if p else "SYSTEM",
                                  "reason": "" if p else "No attendance submission", "at": scanned.get(u["uid"], "")}
    s["alert_count"] = len(get_alerts(sid))
    s["status"] = "CLOSED"
    save(M)
    return summary(s)


@app.put("/api/sessions/{sid}/records/{uid}")
def edit(sid: int, uid: str, req: RecordReq):
    M = meta()
    s = sess(M, sid)
    if s["status"] not in ("CLOSED", "SAVED", "SUBMITTED"):
        raise ApiError("INVALID_STATE", "Edits are allowed only after the session is closed")
    if req.status not in ("PRESENT", "ABSENT", "EXCUSED") or len(req.reason.strip()) < 5:
        raise ApiError("VALIDATION_ERROR", "Valid status and a reason of at least 5 characters are required")
    r = s["records"].get(uid)
    if not r:
        raise ApiError("NOT_FOUND", "Student not found", 404)
    s["log"].insert(0, {"time": hms(), "uid": uid, "old": r["status"], "new": req.status, "reason": req.reason.strip()})
    r.update(status=req.status, source="MANUAL", reason=req.reason.strip())
    save(M)
    return {"ok": True}


def move(sid, frm, to):
    M = meta()
    s = sess(M, sid)
    if s["status"] != frm:
        raise ApiError("INVALID_STATE", f"Session must be {frm}")
    s["status"] = to
    if to == "SUBMITTED" and s["plan_id"]:
        for p in M["plan"]:
            if p["id"] == s["plan_id"]:
                p["status"] = "DONE"
    save(M)
    return summary(s)


@app.post("/api/sessions/{sid}/save")
def save_attendance(sid: int):
    return move(sid, "CLOSED", "SAVED")


@app.post("/api/sessions/{sid}/submit")
def submit_final(sid: int):
    return move(sid, "SAVED", "SUBMITTED")


@app.get("/api/live")
def live():
    s = open_session(meta())
    if not s:
        return {"session": None}
    sid = s["id"]
    with ThreadPoolExecutor(3) as ex:
        f_scans, f_devs, f_alerts = ex.submit(get_scans, sid), ex.submit(hgetall, "ps:devices"), ex.submit(get_alerts, sid)
        scans, devs, alerts = f_scans.result(), f_devs.result(), f_alerts.result()
    left = max(0, round(s["opened_at"] + s["window_seconds"] - time.time()))
    svg = None
    if left > 0:
        svg = segno.make(qr_for(s, step(s)), error="m").svg_inline(scale=8, border=2, dark="#1d3b6f", light="#ffffff")
    rot = s["rotation_seconds"]
    scanned = {x["uid"]: x for x in scans}
    roster = [{"uid": u["uid"], "name": u["name"], "device": LOGIN_BY_UID[u["uid"]] in devs,
               "present": u["uid"] in scanned, "time": scanned.get(u["uid"], {}).get("time", "")} for u in ROSTER]
    return {"session": summary(s, scans, len(alerts)), "qr_svg": svg,
            "expires_in": round(rot - ((time.time() - s["opened_at"]) % rot), 1),
            "remaining": left, "roster": roster, "scans": scans, "alerts": alerts}


@app.get("/api/health")
def health():
    """Open /api/health to check the database works and see how much data it holds."""
    out = {"store": "sqlite", "file": DB_PATH}
    try:
        out["sessions"] = len(meta()["sessions"])
        out["devices_registered"] = len(hgetall("ps:devices"))
        out["ok"] = True
    except ApiError as e:
        out.update(ok=False, error=e.message)
    return out


@app.get("/api/analytics/{cid}")
def analytics(cid: int):
    M = meta()
    subs = sorted([s for s in M["sessions"].values() if s["course_id"] == cid and s["status"] == "SUBMITTED"],
                  key=lambda s: s["id"])
    rows = []
    for u in ROSTER:
        recs = [s["records"][u["uid"]]["status"] for s in subs]
        t = len(recs) - recs.count("EXCUSED")
        p = recs.count("PRESENT")
        rows.append({"uid": u["uid"], "name": u["name"], "present": p, "conducted": t,
                     "pct": round(p * 100 / t, 1) if t else None})
    per = [{"id": s["id"], "date": s["date"], "topic": s["topic"],
            "present": sum(r["status"] == "PRESENT" for r in s["records"].values()), "total": len(ROSTER)} for s in subs]
    return {"conducted": len(subs), "students": rows, "sessions": per}


@app.get("/api/plan")
def plan():
    return meta()["plan"]


@app.post("/api/plan")
def plan_add(req: PlanReq):
    M = meta()
    M["nid"]["p"] += 1
    n = sum(p["course_id"] == req.course_id for p in M["plan"]) + 1
    M["plan"].append({"id": M["nid"]["p"], "course_id": req.course_id, "no": n, "topic": req.topic.strip(),
                      "planned_date": req.planned_date, "status": "PLANNED"})
    save(M)
    return {"ok": True}


@app.post("/api/plan/{pid}/toggle")
def plan_toggle(pid: int):
    M = meta()
    for p in M["plan"]:
        if p["id"] == pid:
            p["status"] = "PLANNED" if p["status"] == "DONE" else "DONE"
    save(M)
    return {"ok": True}


@app.delete("/api/plan/{pid}")
def plan_del(pid: int):
    M = meta()
    M["plan"] = [p for p in M["plan"] if p["id"] != pid]
    save(M)
    return {"ok": True}


@app.post("/api/admin/reset-devices")
def reset_devices():
    cmd("DEL", "ps:devices")
    return {"ok": True}


@app.post("/api/admin/reset-all")
def reset_all():
    """Wipes sessions/plan back to the seed data (devices stay registered)."""
    save(seed())
    return {"ok": True}


@app.get("/")
def faculty_page():
    return FileResponse(BASE / "faculty.html")
