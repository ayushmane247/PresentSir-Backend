"""PresentSir demo backend. Run: uvicorn main:app --host 0.0.0.0 --port 8000"""
import base64, hashlib, hmac, json, random, secrets, time
from pathlib import Path

import segno
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi import FastAPI, Header, Request
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel

ROTATE = 10
BASE = Path(__file__).parent
DB = BASE / "devices.json"
SECRET = secrets.token_bytes(32)

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
DEVICES: dict = json.loads(DB.read_text()) if DB.exists() else {}
TOKENS: dict = {}
SESSIONS: dict = {}
PLAN: list = []
NONCES: set = set()
NID = {"s": 4800, "p": 0}

app = FastAPI(title="PresentSir demo")


class ApiError(Exception):
    def __init__(self, code, message, status=400):
        self.code, self.message, self.status = code, message, status


@app.exception_handler(ApiError)
async def _err(_: Request, e: ApiError):
    return JSONResponse(status_code=e.status, content={"code": e.code, "message": e.message})


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
    start_time: str = "10:00"          # HH:MM
    duration_min: int = 60
    rotation_seconds: int = 10         # how often the QR changes
    window_seconds: int = 120          # how long attendance stays open


class RecordReq(BaseModel):
    status: str
    reason: str


class PlanReq(BaseModel):
    course_id: int
    topic: str
    planned_date: str


def hms() -> str:
    return time.strftime("%H:%M:%S")


def course(cid):
    return next(c for c in COURSES if c["id"] == cid)


def sess(sid):
    s = SESSIONS.get(sid)
    if not s:
        raise ApiError("NOT_FOUND", "Session not found", 404)
    return s


def open_session():
    return next((s for s in SESSIONS.values() if s["status"] == "OPEN"), None)


def to_min(hhmm):
    h, m = hhmm.split(":")
    return int(h) * 60 + int(m)


def to_hhmm(mins):
    return f"{mins // 60:02d}:{mins % 60:02d}"


def new_session(cid, topic, date, plan_id=None, status="SCHEDULED", start="10:00", end="11:00",
                rot=10, win=120):
    NID["s"] += 1
    s = {"id": NID["s"], "course_id": cid, "topic": topic, "date": date, "plan_id": plan_id,
         "start_time": start, "end_time": end, "rotation_seconds": rot, "window_seconds": win,
         "status": status, "scans": [], "alerts": [], "records": {}, "log": []}
    SESSIONS[s["id"]] = s
    return s


def summary(s):
    pres = (sum(r["status"] == "PRESENT" for r in s["records"].values())
            if s["records"] else len(s["scans"]))
    c = course(s["course_id"])
    return {"id": s["id"], "course_id": c["id"], "course": c["name"], "code": c["code"], "date": s["date"],
            "topic": s["topic"], "status": s["status"], "present": pres, "total": len(ROSTER),
            "alerts": len(s["alerts"]), "start_time": s["start_time"], "end_time": s["end_time"],
            "rotation_seconds": s["rotation_seconds"], "window_seconds": s["window_seconds"]}


def seed():
    rnd = random.Random(7)
    topics = ["Introduction", "Activities and Intents", "Jetpack Compose basics", "Navigation", "Networking"]
    for cid in (1, 2, 3):
        for i, t in enumerate(topics):
            s = new_session(cid, t, f"2026-09-{8 + i * 3:02d}", status="SUBMITTED",
                            start=f"{8 + cid:02d}:00", end=f"{9 + cid:02d}:00")
            for u in ROSTER:
                p = rnd.random() < (0.55 if u["uid"] in ("A07", "A22") else 0.88)
                s["records"][u["uid"]] = {"status": "PRESENT" if p else "ABSENT",
                                          "source": "SCAN" if p else "SYSTEM", "reason": "", "at": "10:05:00"}
    for c in COURSES:
        for n, t in enumerate(["Unit 1 overview", "Unit 2 concepts", "Case study", "Revision"], 1):
            NID["p"] += 1
            PLAN.append({"id": NID["p"], "course_id": c["id"], "no": n, "topic": t,
                         "planned_date": f"2026-10-{n * 4:02d}", "status": "DONE" if n == 1 else "PLANNED"})


seed()


def user_from(auth):
    login = TOKENS.get((auth or "").removeprefix("Bearer ").strip())
    if not login:
        raise ApiError("UNAUTHORIZED", "Please log in again", 401)
    return login


def step(s):
    return int((time.time() - s["opened_at"]) // s["rotation_seconds"])


def qr_for(s, w):
    mac = base64.urlsafe_b64encode(hmac.new(SECRET, f"{s['id']}.{w}".encode(), hashlib.sha256).digest()[:9]).decode()
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


# ---------------- student / device (used by the Android app) ----------------
@app.post("/api/login")
def login(req: LoginReq):
    lid = req.login_id.strip().lower()
    u = USERS.get(lid)
    if not u or u["password"] != req.password:
        raise ApiError("INVALID_CREDENTIALS", "Wrong ID or password", 401)
    tok = secrets.token_urlsafe(24)
    TOKENS[tok] = lid
    d = DEVICES.get(lid)
    st = "NONE" if not d else ("ACTIVE_THIS_DEVICE" if d["android_id"] == req.android_id else "BOUND_TO_OTHER_DEVICE")
    return {"access_token": tok, "name": u["name"], "uid": u["uid"], "device_status": st}


@app.post("/api/device/register")
def register(req: RegisterReq, authorization: str | None = Header(None)):
    lid = user_from(authorization)
    d = DEVICES.get(lid)
    if d and d["android_id"] != req.android_id:
        raise ApiError("DEVICE_ALREADY_BOUND", "This account is bound to another device", 409)
    try:
        serialization.load_der_public_key(base64.b64decode(req.public_key))
    except Exception:
        raise ApiError("VALIDATION_ERROR", "Invalid public key")
    DEVICES[lid] = {"android_id": req.android_id, "public_key": req.public_key}
    DB.write_text(json.dumps(DEVICES))
    return {"status": "ACTIVE"}


@app.post("/api/attendance/submit")
def submit(req: SubmitReq, authorization: str | None = Header(None)):
    lid = user_from(authorization)
    s = open_session()
    if not s:
        raise ApiError("SESSION_NOT_OPEN", "Attendance session is not open")
    if time.time() > s["ends_at"]:
        raise ApiError("WINDOW_CLOSED", "The attendance window has ended")
    if req.session_id != s["id"]:
        raise ApiError("QR_INVALID", "QR belongs to a different session")
    check_qr(s, req.qr_token)
    if req.client_nonce in NONCES:
        raise ApiError("REPLAY", "Request already used")
    NONCES.add(req.client_nonce)
    d = DEVICES.get(lid)
    if not d:
        raise ApiError("DEVICE_NOT_REGISTERED", "Register this device first")
    u = USERS[lid]

    def alert(kind):
        s["alerts"].insert(0, {"time": hms(), "name": u["name"], "uid": u["uid"], "kind": kind,
                               "attempted_device": req.android_id, "registered_device": d["android_id"]})

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
    if not any(x["uid"] == u["uid"] for x in s["scans"]):
        s["scans"].append({"name": u["name"], "uid": u["uid"], "time": hms(), "device": req.android_id})
    return {"status": "MARKED", "message": "Attendance marked"}


@app.get("/api/student/attendance")
def student_attendance(authorization: str | None = Header(None)):
    """Per-course attendance of the logged-in student.
    Demo rule: an OPEN session counts as present as soon as the student has scanned;
    closed/saved/submitted sessions use the official record."""
    uid = USERS[user_from(authorization)]["uid"]
    out = []
    for c in COURSES:
        present = total = 0
        for s in SESSIONS.values():
            if s["course_id"] != c["id"]:
                continue
            if s["status"] == "OPEN":
                if any(x["uid"] == uid for x in s["scans"]):
                    present += 1
                    total += 1
            elif s["records"]:
                st = s["records"].get(uid, {}).get("status")
                if st == "EXCUSED":
                    continue
                total += 1
                present += st == "PRESENT"
        out.append({"name": c["name"], "code": c["code"], "faculty": c["faculty"],
                    "present": present, "total": total})
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
    return [summary(s) for s in sorted(SESSIONS.values(), key=lambda s: (s["date"], s["start_time"], s["id"]), reverse=True)]


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
    for o in SESSIONS.values():
        if o["date"] == req.date and o["status"] != "CANCELLED" and a < to_min(o["end_time"]) and to_min(o["start_time"]) < b:
            raise ApiError("SLOT_OVERLAP", f"Slot overlaps session {o['id']} ({o['start_time']}-{o['end_time']})")
    return summary(new_session(req.course_id, req.topic.strip(), req.date, req.plan_id, start=req.start_time,
                               end=to_hhmm(b), rot=req.rotation_seconds, win=req.window_seconds))


@app.get("/api/sessions/{sid}")
def detail(sid: int):
    s = sess(sid)
    rows = [{**u, **s["records"].get(u["uid"], {"status": None, "source": None, "reason": ""})} for u in ROSTER]
    return {**summary(s), "records": [{"uid": r["uid"], "name": r["name"], "status": r["status"],
                                       "source": r["source"], "reason": r["reason"]} for r in rows],
            "alerts": s["alerts"], "log": s["log"]}


@app.post("/api/sessions/{sid}/start")
def start(sid: int):
    s = sess(sid)
    if s["status"] != "SCHEDULED":
        raise ApiError("INVALID_STATE", f"Cannot start a session that is {s['status']}")
    if open_session():
        raise ApiError("INVALID_STATE", "Another session is already open")
    s["status"] = "OPEN"
    s["opened_at"] = time.time()
    s["ends_at"] = s["opened_at"] + s["window_seconds"]
    NONCES.clear()
    return summary(s)


@app.post("/api/sessions/{sid}/close")
def close(sid: int):
    s = sess(sid)
    if s["status"] != "OPEN":
        raise ApiError("INVALID_STATE", "Only an open session can be closed")
    scanned = {x["uid"]: x["time"] for x in s["scans"]}
    for u in ROSTER:
        p = u["uid"] in scanned
        s["records"][u["uid"]] = {"status": "PRESENT" if p else "ABSENT", "source": "SCAN" if p else "SYSTEM",
                                  "reason": "" if p else "No attendance submission", "at": scanned.get(u["uid"], "")}
    s["status"] = "CLOSED"
    return summary(s)


@app.put("/api/sessions/{sid}/records/{uid}")
def edit(sid: int, uid: str, req: RecordReq):
    s = sess(sid)
    if s["status"] not in ("CLOSED", "SAVED", "SUBMITTED"):
        raise ApiError("INVALID_STATE", "Edits are allowed only after the session is closed")
    if req.status not in ("PRESENT", "ABSENT", "EXCUSED") or len(req.reason.strip()) < 5:
        raise ApiError("VALIDATION_ERROR", "Valid status and a reason of at least 5 characters are required")
    r = s["records"].get(uid)
    if not r:
        raise ApiError("NOT_FOUND", "Student not found", 404)
    s["log"].insert(0, {"time": hms(), "uid": uid, "old": r["status"], "new": req.status, "reason": req.reason.strip()})
    r.update(status=req.status, source="MANUAL", reason=req.reason.strip())
    return {"ok": True}


def move(sid, frm, to):
    s = sess(sid)
    if s["status"] != frm:
        raise ApiError("INVALID_STATE", f"Session must be {frm}")
    s["status"] = to
    if to == "SUBMITTED" and s["plan_id"]:
        for p in PLAN:
            if p["id"] == s["plan_id"]:
                p["status"] = "DONE"
    return summary(s)


@app.post("/api/sessions/{sid}/save")
def save(sid: int):
    return move(sid, "CLOSED", "SAVED")


@app.post("/api/sessions/{sid}/submit")
def submit_final(sid: int):
    return move(sid, "SAVED", "SUBMITTED")


@app.get("/api/live")
def live():
    s = open_session()
    if not s:
        return {"session": None}
    left = max(0, round(s["ends_at"] - time.time()))
    svg = None
    if left > 0:
        svg = segno.make(qr_for(s, step(s)), error="m").svg_inline(scale=8, border=2, dark="#1d3b6f", light="#ffffff")
    rot = s["rotation_seconds"]
    scanned = {x["uid"]: x for x in s["scans"]}
    roster = [{"uid": u["uid"], "name": u["name"], "device": LOGIN_BY_UID[u["uid"]] in DEVICES,
               "present": u["uid"] in scanned, "time": scanned.get(u["uid"], {}).get("time", "")} for u in ROSTER]
    return {"session": summary(s), "qr_svg": svg, "expires_in": round(rot - ((time.time() - s["opened_at"]) % rot), 1),
            "remaining": left, "roster": roster, "scans": s["scans"], "alerts": s["alerts"]}


@app.get("/api/analytics/{cid}")
def analytics(cid: int):
    subs = sorted([s for s in SESSIONS.values() if s["course_id"] == cid and s["status"] == "SUBMITTED"],
                  key=lambda s: s["id"])
    rows = []
    for u in ROSTER:
        recs = [s["records"][u["uid"]]["status"] for s in subs]
        t = len(recs) - recs.count("EXCUSED")
        p = recs.count("PRESENT")
        rows.append({"uid": u["uid"], "name": u["name"], "present": p, "conducted": t,
                     "pct": round(p * 100 / t, 1) if t else None})
    per = [{"id": s["id"], "date": s["date"], "topic": s["topic"], "present": summary(s)["present"],
            "total": len(ROSTER)} for s in subs]
    return {"conducted": len(subs), "students": rows, "sessions": per}


@app.get("/api/plan")
def plan():
    return PLAN


@app.post("/api/plan")
def plan_add(req: PlanReq):
    NID["p"] += 1
    n = sum(p["course_id"] == req.course_id for p in PLAN) + 1
    PLAN.append({"id": NID["p"], "course_id": req.course_id, "no": n, "topic": req.topic.strip(),
                 "planned_date": req.planned_date, "status": "PLANNED"})
    return {"ok": True}


@app.post("/api/plan/{pid}/toggle")
def plan_toggle(pid: int):
    for p in PLAN:
        if p["id"] == pid:
            p["status"] = "PLANNED" if p["status"] == "DONE" else "DONE"
    return {"ok": True}


@app.delete("/api/plan/{pid}")
def plan_del(pid: int):
    PLAN[:] = [p for p in PLAN if p["id"] != pid]
    return {"ok": True}


@app.post("/api/admin/reset-devices")
def reset_devices():
    DEVICES.clear()
    DB.write_text("{}")
    return {"ok": True}


@app.get("/")
def faculty_page():
    return FileResponse(BASE / "faculty.html")
