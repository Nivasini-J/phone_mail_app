import os, sqlite3, random, secrets, time, json, hashlib, requests
from flask import Flask, request, jsonify, send_from_directory, Response
app = Flask(__name__, static_folder="static", static_url_path="")
DB = "/data/pm.db" if os.path.isdir("/data") else "pm.db"
OTPS, TOKENS = {}, {}
def db():
    c = sqlite3.connect(DB); c.row_factory = sqlite3.Row; return c
with db() as c:
    c.executescript("""create table if not exists users(phone text primary key, app int default 0, name text default '', pw text, lang text default 'en', pic text default '');
    create table if not exists alias(alias text primary key, phone text);
    create table if not exists mail(id integer primary key, frm text, to_ text, cc text default '', subj text, body text, reply_to int, grp text, att text default '[]', ts real);
    create table if not exists st(mid int, user text, read int default 0, fav int default 0, trash int default 0, spam int default 0, primary key(mid,user));
    create table if not exists otp(phone text primary key, code text, exp real, tries int default 0);
    create table if not exists sess(token text primary key, phone text);
    create table if not exists drafts(id integer primary key, user text, to_ text, subj text, body text, ts real);""")
def sms(to, text):
    s, t, f = (os.getenv(k) for k in ("TWILIO_SID", "TWILIO_TOKEN", "TWILIO_FROM"))
    if s and t and f:
        try: requests.post(f"https://api.twilio.com/2010-04-01/Accounts/{s}/Messages.json", auth=(s, t), data={"To": to, "From": f, "Body": text}, timeout=8); return True
        except Exception: pass
    return False
def tok(t):
    with db() as c: r = c.execute("select phone from sess where token=?", (t,)).fetchone()
    return r["phone"] if r else None
def me(): return tok(request.headers.get("Authorization", ""))
def chk(p, o):
    with db() as c:
        r = c.execute("select * from otp where phone=?", (p,)).fetchone()
        if not r or r["exp"] < time.time() or r["tries"] >= 5: return False
        if r["code"] != str(o):
            c.execute("update otp set tries=tries+1 where phone=?", (p,)); return False
        c.execute("delete from otp where phone=?", (p,)); return True
def hp(p): return hashlib.sha256(("pm" + p).encode()).hexdigest()
def norm(p): return "".join(ch for ch in p.split("@")[0] if ch.isdigit())
def resolve(x):
    x = x.strip().split("@")[0]
    with db() as c:
        r = c.execute("select phone from alias where alias=?", (x.lower(),)).fetchone()
    return r["phone"] if r else norm(x)
def login_token(p, app_=0, pw=None):
    with db() as c:
        c.execute("insert or ignore into users(phone,app) values(?,?)", (p, app_))
        if app_: c.execute("update users set app=1 where phone=?", (p,))
        if pw: c.execute("update users set pw=? where phone=?", (hp(pw), p))
    t = secrets.token_hex(16)
    with db() as c: c.execute("insert into sess values(?,?)", (t, p))
    return jsonify(token=t, email=f"{p}@phonemail.com")
@app.post("/api/otp")
def otp():
    p = norm(request.json["phone"]); o = str(random.randint(100000, 999999))
    if len(p) < 10: return jsonify(error="Enter a valid phone number"), 400
    with db() as c:
        r = c.execute("select exp from otp where phone=?", (p,)).fetchone()
        if r and time.time() - (r["exp"] - 300) < 30: return jsonify(error="Wait 30 seconds before requesting another OTP"), 429
        c.execute("insert or replace into otp values(?,?,?,0)", (p, o, time.time() + 300))
    sent = sms("+" + p if len(p) > 10 else p, f"Your PhoneMail code is {o}")
    return jsonify(sent=sent, demo_otp=None if sent else o)
@app.post("/api/verify")
def verify():
    p = norm(request.json["phone"])
    if not chk(p, request.json["otp"]): return jsonify(error="Wrong or expired OTP"), 400
    return login_token(p, int(request.json.get("app", 0)), request.json.get("pw"))
@app.post("/api/login")  # password fallback
def pwlogin():
    p = norm(request.json["phone"])
    with db() as c: u = c.execute("select pw from users where phone=?", (p,)).fetchone()
    if not u or u["pw"] != hp(request.json["pw"]): return jsonify(error="Wrong phone or password"), 400
    return login_token(p, 1)
@app.post("/api/portal")  # registration-only portal
def portal():
    p = norm(request.json["phone"])
    if not chk(p, request.json["otp"]): return jsonify(error="Wrong or expired OTP"), 400
    with db() as c: c.execute("insert or ignore into users(phone,app) values(?,0)", (p,))
    return jsonify(ok=1, email=f"{p}@phonemail.com")
# ---- Twilio toll-free: IVR + SMS account creation
def twiml(x): return Response(f"<?xml version='1.0'?><Response>{x}</Response>", mimetype="text/xml")
@app.route("/voice", methods=["GET", "POST"])
def voice():
    return twiml("<Gather numDigits='1' action='/voice/gather'><Say>Welcome to Phone Mail. Press 1 to create your account.</Say></Gather><Say>No input received. Goodbye.</Say>")
@app.route("/voice/gather", methods=["GET", "POST"])
def gather():
    if request.values.get("Digits") != "1": return twiml("<Say>Invalid choice.</Say><Redirect>/voice</Redirect>")
    p = norm(request.values.get("From", ""))
    with db() as c: c.execute("insert or ignore into users(phone,app) values(?,0)", (p,))
    return twiml(f"<Say>Your account is created. Your mail I D is {' '.join(p)} at phone mail dot com. You will get an S M S for every email.</Say>")
@app.route("/sms", methods=["GET", "POST"])
def sms_in():
    p = norm(request.values.get("From", ""))
    with db() as c: c.execute("insert or ignore into users(phone,app) values(?,0)", (p,))
    return twiml(f"<Message>PhoneMail account created: {p}@phonemail.com</Message>")
# ---- mail
@app.post("/api/send")
def send():
    u = me()
    if not u: return "", 401
    d = request.json
    to = sorted({resolve(x) for x in d["to"].split(",") if x.strip()} - {u})
    cc = sorted({resolve(x) for x in d.get("cc", "").split(",") if x.strip()} - {u} - set(to))
    if not to: return jsonify(error="Add a recipient"), 400
    if d.get("reply_to"):
        with db() as c:
            if c.execute("select 1 from mail where reply_to=? and frm=?", (d["reply_to"], u)).fetchone():
                return jsonify(error="Each message can be replied to only once"), 400
    grp = ",".join(sorted(to + cc + [u])) if len(to + cc) > 1 else None
    with db() as c:
        cur = c.execute("insert into mail(frm,to_,cc,subj,body,reply_to,grp,att,ts) values(?,?,?,?,?,?,?,?,?)",
            (u, ",".join(to), ",".join(cc), d.get("subj", ""), d["body"], d.get("reply_to"), grp, json.dumps(d.get("att", [])), time.time()))
        spam = any(w in d["body"].lower() for w in ("lottery", "free money", "you won"))
        for r in to + cc:
            row = c.execute("select app from users where phone=?", (r,)).fetchone()
            if not row: c.execute("insert into users(phone,app) values(?,0)", (r,))
            c.execute("insert or ignore into st(mid,user,spam) values(?,?,?)", (cur.lastrowid, r, int(spam)))
            if (row is None or not row["app"]) and not spam:
                sms(r, f"You have received an email from {u}. Subject: {d.get('subj','')}.")
    return jsonify(ok=1)
@app.get("/api/mail")
def mail():
    u = me()
    if not u: return "", 401
    f = request.args.get("f", "home")
    with db() as c:
        rows = c.execute("""select m.*, coalesce(s.read,0) read, coalesce(s.fav,0) fav, coalesce(s.trash,0) trash, coalesce(s.spam,0) spam, (select coalesce(max(read),0) from st where mid=m.id and user!=m.frm) seen
          from mail m left join st s on s.mid=m.id and s.user=? where (m.frm=? or (','||m.to_||','||m.cc||',') like ?) order by ts""",
          (u, u, f"%,{u},%")).fetchall()
    out = [dict(r) for r in rows]
    keep = {"home": lambda r: not r["trash"] and not r["spam"], "spam": lambda r: r["spam"] and not r["trash"], "trash": lambda r: r["trash"]}[f]
    return jsonify([r for r in out if keep(r)])
@app.post("/api/mark/<int:i>/<f>")
def mark(i, f):
    u = me()
    if f not in ("read", "fav", "trash", "spam") or not u: return "", 400
    with db() as c:
        c.execute("insert or ignore into st(mid,user) values(?,?)", (i, u))
        c.execute(f"update st set {f}=1-{f} where mid=? and user=?", (i, u))
    return jsonify(ok=1)
@app.route("/api/drafts", methods=["GET", "POST", "DELETE"])
def drafts():
    u = me()
    if not u: return "", 401
    with db() as c:
        if request.method == "POST":
            d = request.json; c.execute("insert into drafts(user,to_,subj,body,ts) values(?,?,?,?,?)", (u, d["to"], d["subj"], d["body"], time.time()))
        if request.method == "DELETE": c.execute("delete from drafts where id=? and user=?", (request.args["id"], u))
        return jsonify([dict(r) for r in c.execute("select * from drafts where user=? order by ts desc", (u,))])
@app.route("/api/profile", methods=["GET", "POST"])
def profile():
    u = me()
    if not u: return "", 401
    with db() as c:
        d = request.json if request.method == "POST" else {}
        if "name" in d: c.execute("update users set name=? where phone=?", (d["name"], u))
        if "lang" in d: c.execute("update users set lang=? where phone=?", (d["lang"], u))
        if "pic" in d: c.execute("update users set pic=? where phone=?", (d["pic"], u))
        if d.get("alias"):
            a = d["alias"].lower().strip()
            if c.execute("select 1 from alias where alias=?", (a,)).fetchone() or a.isdigit(): return jsonify(error="Alias unavailable"), 400
            c.execute("insert into alias values(?,?)", (a, u))
        if d.get("del_alias"): c.execute("delete from alias where alias=? and phone=?", (d["del_alias"], u))
        r = dict(c.execute("select name,lang,pic from users where phone=?", (u,)).fetchone())
        r["aliases"] = [x["alias"] for x in c.execute("select alias from alias where phone=?", (u,))]
        r["phone"] = u
    return jsonify(r)
@app.get("/api/stream")  # realtime push (Server-Sent Events)
def stream():
    u = tok(request.args.get("token", ""))
    if not u: return "", 401
    def gen():
        last = None
        for n in range(900):
            with db() as c:
                sig = tuple(c.execute("select (select max(id) from mail),(select coalesce(sum(read+fav+trash+spam),0) from st),(select count(*) from st)").fetchone())
            if sig != last: last = sig; yield "data: update\n\n"
            elif n % 15 == 0: yield ": ping\n\n"
            time.sleep(1)
    return Response(gen(), mimetype="text/event-stream", headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})
@app.get("/healthz")
def health(): return "ok"
@app.get("/")
def idx(): return send_from_directory("static", "index.html")
