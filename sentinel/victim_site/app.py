"""ShopSecure: a deliberately vulnerable demo shop. Bind to localhost only.

Vulnerabilities (on purpose): SQL injection in /login and /search, reflected XSS
in /search, path traversal in /files, no rate limit on /login, trusts
X-Forwarded-For. In *protected* mode the shop asks the same automata the
detector uses to inspect each request before handling it.
"""
import html
import json
import os
import sqlite3
import sys
import time
from urllib.parse import parse_qs, quote

import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, PlainTextResponse

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from engine.detectors import inspect  # noqa: E402

SHARED = os.path.join(ROOT, "shared")
LOG = os.path.join(SHARED, "victim.log")
MODE = os.path.join(SHARED, "mode.json")
BANS = os.path.join(SHARED, "blocklist.json")
FILES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "files")
os.makedirs(SHARED, exist_ok=True)

db = sqlite3.connect(":memory:", check_same_thread=False)
db.executescript("""
CREATE TABLE users(id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT);
INSERT INTO users(username,password,role) VALUES('ravi','2025uai1639','admin'),('vyom','2025uai1866','user'),('jatish','2025uai1362','user');
CREATE TABLE products(id INTEGER PRIMARY KEY, name TEXT, price REAL);
INSERT INTO products(name,price) VALUES('Blue Running Shoes',59.9),('Red Hoodie',39.5),('Black Backpack',45.0),
 ('Steel Water Bottle',19.0),('Wireless Headphones',89.0),('Desk Lamp',24.5);
""")

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)


def read_json(path, default):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def protected():
    return bool(read_json(MODE, {}).get("protected"))


def banned(ip):
    exp = read_json(BANS, {}).get(ip)
    return bool(exp) and exp > time.time()


def client_ip(request):
    fwd = request.headers.get("x-forwarded-for")
    return fwd.split(",")[0].strip() if fwd else request.client.host


def write_log(ip, method, target, status, result):
    iso = time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime()) + ".%03d" % (int(time.time() * 1000) % 1000)
    with open(LOG, "a", encoding="utf-8") as f:
        f.write("%s %s %s %s %d %s\n" % (iso, ip, method, target, status, result))


PAGE = """<!doctype html><html><head><meta charset="utf-8"><title>ShopSecure</title>
<style>body{{font-family:system-ui,sans-serif;background:#f6f7fb;color:#1f2937;margin:0}}
header{{background:#fff;border-bottom:1px solid #e5e7eb;padding:14px 28px;display:flex;gap:22px;align-items:center}}
header b{{font-size:20px;color:#2563eb}} a{{color:#2563eb;text-decoration:none}} main{{max-width:820px;margin:28px auto;padding:0 20px}}
.card{{background:#fff;border:1px solid #e5e7eb;border-radius:10px;padding:16px 20px;margin-bottom:14px}}
input{{padding:8px 10px;border:1px solid #cbd5e1;border-radius:6px;margin:4px 0;width:260px}}
button{{padding:8px 16px;border:0;border-radius:6px;background:#2563eb;color:#fff;cursor:pointer}}
.pill{{margin-left:auto;font-size:12px;padding:4px 10px;border-radius:99px;background:{pc};color:#fff}} .err{{color:#b91c1c}}</style></head>
<body><header><b>ShopSecure</b><a href="/">Home</a><a href="/login">Login</a><a href="/files?name=readme.txt">Docs</a>
<form action="/search" style="margin:0"><input name="q" placeholder="Search products" style="width:200px"> <button>Search</button></form>
<span class="pill">{mode}</span></header><main>{body}</main></body></html>"""


def page(body):
    prot = protected()
    return HTMLResponse(PAGE.format(body=body, mode="PROTECTED" if prot else "VULNERABLE", pc="#16a34a" if prot else "#dc2626"))


def blocked_page(why):
    return HTMLResponse(PAGE.format(body='<div class="card"><h2 class="err">403 Blocked</h2><p>%s</p></div>' % html.escape(why),
                                    mode="PROTECTED", pc="#16a34a"), status_code=403)


@app.middleware("http")
async def logger(request: Request, call_next):
    ip = client_ip(request)
    target = request.url.path + ("?" + request.url.query if request.url.query else "")
    if banned(ip):
        write_log(ip, request.method, target, 403, "BANNED")
        return blocked_page("Your IP address was banned by the intrusion detector.")
    if protected() and request.method == "GET" and (hits := [f for f in inspect(target) if f["severity"] != "low"]):
        write_log(ip, request.method, target, 403, "BLOCKED")
        return blocked_page("Request blocked by automata firewall (%s)." % hits[0]["machine"])
    response = await call_next(request)
    result = response.headers.get("x-result", "-")
    logged = response.headers.get("x-log-target", target)
    for h in ("x-result", "x-log-target"):
        if h in response.headers:
            del response.headers[h]
    write_log(ip, request.method, logged, response.status_code, result)
    return response


@app.get("/", response_class=HTMLResponse)
def home():
    rows = db.execute("SELECT id,name,price FROM products").fetchall()
    items = "".join('<div class="card"><a href="/product/%d">%s</a> <span style="float:right">$%.2f</span></div>' % r for r in rows)
    return page("<h2>Products</h2>" + items)


@app.get("/product/{pid}", response_class=HTMLResponse)
def product(pid: int):
    r = db.execute("SELECT name,price FROM products WHERE id=?", (pid,)).fetchone()
    if not r:
        return HTMLResponse(PAGE.format(body="<h2>No such product</h2>", mode="", pc="#6b7280"), status_code=404)
    return page('<div class="card"><h2>%s</h2><p>$%.2f</p></div>' % (html.escape(r[0]), r[1]))


@app.get("/search", response_class=HTMLResponse)
def search(q: str = ""):
    # VULNERABLE: string concatenation (SQLi) and unescaped reflection (XSS)
    sql = "SELECT name, price FROM products WHERE name LIKE '%" + q + "%'"
    try:
        rows = db.execute(sql).fetchall()
        out = "".join('<div class="card">%s <span style="float:right">%s</span></div>' % (r[0], r[1]) for r in rows) or "<p>No results.</p>"
    except sqlite3.Error as e:
        out = '<p class="err">Database error: %s<br>Query: %s</p>' % (html.escape(str(e)), html.escape(sql))
    return page("<h2>Results for: %s</h2>%s" % (q, out))


@app.get("/login", response_class=HTMLResponse)
def login_form():
    return page('<div class="card"><h2>Login</h2><form method="post" action="/login">'
                'Username<br><input name="user"><br>Password<br><input name="password" type="password"><br><br>'
                '<button>Sign in</button></form><p style="font-size:12px;color:#6b7280">Demo users: vyom / 2025uai1866</p></div>')


@app.post("/login", response_class=HTMLResponse)
async def login(request: Request):
    form = parse_qs((await request.body()).decode("utf-8", "replace"), keep_blank_values=True)
    user, pw = form.get("user", [""])[0], form.get("password", [""])[0]
    log_target = "/login?user=" + quote(user, safe="")
    if protected() and any(f["severity"] != "low" for f in inspect("/login?user=" + quote(user, safe="") + "&pw=" + quote(pw, safe=""))):
        r = blocked_page("Login attempt blocked by automata firewall.")
        r.headers["x-result"], r.headers["x-log-target"] = "BLOCKED", log_target
        r.status_code = 403
        return r
    # VULNERABLE: string concatenation
    sql = "SELECT username, role FROM users WHERE username='%s' AND password='%s'" % (user, pw)
    try:
        row = db.execute(sql).fetchone()
    except sqlite3.Error as e:
        r = page('<div class="card err">Database error: %s</div>' % html.escape(str(e)))
        r.headers["x-result"], r.headers["x-log-target"] = "LOGIN_FAIL", log_target
        return r
    if row:
        r = page('<div class="card"><h2>Welcome, %s</h2><p>Role: %s</p></div>' % (html.escape(row[0]), html.escape(row[1])))
        r.headers["x-result"] = "LOGIN_OK"
    else:
        r = page('<div class="card"><h2 class="err">Login failed</h2><p><a href="/login">Try again</a></p></div>')
        r.status_code = 401
        r.headers["x-result"] = "LOGIN_FAIL"
    r.headers["x-log-target"] = log_target
    return r


@app.get("/files")
def files(name: str = "readme.txt"):
    # VULNERABLE: no path sanitisation
    path = os.path.join(FILES, name)
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return PlainTextResponse(f.read())
    except OSError:
        return PlainTextResponse("File not found", status_code=404)


if __name__ == "__main__":
    port = int(os.environ.get("VICTIM_PORT", "5000"))
    print("ShopSecure (intentionally vulnerable) on http://127.0.0.1:%d" % port)
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="warning")
