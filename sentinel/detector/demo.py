"""Backup traffic generator: emits log lines in the victim's format with no web server."""
import asyncio
import random
import time
from urllib.parse import quote

ATTACKS = [
    ("POST", "/login?user=" + quote("admin' or 1=1 --", safe=""), 200, "LOGIN_OK"),
    ("GET", "/search?q=" + quote("x' union select username,password from users --", safe=""), 200, "-"),
    ("GET", "/search?q=" + quote("<script>alert(1)</script>", safe=""), 200, "-"),
    ("GET", "/search?q=" + quote("<div><b>x</b></div>", safe=""), 200, "-"),
    ("GET", "/search?q=" + quote("x' and (select (select 1))=1 and 'a'='a", safe=""), 200, "-"),
    ("GET", "/files?name=" + quote("../secret.txt", safe=""), 200, "-"),
]
NORMAL = [("GET", "/", 200, "-"), ("GET", "/product/2", 200, "-"), ("GET", "/search?q=shoes", 200, "-"), ("GET", "/login", 200, "-")]


def _line(ip, method, target, status, result):
    iso = time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime()) + ".%03d" % (int(time.time() * 1000) % 1000)
    return "%s %s %s %s %d %s" % (iso, ip, method, target, status, result)


async def generate(push):
    n = 0
    while True:
        n += 1
        await push(_line("10.0.1.%d" % random.randint(2, 5), *random.choice(NORMAL)))
        await asyncio.sleep(0.5)
        if n % 6 == 0:
            await push(_line("10.0.9.9", *random.choice(ATTACKS)))
        if n % 17 == 0:
            for i in range(6):
                await push(_line("10.0.8.8", "POST", "/login?user=admin", 401, "LOGIN_FAIL"))
                await asyncio.sleep(0.3)
        if n % 23 == 0:
            for p in ("/admin", "/.env", "/wp-login.php", "/backup.zip", "/phpmyadmin", "/x"):
                await push(_line("10.0.7.7", "GET", p, 404, "-"))
                await asyncio.sleep(0.2)
