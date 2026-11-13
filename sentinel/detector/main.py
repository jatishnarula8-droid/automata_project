"""Detector server: tails the victim's log, runs the automata, streams to the dashboard.

    python -m detector.main                 # watch shared/victim.log
    python -m detector.main --demo          # synthetic traffic, no victim needed
    python -m detector.main --log some.log  # any file in the same line format
"""
import argparse
import asyncio
import csv
import io
import json
import os
import sys
import threading
import time
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import simulate  # noqa: E402
from engine.detectors import Analyzer, inspect, machine_defs, parse_line  # noqa: E402
from engine.dfa import RegexError, regex_pipeline  # noqa: E402

SHARED = os.path.join(ROOT, "shared")
MODE = os.path.join(SHARED, "mode.json")
BANS = os.path.join(SHARED, "blocklist.json")
BAN_SECONDS = 20

analyzer = Analyzer()
clients = set()
history = []
config = {"log": os.path.join(SHARED, "victim.log"), "demo": False, "from_start": False}
state = {"protected": False, "lines": 0}


def read_json(path, default):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def write_json(path, obj):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f)
    os.replace(tmp, path)


def bans():
    now = time.time()
    return {ip: exp for ip, exp in read_json(BANS, {}).items() if exp > now}


async def broadcast(msg):
    text = json.dumps(msg)
    for ws in list(clients):
        try:
            await ws.send_text(text)
        except Exception:
            clients.discard(ws)


async def handle_line(line):
    rec = parse_line(line)
    if not rec:
        return
    state["lines"] += 1
    ev = analyzer.process(rec)
    history.append(ev)
    del history[:-400]
    if state["protected"] and ev["alerts"]:
        current = bans()
        if ev["ip"] not in current:
            current[ev["ip"]] = time.time() + BAN_SECONDS
            write_json(BANS, current)
            ev["banned"] = BAN_SECONDS
    await broadcast(ev)


async def tail(path, from_start):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if not os.path.exists(path):
        open(path, "a").close()
    pos = 0 if from_start else os.path.getsize(path)
    buf = b""
    while True:
        size = os.path.getsize(path)
        if size < pos:
            pos, buf = 0, b""
        if size > pos:
            with open(path, "rb") as f:
                f.seek(pos)
                chunk = f.read()
            pos += len(chunk)
            buf += chunk
            *lines, buf = buf.split(b"\n")
            for ln in lines:
                await handle_line(ln.decode("utf-8", "replace"))
        await asyncio.sleep(0.1)


async def ban_watcher():
    """Tell dashboards when bans appear/expire so the blocked-IP panel stays live."""
    last = None
    while True:
        cur = {ip: round(exp - time.time()) for ip, exp in bans().items()}
        if cur != last or cur:
            await broadcast({"type": "bans", "bans": cur})
            last = cur
        await asyncio.sleep(1)


@asynccontextmanager
async def lifespan(app):
    os.makedirs(SHARED, exist_ok=True)
    state["protected"] = bool(read_json(MODE, {}).get("protected"))
    write_json(BANS, {})
    tasks = [asyncio.create_task(ban_watcher())]
    if config["demo"]:
        from .demo import generate
        tasks.append(asyncio.create_task(generate(handle_line)))
    else:
        tasks.append(asyncio.create_task(tail(config["log"], config["from_start"])))
    yield
    for t in tasks:
        t.cancel()


app = FastAPI(lifespan=lifespan)
STATIC = os.path.join(ROOT, "static")


@app.get("/")
def index():
    return FileResponse(os.path.join(STATIC, "index.html"))


@app.websocket("/ws")
async def ws(websocket: WebSocket):
    await websocket.accept()
    clients.add(websocket)
    try:
        await websocket.send_text(json.dumps({"type": "init", "machines": machine_defs(), "history": history[-300:],
                                              "protected": state["protected"], "demo": config["demo"],
                                              "log": config["log"], "banSeconds": BAN_SECONDS}))
        while True:
            await websocket.receive_text()
    except (WebSocketDisconnect, RuntimeError):
        pass
    finally:
        clients.discard(websocket)


@app.get("/api/trace/{rid}")
def trace(rid: int):
    t = analyzer.trace(rid)
    return JSONResponse(t) if t else JSONResponse({"error": "gone"}, status_code=404)


@app.post("/api/mode")
async def set_mode(body: dict):
    state["protected"] = bool(body.get("protected"))
    write_json(MODE, {"protected": state["protected"]})
    if not state["protected"]:
        write_json(BANS, {})
    await broadcast({"type": "mode", "protected": state["protected"]})
    return {"protected": state["protected"]}


@app.post("/api/unblock")
def unblock():
    write_json(BANS, {})
    return {"ok": True}


@app.post("/api/reset")
def reset():
    analyzer.reset()
    history.clear()
    write_json(BANS, {})
    return {"ok": True}


@app.post("/api/simulate")
def run_simulation(body: dict):
    name = body.get("kind", "")
    if name != "all" and name not in simulate.SCENARIOS:
        return JSONResponse({"error": "unknown scenario"}, status_code=400)
    threading.Thread(target=simulate.run, args=(name,), daemon=True).start()
    return {"started": name}


@app.post("/api/regex")
def regex(body: dict):
    try:
        return regex_pipeline(body.get("pattern", ""), body.get("sample"))
    except RegexError as e:
        return JSONResponse({"error": str(e)}, status_code=400)


@app.post("/api/inspect")
def inspect_payload(body: dict):
    """Run a payload through every machine (used by the 'compare machines' lab)."""
    target = body.get("payload", "")
    if "?" not in target:
        target = "/search?q=" + target
    rec = parse_line("2000-01-01T00:00:00.000 0.0.0.0 GET %s 200 -" % target.replace(" ", "%20"))
    rec["ip_steps"] = {}
    from engine.detectors import full_trace
    return {"findings": inspect(target.replace(" ", "%20")), "trace": full_trace(rec)}


@app.get("/api/report.csv")
def report():
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(["time", "ip", "attack_type", "machine", "severity", "detail", "request"])
    for ev in history:
        for a in ev["alerts"]:
            w.writerow([ev["iso"], ev["ip"], a["kind"], a["machine"], a["severity"], a["detail"], ev["target"]])
    return Response(out.getvalue(), media_type="text/csv",
                    headers={"Content-Disposition": "attachment; filename=alerts.csv"})


app.mount("/static", StaticFiles(directory=STATIC), name="static")

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--log", default=config["log"])
    ap.add_argument("--demo", action="store_true", help="synthetic traffic instead of tailing a file")
    ap.add_argument("--from-start", action="store_true", help="process the existing file content first")
    ap.add_argument("--port", type=int, default=8000)
    a = ap.parse_args()
    config.update(log=a.log, demo=a.demo, from_start=a.from_start)
    print("Dashboard: http://127.0.0.1:%d   (watching %s)" % (a.port, "demo traffic" if a.demo else a.log))
    uvicorn.run(app, host="127.0.0.1", port=a.port, log_level="warning")
