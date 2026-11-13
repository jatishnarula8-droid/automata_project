"""Machine registry, log parsing and the stateful per-IP analyzer."""
import re
import time
from collections import deque
from datetime import datetime
from urllib.parse import unquote_plus

from . import cfg
from .dfa import DFA, aho_corasick
from .pda import HTML_PDA, SQL_PDA

WINDOW = 60.0          # seconds of silence after which per-IP counters reset (symbol T)
BRUTE_N = 5            # consecutive failed logins that trigger the alarm
SCAN_N = 5             # consecutive 404s that trigger the alarm

# ---- signature DFAs (Aho-Corasick) over the normalised request ------------
SIGNATURES = {
    "sqli_tautology": dict(title="DFA: SQLi tautology / comment", kind="SQL Injection", severity="high",
                           patterns=["' or ", "or 1=1", "'--"],
                           desc="Substring search for the classic login-bypass fragments."),
    "sqli_union": dict(title="DFA: SQLi UNION / schema probe", kind="SQL Injection", severity="high",
                       patterns=["union select", "information_schema"],
                       desc="Substring search for data-exfiltration keywords."),
    "xss_dfa": dict(title="DFA: XSS keywords", kind="XSS", severity="high",
                    patterns=["<script", "onerror=", "javascript:"],
                    desc="Substring search for script-injection markers."),
    "traversal_dfa": dict(title="DFA: path traversal", kind="Path Traversal", severity="high",
                          patterns=["../", "..\\", "/etc/passwd"],
                          desc="Substring search for directory escape sequences."),
}
SIG_DFAS = {k: aho_corasick(v["patterns"], k) for k, v in SIGNATURES.items()}


def _counter_dfa(name, n, up, labels_extra=None):
    """q0..qn counter. `up` advances, `reset` and T return to q0, qn is accepting and sticky on `up`."""
    alphabet = [up[0], up[1], "T"]
    delta = {}
    for q in range(n + 1):
        delta[(q, up[0])] = min(q + 1, n)
        delta[(q, up[1])] = 0
        delta[(q, "T")] = 0
    return DFA(range(n + 1), alphabet, delta, 0, {n}, name, {q: "q%d" % q for q in range(n + 1)})


# symbols: F = failed login, S = successful login, T = timeout / window expired
BRUTE = _counter_dfa("brute", BRUTE_N, ("F", "S"))
# symbols: N = a 404 response, O = any other response, T = timeout
SCAN = _counter_dfa("scan", SCAN_N, ("N", "O"))
PER_IP = {"brute": dict(dfa=BRUTE, kind="Brute Force", severity="high",
                        title="DFA: brute-force counter (per IP)",
                        desc="F = failed login, S = success, T = 60 s of silence. %d failures in a row raise the alarm." % BRUTE_N),
          "scan": dict(dfa=SCAN, kind="Scan / Probing", severity="medium",
                       title="DFA: 404 scan counter (per IP)",
                       desc="N = 404 response, O = anything else, T = 60 s of silence. %d 404s in a row raise the alarm." % SCAN_N)}


def machine_defs():
    defs = []
    for mid, s in SIGNATURES.items():
        d = SIG_DFAS[mid]
        defs.append(dict(id=mid, title=s["title"], kind="dfa", cls="Regular", perIP=False, desc=s["desc"],
                         patterns=s["patterns"], attack=s["kind"], graph=d.to_dict(forward_only=True), table=None))
    for mid, s in PER_IP.items():
        d = s["dfa"]
        defs.append(dict(id=mid, title=s["title"], kind="dfa", cls="Regular", perIP=True, desc=s["desc"],
                         patterns=[], attack=s["kind"], graph=d.to_dict(), table=d.to_table()))
    for p, desc in ((SQL_PDA, "Pushes on '(' and pops on ')'. Detects a SELECT nested two or more brackets deep, or brackets that never close. Balanced brackets are not a regular language, so a DFA cannot do this."),
                    (HTML_PDA, "Pushes each opening tag and pops on the matching closing tag. Flags tags nested inside tags or closed in the wrong order, which a keyword DFA does not see.")):
        defs.append(dict(id=p.id, title=p.title, kind="pda", cls="Context-free", perIP=False, desc=desc,
                         attack="SQL Injection" if p is SQL_PDA else "XSS", **p.definition()))
    defs.append(dict(id="cfg_sql", title="CFG: SQL boolean-injection grammar", kind="cfg", cls="Context-free", perIP=False,
                     desc="A recursive-descent parser for the grammar below. If a quoted fragment in a parameter can be derived from Inj, it is a boolean injection.",
                     attack="SQL Injection", grammar=cfg.GRAMMAR))
    return defs


# ---- request normalisation ------------------------------------------------
def normalize(s):
    for _ in range(3):
        d = unquote_plus(s)
        if d == s:
            break
        s = d
    s = re.sub(r"/\*.*?\*/", " ", s)
    return re.sub(r"\s+", " ", s.lower())[:300]


def param_values(norm):
    _, _, qs = norm.partition("?")
    return [p.partition("=")[2] for p in qs.split("&")] if qs else []


def inspect(target):
    """Run every stateless machine on one request target. Returns a list of findings."""
    norm = normalize(target)
    found = []
    for mid, dfa in SIG_DFAS.items():
        hit = dfa.first_hit(norm)
        if hit:
            i, q = hit
            found.append(dict(machine=mid, kind=SIGNATURES[mid]["kind"], severity=SIGNATURES[mid]["severity"],
                              detail="matched %s at char %d" % (" / ".join(dfa.outputs[q]), i + 1), at=i + 1))
    for pda in (SQL_PDA, HTML_PDA):
        v = pda.run(norm)["verdict"]
        if v:
            found.append(dict(machine=pda.id, kind=v["kind"], severity=v["severity"], detail=v["detail"], at=None))
    for val in param_values(norm):
        if "'" in val:
            r = cfg.parse_injection(val)
            if r["accepted"]:
                found.append(dict(machine="cfg_sql", kind="SQL Injection", severity="high",
                                  detail="parameter parses as Inj: %s" % r["value"][:40], at=None))
                break
    return found


def full_trace(rec):
    """Step-by-step execution of every machine on one stored record (for replay)."""
    norm = normalize(rec["target"])
    out = {}
    for mid, dfa in SIG_DFAS.items():
        steps = [dict(sym=None, state=dfa.start)] + [dict(sym=ch, state=q) for ch, q in dfa.trace(norm)]
        hit = dfa.first_hit(norm)
        out[mid] = dict(kind="dfa", input=norm, steps=steps, fired=hit[0] + 1 if hit else None,
                        detail=" / ".join(dfa.outputs[hit[1]]) if hit else "")
    for pda in (SQL_PDA, HTML_PDA):
        r = pda.run(norm)
        out[pda.id] = dict(kind="pda", input=norm, steps=r["steps"], tokens=r["tokens"],
                           fired=len(r["steps"]) - 1 if r["verdict"] else None,
                           detail=r["verdict"]["detail"] if r["verdict"] else "")
    cfg_res = None
    for val in param_values(norm):
        if "'" in val:
            cfg_res = cfg.parse_injection(val)
            if cfg_res["accepted"]:
                break
    if cfg_res:
        out["cfg_sql"] = dict(kind="cfg", input=norm, result=cfg_res, fired=1 if cfg_res["accepted"] else None,
                              detail=cfg_res["reason"], steps=[dict(sym=None, state=0)])
    for mid, cur in rec.get("ip_steps", {}).items():
        st = rec.get("ip_hist", {}).get(mid) or cur      # whole recent history of this IP, ending at this request
        if cur and st:
            steps = [dict(sym=None, state=st[0]["from"])] + [dict(sym=s["sym"], state=s["to"]) for s in st]
            out[mid] = dict(kind="dfa", input="".join(s["sym"] for s in st), steps=steps,
                            fired=len(steps) - 1 if rec.get("fired_ip", {}).get(mid) else None, detail="per-IP counter")
    return out


# ---- log line parsing -----------------------------------------------------
LINE = re.compile(r"^(\S+) (\S+) (\S+) (\S+) (\d{3}) (\S+)$")


def parse_line(line):
    m = LINE.match(line.strip())
    if not m:
        return None
    iso, ip, method, target, status, result = m.groups()
    try:
        ts = datetime.fromisoformat(iso).timestamp()
    except ValueError:
        ts = time.time()
    return dict(iso=iso, ts=ts, ip=ip, method=method, target=target, status=int(status), result=result,
                raw=line.strip())


class Analyzer:
    def __init__(self, keep=3000):
        self.ips = {}
        self.records = {}
        self.order = deque(maxlen=keep)
        self.next_id = 1

    def reset(self):
        self.ips.clear()
        self.records.clear()
        self.order.clear()

    def _advance(self, ip, key, dfa, syms, now):
        st = self.ips[ip]
        steps = []
        if now - st["last"] > WINDOW and st[key] != dfa.start:
            steps.append(dict(sym="T", **{"from": st[key], "to": dfa.start}))
            st[key] = dfa.start
        for sym in syms:
            nxt = dfa.delta[(st[key], sym)]
            steps.append(dict(sym=sym, **{"from": st[key], "to": nxt}))
            st[key] = nxt
        return steps

    def process(self, rec):
        rec = dict(rec)
        rec["id"] = self.next_id
        self.next_id += 1
        ip = rec["ip"]
        st = self.ips.setdefault(ip, dict(brute=BRUTE.start, scan=SCAN.start, last=rec["ts"], hist=dict(brute=[], scan=[])))
        alerts = [dict(f) for f in inspect(rec["target"])]

        brute_syms = ["F"] if rec["result"] == "LOGIN_FAIL" else ["S"] if rec["result"] == "LOGIN_OK" else []
        scan_syms = ["N"] if rec["status"] == 404 else ["O"]
        rec["ip_steps"], rec["ip_hist"], rec["fired_ip"] = {}, {}, {}
        for key, syms in (("brute", brute_syms), ("scan", scan_syms)):
            dfa = PER_IP[key]["dfa"]
            before = st[key]
            steps = self._advance(ip, key, dfa, syms, rec["ts"])
            rec["ip_steps"][key] = steps
            hist = st["hist"][key]
            hist.extend(steps)
            del hist[:-12]
            rec["ip_hist"][key] = list(hist)
            if st[key] in dfa.accepting and (before not in dfa.accepting or any(s["sym"] == "T" for s in steps)):
                rec["fired_ip"][key] = True
                alerts.append(dict(machine=key, kind=PER_IP[key]["kind"], severity=PER_IP[key]["severity"],
                                   detail="counter reached q%d for %s" % (st[key], ip), at=None))
        st["last"] = rec["ts"]

        rec["alerts"] = alerts
        rec["attack"] = bool(alerts)
        self.records[rec["id"]] = rec
        if len(self.order) == self.order.maxlen:
            self.records.pop(self.order[0], None)
        self.order.append(rec["id"])
        return self.event(rec)

    @staticmethod
    def _latency(rec):
        age = time.time() - rec["ts"]
        return round(age * 1000) if 0 <= age < 5 else None   # replayed old lines have no meaningful latency

    def event(self, rec):
        st = self.ips[rec["ip"]]
        return dict(type="event", id=rec["id"], iso=rec["iso"], ts=rec["ts"], ip=rec["ip"], method=rec["method"],
                    target=rec["target"], status=rec["status"], result=rec["result"], raw=rec["raw"],
                    attack=rec["attack"], alerts=rec["alerts"], blocked=rec["status"] == 403,
                    ip_state=dict(brute=st["brute"], scan=st["scan"]),
                    latency_ms=self._latency(rec))

    def trace(self, rid):
        rec = self.records.get(rid)
        return full_trace(rec) if rec else None
