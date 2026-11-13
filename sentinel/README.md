# Sentinel: automata-based log attack detector

Watches a web server's log in real time, runs every line through finite automata
(DFA), pushdown automata (PDA) and a context-free grammar (CFG), flags attacks, and
draws the machines executing, step by step.

```
victim_site (ShopSecure, :5000)  --writes-->  shared/victim.log  --tail-->  detector (:8000)  --WebSocket-->  dashboard
```

## Run

```
pip install -r requirements.txt
run_all.bat                      # or, in two terminals:
python -m victim_site.app        # intentionally vulnerable shop  http://127.0.0.1:5000
python -m detector.main          # dashboard                      http://127.0.0.1:8000
python -m detector.main --demo   # backup: synthetic traffic, no shop needed
python -m pytest tests -q        # 31 tests
```

`VICTIM_PORT` / `VICTIM_URL` and `--port` change the ports. The shop is deliberately
insecure, so it binds to 127.0.0.1 only. Do not expose it.

## Which machine catches what

| Attack | Language | Machine |
|---|---|---|
| `union select`, `' or `, `../`, `<script` | Regular | DFA (Aho-Corasick) |
| 5 failed logins in a row (per IP) | Regular | counter DFA, symbols F/S/T |
| 5 consecutive 404s (per IP) | Regular | counter DFA, symbols N/O/T |
| `(select (select …))`, unclosed brackets | Context-free | PDA (stack depth) |
| `<div><b>…</b></div>`, mismatched tags | Context-free | PDA (stack of open tags) |
| `' OR (1=1 AND (2=2)) --` | Context-free | CFG + recursive-descent parser |

The **Compare machines** tab runs any payload through all of them. "Nested sub-query"
is missed by every DFA and caught by the PDA, which is the argument for going beyond DFAs.

## Dashboard

* **Live monitor**: log stream (attacks in red), automaton view with animated active state,
  transition table, input strip, play/step/scrub replay of any request, alerts, charts, banned IPs.
* **Regex → DFA lab**: regex → NFA (Thompson) → DFA (subset construction) → minimal DFA (Moore), with a test-string run.
* **Compare machines**, **Theory** (Chomsky hierarchy, why PDAs).
* **Vulnerable / Protected shop** toggle. In protected mode the shop asks the same automata to
  inspect each request before handling it (403 on a hit), and the detector bans attacking IPs for 20 s.
* Export CSV, print report. Attack simulator buttons fire real HTTP requests at the shop.

## Manual attacks to try on http://127.0.0.1:5000

* Login username `admin'--` (any password): logs in as admin in vulnerable mode.
* Search `zzz' union select username,password from users --`: dumps credentials.
* Search `<div><b>hi</b></div>` or `x' and (select (select 1))=1 and 'a'='a`: only PDA/CFG flag these.
* `/files?name=../secret.txt`: path traversal. Five wrong passwords: brute force. Visit five unknown URLs: scan.

## Layout

`engine/` (dfa.py, pda.py, cfg.py, detectors.py) · `detector/` (server, tail, demo) · `victim_site/` · `static/` (dashboard) · `simulate.py` · `tests/`
