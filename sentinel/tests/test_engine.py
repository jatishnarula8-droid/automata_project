import random
import re
import time

import pytest

from engine import cfg
from engine.detectors import Analyzer, inspect, parse_line
from engine.dfa import aho_corasick, minimize, nfa_to_dfa, regex_pipeline, regex_to_nfa
from engine.pda import HTML_PDA, SQL_PDA


def machines(target):
    return {f["machine"] for f in inspect(target)}


# ---- regex pipeline ------------------------------------------------------
@pytest.mark.parametrize("pat", ["a(b|c)*d", "(ab)+|c?", "[a-c]x*", "a.b", "(a|b)*abb", "[^a]b"])
def test_pipeline_matches_python_re(pat):
    nfa = regex_to_nfa(pat)
    dfa = nfa_to_dfa(nfa)
    mini = minimize(dfa)
    assert len(mini.states) <= len(dfa.states)
    rnd = random.Random(1)
    for _ in range(300):
        s = "".join(rnd.choice("abcdx") for _ in range(rnd.randint(0, 7)))
        expect = re.fullmatch(pat, s) is not None
        assert dfa.accepts(s) == expect, (pat, s)
        assert mini.accepts(s) == expect, (pat, s)


def test_minimization_shrinks():
    r = regex_pipeline("(a|b)*abb", "aabb")
    assert r["counts"]["min"] == 5  # 4 live states + the dead state reached on "other"
    assert r["run"]["accepted"]


def test_aho_corasick_substring():
    d = aho_corasick(["union select", "he", "she"])
    assert d.first_hit("xx union select y")
    assert d.first_hit("ushers")
    assert not d.first_hit("union  select")


# ---- detectors: DFA catches, benign passes -------------------------------
@pytest.mark.parametrize("t,m", [
    ("/login?user=admin%27%20or%201%3D1%20--", "sqli_tautology"),
    ("/search?q=%27+UNION+SELECT+username,password+FROM+users--", "sqli_union"),
    ("/search?q=%3Cscript%3Ealert(1)%3C/script%3E", "xss_dfa"),
    ("/files?name=../secret.txt", "traversal_dfa"),
    ("/files?name=%2e%2e%2fsecret.txt", "traversal_dfa"),
    ("/files?name=%252e%252e%252fsecret.txt", "traversal_dfa"),
])
def test_signature_hits(t, m):
    assert m in machines(t)


@pytest.mark.parametrize("t", ["/", "/product/3", "/search?q=blue+shoes", "/search?q=O%27Brien", "/files?name=readme.txt",
                               "/search?q=rock+n+roll+(live)", "/login?user=alice"])
def test_benign_is_clean(t):
    assert inspect(t) == []


# ---- the point of the project: payloads a DFA misses but a PDA/CFG catches
NESTED_SQL = "/search?q=x%27%20and%20(select%20(select%20count(*)%20from%20users))%3E0%20and%20%27a%27%3D%27a"
NESTED_HTML = "/search?q=%3Cdiv%3E%3Cb%3Ehello%3C/b%3E%3C/div%3E"


def test_nested_sql_missed_by_dfa_caught_by_pda():
    m = machines(NESTED_SQL)
    assert "pda_sql" in m
    assert not m & {"sqli_tautology", "sqli_union"}


def test_nested_html_missed_by_dfa_caught_by_pda():
    m = machines(NESTED_HTML)
    assert "pda_html" in m
    assert "xss_dfa" not in m


def test_cfg_catches_quote_comment_and_nested_boolean():
    assert cfg.parse_injection("admin'--")["accepted"]
    assert cfg.parse_injection("' or (1=1) --")["accepted"]
    assert cfg.parse_injection("') or ('a'='a")["accepted"]
    assert cfg.parse_injection("' or ((1=1) and (2=2)) --")["accepted"]
    assert not cfg.parse_injection("o'brien")["accepted"]
    assert not cfg.parse_injection("rock 'n' roll")["accepted"]


def test_pda_balance():
    assert SQL_PDA.run("select (a)")["verdict"] is None
    assert SQL_PDA.run("select ((a)")["verdict"]          # unclosed
    assert SQL_PDA.run("select a)")["verdict"]            # stray )
    assert SQL_PDA.run("(a))")["verdict"] is None         # no SELECT -> not interesting
    assert HTML_PDA.run("<b>x</b>")["verdict"] is None
    assert HTML_PDA.run("<b><i>x</i></b>")["verdict"]
    assert HTML_PDA.run("<b>x</i>")["verdict"]


# ---- per-IP counters -----------------------------------------------------
def line(i, ip="9.9.9.9", target="/login?user=a", status=200, result="-", t=None):
    t = time.time() + i if t is None else t
    iso = time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(t)) + ".000"
    return parse_line("%s %s POST %s %d %s" % (iso, ip, target, status, result))


def test_brute_force_fires_once_on_fifth_failure():
    a = Analyzer()
    fired = []
    t0 = time.time()
    for i in range(7):
        ev = a.process(line(i, result="LOGIN_FAIL", status=401, t=t0 + i))
        fired.append(any(x["machine"] == "brute" for x in ev["alerts"]))
    assert fired == [False, False, False, False, True, False, False]


def test_success_resets_brute_counter():
    a = Analyzer()
    t0 = time.time()
    for i in range(4):
        a.process(line(i, result="LOGIN_FAIL", status=401, t=t0 + i))
    a.process(line(4, result="LOGIN_OK", t=t0 + 4))
    for i in range(5, 9):
        ev = a.process(line(i, result="LOGIN_FAIL", status=401, t=t0 + i))
    assert not ev["attack"]


def test_timeout_resets_counter():
    a = Analyzer()
    t0 = time.time()
    for i in range(4):
        a.process(line(i, result="LOGIN_FAIL", status=401, t=t0 + i))
    ev = a.process(line(0, result="LOGIN_FAIL", status=401, t=t0 + 200))
    assert not ev["attack"] and ev["ip_state"]["brute"] == 1


def test_scan_and_isolation_between_ips():
    a = Analyzer()
    t0 = time.time()
    hits = []
    for i in range(6):
        hits.append(a.process(line(i, ip="1.1.1.1", target="/x%d" % i, status=404, t=t0 + i))["attack"])
        a.process(line(i, ip="2.2.2.2", target="/", status=200, t=t0 + i))
    assert hits == [False] * 4 + [True, False]


def test_trace_available_for_replay():
    a = Analyzer()
    ev = a.process(line(0, target="/search?q=%27+union+select+1", status=200))
    tr = a.trace(ev["id"])
    assert tr["sqli_union"]["fired"] and len(tr["sqli_union"]["steps"]) > 5
    assert "pda_sql" in tr and "scan" in tr


def test_brute_trace_replays_whole_history():
    a = Analyzer()
    t0 = time.time()
    for i in range(5):
        ev = a.process(line(i, result="LOGIN_FAIL", status=401, t=t0 + i))
    tr = a.trace(ev["id"])["brute"]
    assert [s["state"] for s in tr["steps"]] == [0, 1, 2, 3, 4, 5]
    assert tr["input"] == "FFFFF" and tr["fired"] == 5
