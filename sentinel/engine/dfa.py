"""DFA / NFA primitives, regex -> NFA -> DFA -> minimal DFA, and Aho-Corasick.

Everything here is a plain textbook construction so the dashboard can draw the
exact machine that is being executed.
"""
from collections import deque

OTHER = "other"   # stands for "any character not named in the alphabet"
EPS = "ε"


def _fmt_sym(s):
    return "␣" if s == " " else s


def _fmt_group(syms):
    syms = sorted(syms, key=lambda x: (x == OTHER, x))
    shown = [_fmt_sym(s) for s in syms]
    if len(shown) > 6:
        shown = shown[:5] + ["…+%d" % (len(shown) - 5)]
    return ",".join(shown)


class DFA:
    def __init__(self, states, alphabet, delta, start, accepting, name="", labels=None):
        self.states = list(states)
        self.alphabet = list(alphabet)
        self._alpha = set(self.alphabet)
        self.delta = dict(delta)
        self.start = start
        self.accepting = set(accepting)
        self.name = name
        self.labels = labels or {}
        self.outputs = {}          # state -> patterns that end there (Aho-Corasick)

    def symbol(self, ch):
        if ch in self._alpha:
            return ch
        return OTHER

    def step(self, q, ch):
        return self.delta[(q, self.symbol(ch))]

    def trace(self, text):
        """[(char, state_after)] for every character of text."""
        q = self.start
        out = []
        for ch in text:
            q = self.step(q, ch)
            out.append((ch, q))
        return out

    def accepts(self, text):
        q = self.start
        for ch in text:
            q = self.step(q, ch)
        return q in self.accepting

    def first_hit(self, text):
        """Index of the first character that lands in an accepting state, or None."""
        q = self.start
        for i, ch in enumerate(text):
            q = self.step(q, ch)
            if q in self.accepting:
                return i, q
        return None

    def dead_states(self):
        return {q for q in self.states if q not in self.accepting and
                all(self.delta[(q, a)] == q for a in self.alphabet)}

    def to_dict(self, elide_to=None, hide_dead=False, forward_only=False):
        """forward_only: keep only trie edges (label[t] == label[q] + symbol); Aho-Corasick fallbacks are dropped."""
        dead = self.dead_states() if hide_dead else set()
        groups = {}
        for (q, s), t in self.delta.items():
            if elide_to is not None and t == elide_to:
                continue
            if forward_only and self.labels.get(t) != self.labels.get(q, "") + s:
                continue
            if t in dead or q in dead:
                continue
            groups.setdefault((q, t), []).append(s)
        edges = [{"from": q, "to": t, "label": _fmt_group(syms)} for (q, t), syms in sorted(groups.items())]
        nodes = [{"id": q, "label": self.labels.get(q, str(q)), "accepting": q in self.accepting,
                  "start": q == self.start} for q in self.states if q not in dead]
        return {"nodes": nodes, "edges": edges, "start": self.start,
                "elided": elide_to is not None or forward_only, "dead": bool(dead)}

    def to_table(self, max_symbols=12):
        if len(self.alphabet) > max_symbols:
            return None
        return {"symbols": [_fmt_sym(a) for a in self.alphabet],
                "rows": [{"state": q, "label": self.labels.get(q, str(q)), "accepting": q in self.accepting,
                          "start": q == self.start, "cells": [self.delta[(q, a)] for a in self.alphabet]}
                         for q in self.states]}


# --------------------------------------------------------------------------
# Aho-Corasick = the DFA for  Sigma* (p1 | p2 | ...) Sigma*
# --------------------------------------------------------------------------
def aho_corasick(patterns, name=""):
    alphabet = sorted(set("".join(patterns))) + [OTHER]
    goto, out, text = [{}], [set()], [""]
    for p in patterns:
        q = 0
        for ch in p:
            if ch not in goto[q]:
                goto.append({})
                out.append(set())
                text.append(text[q] + ch)
                goto[q][ch] = len(goto) - 1
            q = goto[q][ch]
        out[q].add(p)
    fail = [0] * len(goto)
    delta = {}
    queue = deque()
    for a in alphabet:
        if a in goto[0]:
            delta[(0, a)] = goto[0][a]
            queue.append(goto[0][a])
        else:
            delta[(0, a)] = 0
    while queue:
        q = queue.popleft()
        out[q] |= out[fail[q]]
        for a in alphabet:
            if a in goto[q]:
                t = goto[q][a]
                fail[t] = delta[(fail[q], a)]
                delta[(q, a)] = t
                queue.append(t)
            else:
                delta[(q, a)] = delta[(fail[q], a)]
    accepting = {q for q in range(len(goto)) if out[q]}
    labels = {q: text[q] for q in range(len(goto))}
    dfa = DFA(range(len(goto)), alphabet, delta, 0, accepting, name, labels)
    dfa.outputs = {q: sorted(out[q]) for q in range(len(goto)) if out[q]}
    return dfa


# --------------------------------------------------------------------------
# Regex -> NFA (Thompson) -> DFA (subset construction) -> minimal DFA (Moore)
# --------------------------------------------------------------------------
class RegexError(ValueError):
    pass


class _Parser:
    def __init__(self, p):
        self.p, self.i = p, 0

    def peek(self):
        return self.p[self.i] if self.i < len(self.p) else None

    def eat(self):
        c = self.p[self.i]
        self.i += 1
        return c

    def alt(self):
        node = self.cat()
        while self.peek() == "|":
            self.eat()
            node = ("alt", node, self.cat())
        return node

    def cat(self):
        node = None
        while self.peek() not in (None, "|", ")"):
            r = self.rep()
            node = r if node is None else ("cat", node, r)
        return node or ("eps",)

    def rep(self):
        node = self.atom()
        while self.peek() in ("*", "+", "?"):
            node = ({"*": "star", "+": "plus", "?": "opt"}[self.eat()], node)
        return node

    def atom(self):
        c = self.eat()
        if c == "(":
            node = self.alt()
            if self.peek() != ")":
                raise RegexError("missing )")
            self.eat()
            return node
        if c == "[":
            return self.cls()
        if c == ".":
            return ("any",)
        if c == "\\":
            if self.peek() is None:
                raise RegexError("dangling \\")
            return ("set", frozenset(self.eat()))
        if c in "*+?":
            raise RegexError("nothing to repeat before " + c)
        return ("set", frozenset(c))

    def cls(self):
        neg = self.peek() == "^"
        if neg:
            self.eat()
        chars = set()
        while True:
            c = self.peek()
            if c is None:
                raise RegexError("missing ]")
            self.eat()
            if c == "]":
                break
            if c == "\\" and self.peek() is not None:
                c = self.eat()
            if self.peek() == "-" and self.i + 1 < len(self.p) and self.p[self.i + 1] != "]":
                self.eat()
                hi = self.eat()
                if ord(hi) < ord(c):
                    raise RegexError("bad range")
                chars.update(chr(x) for x in range(ord(c), ord(hi) + 1))
            else:
                chars.add(c)
        return ("neg" if neg else "set", frozenset(chars))


def _literals(node, acc):
    if node[0] in ("set", "neg"):
        acc.update(node[1])
    else:
        for child in node[1:]:
            if isinstance(child, tuple):
                _literals(child, acc)


class NFA:
    def __init__(self, alphabet):
        self.alphabet = alphabet
        self.n = 0
        self.trans, self.eps = {}, {}
        self.start = self.accept = None

    def new(self):
        self.n += 1
        return self.n - 1

    def add(self, q, sym, r):
        self.trans.setdefault((q, sym), set()).add(r)

    def add_eps(self, q, r):
        self.eps.setdefault(q, set()).add(r)

    def closure(self, qs):
        seen, stack = set(qs), list(qs)
        while stack:
            for r in self.eps.get(stack.pop(), ()):
                if r not in seen:
                    seen.add(r)
                    stack.append(r)
        return seen

    def to_dict(self):
        groups = {}
        for (q, s), rs in self.trans.items():
            for r in rs:
                groups.setdefault((q, r), []).append(s)
        for q, rs in self.eps.items():
            for r in rs:
                groups.setdefault((q, r), []).append(EPS)
        edges = [{"from": q, "to": r, "label": ",".join(
            sorted(_fmt_sym(x) for x in syms)) if len(syms) <= 5 else "%d symbols" % len(syms)}
            for (q, r), syms in sorted(groups.items())]
        nodes = [{"id": q, "label": str(q), "accepting": q == self.accept, "start": q == self.start}
                 for q in range(self.n)]
        return {"nodes": nodes, "edges": edges, "start": self.start, "elided": False, "dead": False}


def _build(nfa, node, alphabet):
    t = node[0]
    s, e = nfa.new(), nfa.new()
    if t == "eps":
        nfa.add_eps(s, e)
    elif t in ("set", "any", "neg"):
        if t == "set":
            syms = node[1]
        elif t == "any":
            syms = alphabet
        else:
            syms = set(alphabet) - node[1]
        for c in syms:
            nfa.add(s, c, e)
    elif t == "cat":
        s1, e1 = _build(nfa, node[1], alphabet)
        s2, e2 = _build(nfa, node[2], alphabet)
        nfa.add_eps(s, s1); nfa.add_eps(e1, s2); nfa.add_eps(e2, e)
    elif t == "alt":
        s1, e1 = _build(nfa, node[1], alphabet)
        s2, e2 = _build(nfa, node[2], alphabet)
        nfa.add_eps(s, s1); nfa.add_eps(s, s2); nfa.add_eps(e1, e); nfa.add_eps(e2, e)
    else:  # star / plus / opt
        s1, e1 = _build(nfa, node[1], alphabet)
        nfa.add_eps(s, s1); nfa.add_eps(e1, e)
        if t in ("star", "opt"):
            nfa.add_eps(s, e)
        if t in ("star", "plus"):
            nfa.add_eps(e1, s1)
    return s, e


def regex_to_nfa(pattern):
    p = _Parser(pattern)
    ast = p.alt()
    if p.i != len(pattern):
        raise RegexError("unexpected " + pattern[p.i])
    lits = set()
    _literals(ast, lits)
    if len(lits) > 40:
        raise RegexError("too many distinct symbols (max 40)")
    alphabet = sorted(lits) + [OTHER]
    nfa = NFA(alphabet)
    nfa.start, nfa.accept = _build(nfa, ast, alphabet)
    return nfa


def nfa_to_dfa(nfa):
    start = frozenset(nfa.closure({nfa.start}))
    ids, order, delta = {start: 0}, [start], {}
    queue = deque([start])
    while queue:
        S = queue.popleft()
        for a in nfa.alphabet:
            T = set()
            for q in S:
                T |= nfa.trans.get((q, a), set())
            T = frozenset(nfa.closure(T))
            if T not in ids:
                ids[T] = len(order)
                order.append(T)
                queue.append(T)
            delta[(ids[S], a)] = ids[T]
    labels = {i: "{" + ",".join(str(x) for x in sorted(S)) + "}" if S else "∅" for i, S in enumerate(order)}
    accepting = {i for i, S in enumerate(order) if nfa.accept in S}
    return DFA(range(len(order)), nfa.alphabet, delta, 0, accepting, "DFA", labels)


def minimize(dfa):
    cls = {q: int(q in dfa.accepting) for q in dfa.states}
    while True:
        ids, new = {}, {}
        for q in dfa.states:
            sig = (cls[q], tuple(cls[dfa.delta[(q, a)]] for a in dfa.alphabet))
            new[q] = ids.setdefault(sig, len(ids))
        stable = len(ids) == len(set(cls.values()))
        cls = new
        if stable:
            break
    # renumber classes in BFS order from the start class
    members = {}
    for q in dfa.states:
        members.setdefault(cls[q], []).append(q)
    order, seen = [], {cls[dfa.start]}
    queue = deque([cls[dfa.start]])
    while queue:
        c = queue.popleft()
        order.append(c)
        rep = members[c][0]
        for a in dfa.alphabet:
            d = cls[dfa.delta[(rep, a)]]
            if d not in seen:
                seen.add(d)
                queue.append(d)
    num = {c: i for i, c in enumerate(order)}
    delta = {}
    for c in order:
        rep = members[c][0]
        for a in dfa.alphabet:
            delta[(num[c], a)] = num[cls[dfa.delta[(rep, a)]]]
    accepting = {num[c] for c in order if members[c][0] in dfa.accepting}
    labels = {num[c]: "{" + ",".join(str(x) for x in members[c]) + "}" for c in order}
    return DFA(range(len(order)), dfa.alphabet, delta, 0, accepting, "Minimal DFA", labels)


def regex_pipeline(pattern, sample=None):
    nfa = regex_to_nfa(pattern)
    dfa = nfa_to_dfa(nfa)
    mini = minimize(dfa)
    result = {
        "alphabet": [_fmt_sym(a) for a in nfa.alphabet],
        "nfa": nfa.to_dict(), "dfa": dfa.to_dict(hide_dead=True), "min": mini.to_dict(hide_dead=True),
        "counts": {"nfa": nfa.n, "dfa": len(dfa.states), "min": len(mini.states)},
        "table": mini.to_table(),
    }
    if sample is not None:
        steps = [{"sym": None, "state": mini.start}]
        for ch, q in mini.trace(sample):
            steps.append({"sym": ch, "state": q})
        result["run"] = {"sample": sample, "steps": steps, "accepted": steps[-1]["state"] in mini.accepting}
    return result
