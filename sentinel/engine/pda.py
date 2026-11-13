"""Deterministic pushdown automata used for attacks a DFA cannot express.

Balanced brackets / matching tags are context-free but not regular (pumping
lemma), so a stack is required.
"""
import re

BOTTOM = "Z"


class PDA:
    def __init__(self, mid, title, tokenize, rule, verdict, states, rules_text):
        self.id, self.title = mid, title
        self.tokenize, self.rule, self.verdict = tokenize, rule, verdict
        self.states, self.rules_text = states, rules_text

    def run(self, text):
        state, stack = "q0", [BOTTOM]
        tokens = self.tokenize(text)
        steps = [{"tok": None, "state": state, "stack": list(stack), "note": "start, stack = [Z]"}]
        for tok in tokens:
            state, action, note = self.rule(state, tok, stack[-1])
            if action:
                if action[0] == "push":
                    stack.append(action[1])
                elif action[0] == "pop" and len(stack) > 1:
                    stack.pop()
            steps.append({"tok": tok, "state": state, "stack": list(stack), "note": note})
        return {"tokens": tokens, "steps": steps, "verdict": self.verdict(state, stack, tokens)}

    def definition(self):
        return {"states": self.states, "rules": self.rules_text}


# ---- PDA 1: nested sub-queries / unbalanced parentheses in SQL ------------
_SQL_TOK = re.compile(r"\(|\)|\bselect\b")


def _sql_tokens(text):
    return ["SEL" if t == "select" else t for t in _SQL_TOK.findall(text)]


def _sql_rule(state, tok, top):
    if state in ("ALARM", "BAD"):
        return state, None, "absorbing"
    if tok == "(":
        sym = "P1" if top == BOTTOM else "P2"
        return state, ("push", sym), "( : push %s" % sym
    if tok == ")":
        if top == BOTTOM:
            return "BAD", None, ") with empty stack: unmatched"
        return state, ("pop",), ") : pop"
    if tok == "SEL":
        if top == "P2":
            return "ALARM", None, "SELECT while 2+ parens deep: nested sub-query"
        return "qS", None, "SELECT seen"
    return state, None, ""


def _sql_verdict(state, stack, tokens):
    if state == "ALARM":
        return {"kind": "SQL Injection", "severity": "high", "detail": "nested sub-query (SELECT inside 2+ levels of parentheses)"}
    if "SEL" in tokens and (state == "BAD" or len(stack) > 1):
        return {"kind": "SQL Injection", "severity": "high",
                "detail": "unbalanced parentheses around SELECT (stack %s)" % ("underflow" if state == "BAD" else "not empty")}
    return None


SQL_PDA = PDA(
    "pda_sql", "PDA: SQL nesting / bracket balance", _sql_tokens, _sql_rule, _sql_verdict,
    ["q0", "qS", "ALARM", "BAD"],
    ["(q, '(', Z)  -> push P1", "(q, '(', P1|P2) -> push P2", "(q, ')', P1|P2) -> pop",
     "(q, ')', Z) -> BAD  (unmatched)", "(q, SELECT, P2) -> ALARM  (nested sub-query)",
     "(q, SELECT, other) -> qS", "end: SELECT seen and stack != [Z] -> flag"])


# ---- PDA 2: matching / nested HTML tags (XSS payload shape) ---------------
_TAG = re.compile(r"<\s*(/?)\s*([a-z][a-z0-9]*)")
_VOID = {"img", "br", "input", "hr", "meta", "link"}


def _html_tokens(text):
    return [("close:" if slash else "open:") + name for slash, name in _TAG.findall(text)]


def _html_rule(state, tok, top):
    if state in ("NESTED", "MISMATCH"):
        return state, None, "absorbing"
    kind, name = tok.split(":")
    if kind == "open":
        if name in _VOID:
            return state, None, "void tag, no push"
        if top == BOTTOM:
            return state, ("push", name), "<%s> : push" % name
        return "NESTED", ("push", name), "<%s> inside <%s>: nested markup" % (name, top)
    if top == name:
        return state, ("pop",), "</%s> matches top : pop" % name
    return "MISMATCH", None, "</%s> does not match top (%s)" % (name, top)


def _html_verdict(state, stack, tokens):
    if state == "NESTED":
        return {"kind": "XSS", "severity": "high", "detail": "nested HTML tags injected into a parameter"}
    if state == "MISMATCH":
        return {"kind": "XSS", "severity": "medium", "detail": "mismatched closing tag in a parameter"}
    return None


HTML_PDA = PDA(
    "pda_html", "PDA: nested / matching HTML tags", _html_tokens, _html_rule, _html_verdict,
    ["q0", "NESTED", "MISMATCH"],
    ["(q0, <t>, Z) -> push t", "(q0, <t>, u) -> NESTED  (tag inside tag)", "(q0, </t>, t) -> pop",
     "(q0, </t>, u != t) -> MISMATCH", "void tags (img, br ...) -> no push"])
