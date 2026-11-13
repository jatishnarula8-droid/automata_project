"""A small context-free grammar for SQL boolean injection, with a recursive
descent parser that returns the parse tree for display.

    Inj   -> QUOTE RP* Tail
    Tail  -> COMMENT | (OR|AND) Expr [COMMENT]
    Expr  -> Term ((OR|AND) Term)*
    Term  -> LP Expr [RP] | NOT Term | Cmp
    Cmp   -> Val [CMPOP Val]
    Val   -> NUM | STR | IDENT

The LP Expr RP rule is what makes the language context-free (nested parens).
"""
import re

GRAMMAR = [
    "Inj  → QUOTE RP* Tail",
    "Tail → COMMENT | (OR | AND) Expr [COMMENT]",
    "Expr → Term ((OR | AND) Term)*",
    "Term → LP Expr [RP] | NOT Term | Cmp",
    "Cmp  → Val [CMPOP Val]",
    "Val  → NUM | STR | IDENT",
]

_TOK = re.compile(r"\s*(?:(--|#)|('[^']*'?)|(\d+(?:\.\d+)?)|(<=|>=|<>|!=|=|<|>)|(\()|(\))|([a-z_][a-z0-9_]*)|(.))", re.S)
_KEYWORDS = {"or": "OR", "and": "AND", "not": "NOT"}


def tokenize(text):
    toks, pos = [], 0
    while pos < len(text):
        m = _TOK.match(text, pos)
        if not m or m.end() == pos:
            break
        pos = m.end()
        comment, string, num, cmp_, lp, rp, ident, other = m.groups()
        if comment:
            toks.append(("COMMENT", comment))
            break
        if string:
            toks.append(("STR", string))
        elif num:
            toks.append(("NUM", num))
        elif cmp_:
            toks.append(("CMPOP", cmp_))
        elif lp:
            toks.append(("LP", "("))
        elif rp:
            toks.append(("RP", ")"))
        elif ident:
            toks.append((_KEYWORDS.get(ident, "IDENT"), ident))
        elif other and other.strip():
            toks.append(("JUNK", other))
    return toks


class _Fail(Exception):
    pass


class _Parser:
    def __init__(self, toks):
        self.t, self.i = toks, 0

    def kind(self):
        return self.t[self.i][0] if self.i < len(self.t) else None

    def take(self, *kinds):
        if self.kind() in kinds:
            tok = self.t[self.i]
            self.i += 1
            return {"name": tok[0], "text": tok[1], "children": []}
        raise _Fail("expected %s at token %d" % ("/".join(kinds), self.i))

    def inj(self):
        kids = [self.take("QUOTE")]
        while self.kind() == "RP":
            kids.append(self.take("RP"))
        kids.append(self.tail())
        if self.i != len(self.t):
            raise _Fail("trailing tokens")
        return {"name": "Inj", "children": kids}

    def tail(self):
        if self.kind() == "COMMENT":
            return {"name": "Tail", "children": [self.take("COMMENT")]}
        kids = [self.take("OR", "AND"), self.expr()]
        if self.kind() == "COMMENT":
            kids.append(self.take("COMMENT"))
        return {"name": "Tail", "children": kids}

    def expr(self):
        kids = [self.term()]
        while self.kind() in ("OR", "AND"):
            kids += [self.take("OR", "AND"), self.term()]
        return {"name": "Expr", "children": kids}

    def term(self):
        if self.kind() == "LP":
            kids = [self.take("LP"), self.expr()]
            if self.kind() == "RP":
                kids.append(self.take("RP"))
            return {"name": "Term", "children": kids}
        if self.kind() == "NOT":
            return {"name": "Term", "children": [self.take("NOT"), self.term()]}
        return {"name": "Term", "children": [self.cmp()]}

    def cmp(self):
        kids = [self.val()]
        if self.kind() == "CMPOP":
            kids += [self.take("CMPOP"), self.val()]
        return {"name": "Cmp", "children": kids}

    def val(self):
        return {"name": "Val", "children": [self.take("NUM", "STR", "IDENT")]}


def parse_injection(value):
    """value: one decoded, lower-cased parameter value. Returns a result dict."""
    i = value.find("'")
    if i < 0:
        return {"accepted": False, "tokens": [], "tree": None, "reason": "no quote"}
    toks = [("QUOTE", "'")] + tokenize(value[i + 1:])
    shown = [{"name": n, "text": t} for n, t in toks]
    try:
        tree = _Parser(toks).inj()
        return {"accepted": True, "tokens": shown, "tree": tree, "reason": "derivable from Inj", "value": value[i:]}
    except _Fail as e:
        return {"accepted": False, "tokens": shown, "tree": None, "reason": str(e), "value": value[i:]}
