import ipaddress
import re

ALIASES = {
    "ip": "ip.addr", "src": "ip.src", "dst": "ip.dst", "mac": "eth.addr", "port": "port", "len": "frame.len", "layer": "frame.layer",
    "ttl": "ip.ttl", "sport": "srcport", "dport": "dstport", "host": "http.host", "sni": "tls.sni", "flags": "tcp.flags",
}
TOKEN = re.compile(r'\s*(?:(==|!=|>=|<=|&&|\|\||[()<>!])|"([^"]*)"|\'([^\']*)\'|([^\s()=!<>"\']+))')
OPS = {"==", "!=", ">=", "<=", ">", "<", "contains"}


def _tokens(text):
    out, pos = [], 0
    text = text.strip()
    while pos < len(text):
        m = TOKEN.match(text, pos)
        if not m or m.end() == pos:
            raise ValueError("Cannot read the filter near: %s" % text[pos:pos + 12])
        if m.group(1):
            out.append(("op", m.group(1)))
        elif m.group(2) is not None or m.group(3) is not None:
            out.append(("str", m.group(2) if m.group(2) is not None else m.group(3)))
        else:
            w = m.group(4)
            if w.lower() in ("and", "or", "not", "contains"):
                out.append(("op", w.lower()))
            else:
                out.append(("word", w))
        pos = m.end()
    return out


class _Parser:
    def __init__(self, toks):
        self.t = toks
        self.i = 0

    def peek(self):
        return self.t[self.i] if self.i < len(self.t) else (None, None)

    def eat(self):
        tok = self.peek()
        self.i += 1
        return tok

    def parse(self):
        node = self.or_()
        if self.i < len(self.t):
            raise ValueError("Unexpected '%s'" % self.peek()[1])
        return node

    def or_(self):
        left = self.and_()
        while self.peek() in (("op", "or"), ("op", "||")):
            self.eat()
            right = self.and_()
            left = ("or", left, right)
        return left

    def and_(self):
        left = self.not_()
        while self.peek() in (("op", "and"), ("op", "&&")):
            self.eat()
            right = self.not_()
            left = ("and", left, right)
        return left

    def not_(self):
        if self.peek() in (("op", "not"), ("op", "!")):
            self.eat()
            return ("not", self.not_())
        return self.atom()

    def atom(self):
        kind, val = self.eat()
        if kind is None:
            raise ValueError("Filter ended unexpectedly")
        if (kind, val) == ("op", "("):
            node = self.or_()
            if self.eat() != ("op", ")"):
                raise ValueError("Missing closing parenthesis")
            return node
        if kind not in ("word", "str"):
            raise ValueError("Unexpected '%s'" % val)
        field = val
        k2, v2 = self.peek()
        if k2 == "op" and v2 in OPS:
            self.eat()
            k3, v3 = self.eat()
            if k3 not in ("word", "str"):
                raise ValueError("Missing value after %s" % v2)
            return ("cmp", field, v2, v3)
        return ("has", field)


def _vals(flat, field):
    f = field.lower()
    f = ALIASES.get(f, f)
    if f == "port":
        out = []
        for k in ("tcp.port", "udp.port"):
            v = flat.get(k)
            if v:
                out += v
        return out
    if f in ("srcport", "dstport"):
        return [flat[k] for k in ("tcp." + f, "udp." + f) if k in flat]
    v = flat.get(f)
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def _cmp(a, op, b, raw_text):
    sa, sb = str(a), str(b)
    if op == "contains":
        return sb.lower() in sa.lower()
    if "/" in sb and op in ("==", "!="):
        try:
            hit = ipaddress.ip_address(sa) in ipaddress.ip_network(sb, strict=False)
            return hit if op == "==" else not hit
        except ValueError:
            pass
    try:
        na, nb = float(sa), float(sb)
        return {"==": na == nb, "!=": na != nb, ">": na > nb, "<": na < nb, ">=": na >= nb, "<=": na <= nb}[op]
    except ValueError:
        pass
    la, lb = sa.lower(), sb.lower()
    return {"==": la == lb, "!=": la != lb, ">": la > lb, "<": la < lb, ">=": la >= lb, "<=": la <= lb}[op]


def _eval(node, flat, text):
    t = node[0]
    if t == "or":
        return _eval(node[1], flat, text) or _eval(node[2], flat, text)
    if t == "and":
        return _eval(node[1], flat, text) and _eval(node[2], flat, text)
    if t == "not":
        return not _eval(node[1], flat, text)
    if t == "has":
        f = node[1].lower()
        if f == "frame":
            return True
        vals = _vals(flat, f)
        if vals:
            return any(v not in (0, "", None) for v in vals) or f in flat
        return bool(flat.get(f))
    _, field, op, val = node
    if field.lower() == "frame" and op == "contains":
        return val.lower() in text
    vals = _vals(flat, field)
    if not vals:
        return op == "!="
    if op == "!=":
        return all(_cmp(v, "!=", val, text) for v in vals)
    return any(_cmp(v, op, val, text) for v in vals)


def compile_filter(expr):
    expr = (expr or "").strip()
    if not expr:
        return None
    tree = _Parser(_tokens(expr)).parse()

    def run(flat, raw):
        text = raw.decode("latin-1", errors="replace").lower() if raw else ""
        return _eval(tree, flat, text)

    return run
