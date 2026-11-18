"""Optimizer agent - source-to-source transformations with explicit preconditions.

Every transformation:
  * is purely token-based and conservative: if a precondition cannot be proven it does nothing;
  * is a Candidate (one or more text edits that stand or fall together);
  * is NOT trusted: the Verifier recompiles + relinks the whole project and rechecks safety before it is kept.

Catalogue
  OPT-T01  `<< endl` inside a loop            -> `<< '\\n'`            (no flush per iteration)
  OPT-T02  `s = s + a + b` (std::string, loop) -> `s += a; s += b;`    (no temporary string per step)
  OPT-T03  `i < strlen(s)` in a for-condition -> hoisted `const size_t n = strlen(s)` (O(n^2) -> O(n))
  OPT-T04  heavy by-value parameter           -> `const T&` parameter    (no copy per call)
  OPT-T05  naive recursive Fibonacci          -> iterative loop          (O(phi^n) -> O(n))
  OPT-T06  `for (string x : v)` read-only      -> `for (const string& x : v)`  (no copy per element)
  OPT-T07  push_back in a counted loop         -> `v.reserve(n)` before the loop (no regrowth)
  OPT-T08  `c.size() == 0` / `> 0` on a std container -> `c.empty()` / `!c.empty()`
"""
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

from lexer import tokenize, IDENT, PUNCT, PREPROC, STRING, find_calls, Token

_ASSIGN = {"=", "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", "<<=", ">>="}
_CONTROL = {"if", "for", "while", "switch", "catch", "return", "sizeof", "else", "do", "new", "delete",
            "case", "throw", "co_return", "co_yield", "goto"}
_HEAVY = {"string", "wstring", "vector", "map", "set", "unordered_map", "unordered_set", "list", "deque",
          "multimap", "multiset"}
_MUTATORS = {"push_back", "pop_back", "push_front", "pop_front", "insert", "erase", "clear", "resize", "emplace",
             "emplace_back", "assign", "append", "swap", "reserve", "shrink_to_fit", "sort", "reverse",
             "replace", "remove", "unique", "splice", "merge", "fill", "rehash", "extract"}
_PURE_CALLS = {"strlen", "isalpha", "isdigit", "isalnum", "isspace", "isupper", "islower", "ispunct",
               "tolower", "toupper", "abs", "sqrt", "pow", "min", "max", "printf", "puts", "putchar",
               "strcmp", "strncmp", "fabs", "floor", "ceil"}
_STDIO = {"printf", "puts", "putchar", "fputs", "fprintf", "scanf", "getchar", "fflush", "system", "fwrite",
          "fputc", "putc", "fgets", "gets"}
_INT_TYPES = {"int", "long", "unsigned", "size_t", "uint64_t", "int64_t", "uint32_t", "int32_t", "short"}


@dataclass
class Candidate:
    rule: str
    line: int
    title: str
    why: str
    impact: str
    edits: List[Tuple[int, int, str]]               # (start, end, replacement) char offsets
    file: str = ""
    before: str = ""
    after: str = ""
    caveat: str = ""

    @property
    def span(self) -> Tuple[int, int]:
        return min(e[0] for e in self.edits), max(e[1] for e in self.edits)


# ───────────────────────────── helpers ─────────────────────────────
def _end(t: Token) -> int:
    return t.pos + len(t.text)


def _match(toks: Sequence[Token], i: int, open_: str, close: str) -> int:
    """index of the bracket matching toks[i] (which must be open_), or -1"""
    d = 0
    for j in range(i, len(toks)):
        if toks[j].kind == PUNCT:
            if toks[j].text == open_:
                d += 1
            elif toks[j].text == close:
                d -= 1
                if d == 0:
                    return j
    return -1


def _stmt_start(toks: Sequence[Token], i: int) -> bool:
    """is toks[i] the first token of a statement inside a braced block (not an unbraced body)?"""
    if i == 0:
        return True
    p = toks[i - 1]
    return p.kind == PUNCT and p.text in (";", "{", "}") or p.kind == PREPROC


def _loop_ranges(toks: Sequence[Token]) -> List[Tuple[int, int]]:
    """token index ranges [a,b) covered by for/while/do bodies"""
    out = []
    for i, t in enumerate(toks):
        if t.kind != IDENT or t.text not in ("for", "while", "do"):
            continue
        if t.text == "do":
            if i + 1 < len(toks) and toks[i + 1].text == "{":
                e = _match(toks, i + 1, "{", "}")
                if e > 0:
                    out.append((i + 1, e))
            continue
        if i + 1 >= len(toks) or toks[i + 1].text != "(":
            continue
        close = _match(toks, i + 1, "(", ")")
        if close < 0:
            continue
        if close + 1 < len(toks) and toks[close + 1].text == "{":
            e = _match(toks, close + 1, "{", "}")
            if e > 0:
                out.append((close + 1, e))
        else:
            j = close + 1
            d = 0
            while j < len(toks) and not (d == 0 and toks[j].text == ";"):
                if toks[j].text in ("(", "{", "["):
                    d += 1
                elif toks[j].text in (")", "}", "]"):
                    d -= 1
                j += 1
            out.append((close + 1, j))
    return out


def _in_loop(loops, i: int) -> bool:
    return any(a <= i <= b for a, b in loops)


def _line_indent(source: str, pos: int) -> str:
    start = source.rfind("\n", 0, pos) + 1
    m = re.match(r"[ \t]*", source[start:pos])
    return m.group(0) if m else ""


def _split_top(toks: Sequence[Token], sep: str, angles: bool = True) -> List[List[Token]]:
    out, cur, d = [], [], 0
    for t in toks:
        if t.kind == PUNCT:
            if t.text in "([{":
                d += 1
            elif t.text in ")]}":
                d -= 1
            elif angles and t.text == "<":
                d += 1
            elif angles and t.text == ">":
                d -= 1
            elif angles and t.text == ">>":
                d -= 2
            elif t.text == sep and d == 0:
                out.append(cur)
                cur = []
                continue
        cur.append(t)
    out.append(cur)
    return out


# ───────────────────────────── function discovery ─────────────────────────────
@dataclass
class Fn:
    name: str
    name_idx: int
    open_p: int
    close_p: int
    body_open: int
    body_close: int
    head: List[Token]


def _functions(toks: Sequence[Token]) -> List[Fn]:
    """free functions (file scope or inside namespaces only; never class members or nested)"""
    out: List[Fn] = []
    stack: List[str] = []                      # kinds: "ns" | "fn" | "other"
    for i, t in enumerate(toks):
        if t.kind != PUNCT:
            continue
        if t.text == "{":
            kind = "other"
            if all(k == "ns" for k in stack):
                # statement head: back to previous ; { } or preprocessor
                j = i - 1
                while j >= 0 and toks[j].kind != PREPROC and not (toks[j].kind == PUNCT and toks[j].text in (";", "{", "}")):
                    j -= 1
                head = list(toks[j + 1:i])
                words = {h.text for h in head if h.kind == IDENT}
                if "namespace" in words and ")" not in {h.text for h in head}:
                    kind = "ns"
                elif words & {"class", "struct", "union", "enum"} and "(" not in {h.text for h in head}:
                    kind = "other"
                else:
                    k = len(head) - 1
                    while k >= 0 and head[k].kind == IDENT and head[k].text in ("const", "noexcept", "override", "final"):
                        k -= 1
                    if k >= 0 and head[k].text == ")":
                        op = _match(toks, j + 1 + k, ")", "(") if False else None
                        # find matching '(' walking backwards
                        d, m = 0, j + 1 + k
                        while m >= j + 1:
                            if toks[m].text == ")":
                                d += 1
                            elif toks[m].text == "(":
                                d -= 1
                                if d == 0:
                                    break
                            m -= 1
                        if m > j + 1 and toks[m - 1].kind == IDENT and toks[m - 1].text not in _CONTROL:
                            close_b = _match(toks, i, "{", "}")
                            if close_b > 0:
                                out.append(Fn(toks[m - 1].text, m - 1, m, j + 1 + k, i, close_b,
                                              list(toks[j + 1:m - 1])))
                                kind = "fn"
            stack.append(kind)
        elif t.text == "}":
            if stack:
                stack.pop()
    return out



# ───────────────────── write-safety analysis (shared by T03 / T04) ─────────────────────
_NONCHAR_NUM = {"int", "long", "short", "float", "double", "size_t", "bool", "uint32_t", "int32_t",
                "uint64_t", "int64_t", "uint16_t", "int16_t", "ptrdiff_t"}
_NOT_TYPE = _CONTROL | {"using", "namespace", "typedef", "operator", "template", "typename"}
_READ_INPUT = {"cin", "scanf", "sscanf", "fscanf", "gets", "fgets", "read", "getline", "getchar", "fread"}
_CONST_METHODS = {"size", "length", "empty", "at", "front", "back", "begin", "end", "cbegin", "cend", "c_str",
                  "data", "find", "count", "substr", "compare", "capacity", "max_size", "rbegin", "rend"}
_SAFE_FUNCS = _PURE_CALLS | {"to_string", "stoi", "stol", "stoll", "stod", "stof", "sort", "reverse",
                             "accumulate", "find", "count"}


def _decl_type(toks: Sequence[Token], name: str) -> Optional[str]:
    """type word of the first declaration of `name` (`int a[8]`, `double x = ..`) or None"""
    for i, t in enumerate(toks):
        if t.kind == IDENT and t.text == name and i > 0:
            j = i - 1
            while j >= 0 and toks[j].text in ("*", "&", "const"):
                j -= 1
            nxt = toks[i + 1].text if i + 1 < len(toks) else ""
            if j >= 0 and toks[j].kind == IDENT and toks[j].text not in _NOT_TYPE \
                    and nxt in ("[", "=", ";", ",", ")", "{", "(", ":"):
                return toks[j].text
    return None


def _local_names(toks: Sequence[Token]) -> set:
    out = set()
    for i, t in enumerate(toks):
        if t.kind != IDENT or i == 0:
            continue
        nxt = toks[i + 1].text if i + 1 < len(toks) else ""
        if nxt not in ("[", "=", ";", ",", ")", "{", "(", ":"):
            continue
        j = i - 1
        while j >= 0 and toks[j].text in ("*", "&", "const"):
            j -= 1
        if j >= 0 and ((toks[j].kind == IDENT and toks[j].text not in _NOT_TYPE) or toks[j].text == ">"):
            out.add(t.text)
    return out


def _operand_before(st: Sequence[Token], k: int) -> List[Token]:
    """tokens of the operand that ends right before st[k] (assignment target or postfix ++/--)"""
    j = k - 1
    depth = 0
    while j >= 0:
        tx = st[j].text
        if st[j].kind == PUNCT:
            if tx == ")" and depth == 0:
                break                                    # `if (...) c++;` : the ')' is not part of the operand
            if tx in ")]":
                depth += 1
            elif tx in "([":
                if depth == 0:
                    break
                depth -= 1
            elif depth == 0 and tx in (",", ";", "{", "}", "?", ":", "&&", "||", "=", "<<", ">>", "+", "-", "/",
                                       "%", "==", "!=", "<", ">", "<=", ">=", "return"):
                break
        elif st[j].kind == IDENT and depth == 0 and tx == "return":
            break
        j -= 1
    return list(st[j + 1:k])


def _operand_after(st: Sequence[Token], k: int) -> List[Token]:
    j = k + 1
    out = []
    depth = 0
    while j < len(st):
        t = st[j]
        if t.kind == PUNCT:
            if t.text in "([":
                depth += 1
            elif t.text in ")]":
                if depth == 0:
                    break
                depth -= 1
            elif depth == 0 and t.text not in (".", "->", "::", "*", "&"):
                break
        out.append(t)
        j += 1
    return out


def _target_ok(ops: List[Token], all_toks, locals_: Optional[set]) -> bool:
    """is a write to this operand provably unable to touch a string / container under inspection?"""
    if not ops:
        return False
    texts = [t.text for t in ops]
    if all(t.kind == IDENT or t.text in ("::", "<", ">", ",") for t in ops):      # `x`, `int x`, `std::string x`
        if locals_ is not None and ops[-1].text not in locals_:
            return False
        return True
    if "*" in texts and texts[0] != "*":                                           # declaration of a pointer
        return False
    if ops[0].kind != IDENT:
        return False
    base = ops[0].text
    if len(ops) > 1 and ops[1].text == "[" and ops[-1].text == "]" \
            and not any(t in (".", "->", "*") for t in _depth0(ops)):
        if locals_ is not None and base not in locals_:
            return False
        if locals_ is not None:
            return True
        return _decl_type(all_toks, base) in _NONCHAR_NUM                          # strict aliasing: int store can't hit chars
    if len(ops) > 2 and ops[1].text == "." and locals_ is not None and base in locals_ \
            and not any(t in ("->", "*") for t in _depth0(ops)):
        return True                                                                # member of a local object
    return False


def _depth0(ops: Sequence[Token]) -> List[str]:
    out, d = [], 0
    for t in ops:
        if t.kind == PUNCT and t.text in "([":
            d += 1
        elif t.kind == PUNCT and t.text in ")]":
            d -= 1
        elif d == 0:
            out.append(t.text)
    return out


def _writes_safe(body: Sequence[Token], all_toks: Sequence[Token], locals_: Optional[set] = None) -> bool:
    """every write in `body` targets something that cannot alias the data being protected"""
    names = {t.text for t in body if t.kind == IDENT}
    if names & _READ_INPUT:
        return False
    for i, t in enumerate(body):
        if t.kind == PUNCT and t.text == "[" and i + 1 < len(body) and body[i + 1].text in ("&", "="):
            return False                                                           # lambda captures
        if t.kind != PUNCT or not (t.text in _ASSIGN or t.text in ("++", "--")):
            continue
        if t.text in ("++", "--"):
            prev = body[i - 1] if i else None
            if prev is not None and (prev.kind == IDENT or prev.text == "]"):
                ops = _operand_before(body, i)
                if ops and ops[0].text == "*":                                     # *p++ : the ++ is on p, fine
                    ops = ops[1:]
            else:
                ops = _operand_after(body, i)
            if not ops:
                return False
        else:
            ops = _operand_before(body, i)
        if not _target_ok(ops, all_toks, locals_):
            return False
    return True


# ───────────────────────────── T01: endl ─────────────────────────────
_CRASHY = {"abort", "terminate", "assert", "raise", "kill", "_exit", "quick_exit", "signal", "longjmp",
           "throw", "fork", "system", "popen", "pthread_create", "thread", "async", "__builtin_trap", "sigaction"}


def _t01_endl(source, toks, loops, idents) -> List[Candidate]:
    if idents & _STDIO or idents & _CRASHY:
        return []
    out = []
    for i, t in enumerate(toks):
        if t.kind != IDENT or t.text != "endl" or i == 0:
            continue
        first = i
        if toks[i - 1].text == "::" and i >= 2 and toks[i - 2].text == "std":
            first = i - 2
        if first == 0 or toks[first - 1].text != "<<" or not _in_loop(loops, i):
            continue
        out.append(Candidate("OPT-T01", t.line, "endl flushes the stream on every loop iteration",
                             "std::endl writes '\\n' AND flushes. Inside a loop that forces a system call per line; "
                             "'\\n' gives identical text and lets the stream buffer.",
                             "removes one flush per iteration (often 5-20x faster output-heavy loops)",
                             [(toks[first].pos, _end(t), "'\\n'")],
                             before=source[toks[first].pos:_end(t)], after="'\\n'",
                             caveat="if the program later crashes (e.g. a segmentation fault) the buffered tail of the "
                                    "output is lost; skipped automatically when the file uses abort/throw/assert/"
                                    "threads/stdio"))
    return out


# ───────────────────────────── T02: string append ─────────────────────────────
_BAD_IN_OPERAND = {"+", "-", "<<", ">>", "<", ">", "<=", ">=", "==", "!=", "&", "|", "^", "&&", "||", "?", ":",
                   ",", "=", "+=", "-=", "*=", "/="}


def _string_vars(toks) -> set:
    out = set()
    for i, t in enumerate(toks):
        if t.kind == IDENT and t.text == "string" and i + 1 < len(toks):
            j = i + 1
            while j < len(toks) and toks[j].text in ("&", "const"):
                j += 1
            if j < len(toks) and toks[j].kind == IDENT and j > i and toks[j - 1].text != "&":
                out.add(toks[j].text)               # by value or plain local
            elif j < len(toks) and toks[j].kind == IDENT:
                out.add(toks[j].text)               # reference to a string is still a string
    return out


def _t02_append(source, toks, loops) -> List[Candidate]:
    svars = _string_vars(toks)
    if not svars:
        return []
    out = []
    for i in range(len(toks) - 4):
        a = toks[i]
        if a.kind != IDENT or a.text not in svars or not _in_loop(loops, i) or not _stmt_start(toks, i):
            continue
        if toks[i + 1].text != "=" or toks[i + 2].kind != IDENT or toks[i + 2].text != a.text \
                or toks[i + 3].text != "+":
            continue
        j = i + 4
        d = 0
        while j < len(toks):
            tx = toks[j].text
            if toks[j].kind == PUNCT and tx in "([{":
                d += 1
            elif toks[j].kind == PUNCT and tx in ")]}":
                d -= 1
                if d < 0:
                    break
            elif tx == ";" and d == 0:
                break
            j += 1
        if j >= len(toks) or toks[j].text != ";":
            continue
        rhs = toks[i + 4:j]
        if not rhs or any(t.kind == IDENT and t.text == a.text for t in rhs):
            continue
        operands = _split_top_plus(rhs)
        if operands is None:
            continue
        if len(operands) > 1 and not (_stmt_start(toks, i) and toks[i - 1].text in (";", "{", "}")):
            continue
        ind = _line_indent(source, a.pos)
        parts = []
        for op in operands:
            txt = source[op[0].pos:_end(op[-1])]
            parts.append(f"{a.text} += {txt};")
        line_start = source.rfind("\n", 0, a.pos) + 1
        sep = ("\n" + ind) if not source[line_start:a.pos].strip() else " "
        new = sep.join(parts)
        out.append(Candidate("OPT-T02", a.line, f"`{a.text} = {a.text} + ...` copies the whole string every pass",
                             "s = s + x builds a temporary string holding all of s each time (O(n^2) overall); "
                             "s += x appends in place (amortised O(1)).",
                             "O(n^2) -> O(n) character copies",
                             [(a.pos, _end(toks[j]), new)],
                             before=source[a.pos:_end(toks[j])], after=new))
    return out


def _split_top_plus(rhs: Sequence[Token]) -> Optional[List[List[Token]]]:
    ops, cur, d = [], [], 0
    for t in rhs:
        if t.kind == PUNCT:
            if t.text in "([{":
                d += 1
            elif t.text in ")]}":
                d -= 1
            elif d == 0 and t.text == "+":
                if not cur:
                    return None
                ops.append(cur)
                cur = []
                continue
            elif d == 0 and t.text in _BAD_IN_OPERAND:
                return None
        cur.append(t)
    if not cur:
        return None
    ops.append(cur)
    return ops


# ───────────────────────────── T03: strlen hoist ─────────────────────────────
def _t03_strlen(source, toks, counter) -> List[Candidate]:
    out = []
    for i, t in enumerate(toks):
        if t.kind != IDENT or t.text != "for" or i + 1 >= len(toks) or toks[i + 1].text != "(":
            continue
        if not _stmt_start(toks, i):
            continue
        close = _match(toks, i + 1, "(", ")")
        if close < 0 or close + 1 >= len(toks):
            continue
        header = toks[i + 2:close]
        parts = _split_top(header, ";", angles=False)
        if len(parts) != 3:
            continue
        init, cond, incr = parts
        # locate strlen ( IDENT ) in cond
        k = next((x for x in range(len(cond) - 3) if cond[x].text == "strlen" and cond[x + 1].text == "("
                  and cond[x + 2].kind == IDENT and cond[x + 3].text == ")"), None)
        if k is None:
            continue
        name = cond[k + 2].text
        if any(c.text in ("&&", "||", "?") for c in cond[:k]):
            continue                                            # hoisting would evaluate it eagerly
        if any(x.kind == IDENT and x.text == name for x in init + incr):
            continue
        # body
        if toks[close + 1].text == "{":
            be = _match(toks, close + 1, "{", "}")
            body = toks[close + 2:be] if be > 0 else None
        else:
            body = None
        if body is None:
            continue
        if not _body_leaves_untouched(body, name, toks):
            continue
        counter[0] += 1
        var = f"_gsc_len{counter[0]}"
        # strlen token span inside the header (std:: prefix included)
        s_tok = cond[k]
        e_tok = cond[k + 3]
        start = s_tok.pos
        gi = next((x for x, tk in enumerate(toks) if tk.pos == s_tok.pos), None)
        if gi and gi >= 2 and toks[gi - 1].text == "::" and toks[gi - 2].text == "std":
            start = toks[gi - 2].pos
        ind = _line_indent(source, t.pos)
        ins = f"const size_t {var} = strlen({name});\n{ind}"
        out.append(Candidate("OPT-T03", t.line, f"strlen({name}) is re-evaluated on every iteration",
                             f"strlen walks the whole string each call, so the loop is O(n^2). {name} is not "
                             "modified in the loop body, so the length can be computed once.",
                             "O(n^2) -> O(n)",
                             [(t.pos, t.pos, ins), (start, _end(e_tok), var)],
                             before=source[start:_end(e_tok)], after=var,
                             caveat="assumes nothing in the body changes the contents of the string through "
                                    "another pointer or a global"))
    return out


def _body_leaves_untouched(body: Sequence[Token], name: str, all_toks: Sequence[Token] = ()) -> bool:
    n = len(body)
    if not _writes_safe(body, all_toks):
        return False
    calls = list(find_calls(body))
    call_spans = [(c.start, c.end, c.name) for c in calls]
    for c in calls:
        prev = body[c.start - 1].text if c.start > 0 else ""
        if prev in (".", "->"):
            recv = body[c.start - 2].text if c.start >= 2 else ""
            if recv == name:
                return False
            continue
        if c.name not in _PURE_CALLS and c.name not in ("cout", "cin"):
            if c.name[0].isupper() or c.name in _CONTROL:
                continue
            return False
    for i, t in enumerate(body):
        if t.kind != IDENT or t.text != name:
            continue
        nxt = body[i + 1].text if i + 1 < n else ""
        prv = body[i - 1].text if i > 0 else ""
        if prv in ("++", "--", "&") or nxt in ("++", "--") or nxt in _ASSIGN:
            return False
        if nxt == "[":
            e = _match(body, i + 1, "[", "]")
            if e < 0 or (e + 1 < n and (body[e + 1].text in _ASSIGN or body[e + 1].text in ("++", "--"))):
                return False
            continue
        if nxt in (".", "->"):
            return False
        inside_pure = any(a < i < b and nm in _PURE_CALLS for a, b, nm in call_spans)
        if not (inside_pure or prv == "<<"):
            return False
    return True


# ───────────────────────────── T04: const-ref params ─────────────────────────────
def _param_info(ptoks: List[Token]):
    """-> (type_first_tok, type_last_tok, name_tok, is_const) for `[const] [std::]Heavy[<..>] name [= ..]` else None"""
    toks = ptoks
    if any(t.text in ("&", "&&", "*", "...", "[") for t in toks):
        return None
    eq = next((i for i, t in enumerate(toks) if t.text == "="), len(toks))
    core = toks[:eq]
    i = 0
    is_const = False
    if i < len(core) and core[i].text == "const":
        is_const = True
        i += 1
    first = core[i] if i < len(core) else None
    if first is None:
        return None
    if core[i].text == "std" and i + 2 < len(core) and core[i + 1].text == "::":
        i += 2
    if i >= len(core) or core[i].kind != IDENT or core[i].text not in _HEAVY:
        return None
    i += 1
    if i < len(core) and core[i].text == "<":
        d = 0
        while i < len(core):
            if core[i].text == "<":
                d += 1
            elif core[i].text == ">":
                d -= 1
            elif core[i].text == ">>":
                d -= 2
            i += 1
            if d <= 0:
                break
        if d != 0:
            return None
    if i != len(core) - 1 or core[i].kind != IDENT:
        return None
    name = core[i]
    type_last = core[i - 1]
    return (ptoks[0], type_last, name, is_const)


def _body_modifies(body: Sequence[Token], name: str) -> bool:
    n = len(body)
    for i, t in enumerate(body):
        if t.kind != IDENT or t.text != name:
            continue
        nxt = body[i + 1].text if i + 1 < n else ""
        prv = body[i - 1].text if i > 0 else ""
        if nxt in _ASSIGN or nxt in ("++", "--") or prv in ("++", "--", "&", ">>") or prv == "swap":
            return True
        if prv == "(" and i >= 2 and body[i - 2].text in ("move", "swap"):
            return True
        if nxt == "[":
            e = _match(body, i + 1, "[", "]")
            if e < 0 or (e + 1 < n and (body[e + 1].text in _ASSIGN or body[e + 1].text in ("++", "--"))):
                return True
        if nxt in (".", "->") and i + 2 < n and body[i + 2].text in _MUTATORS:
            return True
        if nxt == "," and i >= 2 and body[i - 1].text == "(" and body[i - 2].text in ("swap", "getline"):
            return True
    return False


def _t04_constref(source, toks, fns, other_files_names: set) -> List[Candidate]:
    out = []
    for f in fns:
        if f.name in ("main",) or f.name in other_files_names:
            continue
        head_words = {h.text for h in f.head}
        if head_words & {"template", "virtual", "friend", "operator", "constexpr", "inline"} and "inline" not in head_words:
            continue
        if head_words & {"template", "virtual", "friend", "operator"} or any(h.text in ("&", "*", "~") for h in f.head) \
                or (f.name_idx > 0 and toks[f.name_idx - 1].text == "::"):
            continue
        # a prototype in this file would also have to change
        if _declared_elsewhere(toks, f):
            continue
        params = _split_top(toks[f.open_p + 1:f.close_p], ",")
        if not params or params == [[]]:
            continue
        # aliasing guard: another param that is a non-const reference/pointer
        risky = any(any(t.text in ("&", "*") for t in p) and not (p and p[0].text == "const") for p in params)
        if risky:
            continue
        body = toks[f.body_open + 1:f.body_close]
        locals_ = _local_names(list(toks[f.open_p:f.close_p + 1]) + list(body))
        if not _function_is_local_only(body, locals_, f.name, toks):
            continue
        for p in params:
            info = _param_info(p)
            if not info:
                continue
            first, tlast, name, is_const = info
            if _body_modifies(body, name.text):
                continue
            ty_txt = source[first.pos:_end(tlast)]
            if is_const:
                new = ty_txt + "& "
            else:
                new = "const " + ty_txt + "& "
            out.append(Candidate("OPT-T04", name.line,
                                 f"parameter '{name.text}' of {f.name}() is copied on every call",
                                 f"{ty_txt} is a heap-backed container; passing it by value copies all elements "
                                 f"per call. {f.name}() never modifies '{name.text}', so a const reference is "
                                 "semantically identical and free.",
                                 "removes an O(n) copy (and allocation) per call",
                                 [(first.pos, name.pos, new)],
                                 before=source[first.pos:_end(name)], after=new + name.text,
                                 caveat="signature changes: every declaration/definition must match (checked by "
                                        "the whole-project link)"))
    return out


def _function_is_local_only(body, locals_: set, own_name: str, all_toks) -> bool:
    """T04 precondition: the body cannot modify anything the caller's argument might alias
    (no writes to non-local state, no calls that could, no lambdas / input reads)."""
    if not _writes_safe(body, all_toks, locals_):
        return False
    for c in find_calls(body):
        prev = body[c.start - 1].text if c.start > 0 else ""
        if prev in (".", "->"):
            recv = body[c.start - 2].text if c.start >= 2 else ""
            if recv in locals_ or c.name in _CONST_METHODS:
                continue
            return False
        if c.name in _CONTROL or c.name == own_name or c.name in _SAFE_FUNCS or c.name in _HEAVY \
                or c.name[:1].isupper():
            continue
        return False
    for t in body:
        if t.kind == IDENT and t.text in ("throw", "new", "delete", "static"):
            return False
    return True


def _declared_elsewhere(toks, f: Fn) -> bool:
    for i, t in enumerate(toks):
        if t.kind == IDENT and t.text == f.name and i != f.name_idx and i + 1 < len(toks) and toks[i + 1].text == "(":
            prev = toks[i - 1] if i else None
            if prev and prev.kind == IDENT and prev.text not in _CONTROL:
                return True                                     # looks like `Type name(...)`
    return False


# ───────────────────────────── T05: fibonacci ─────────────────────────────
def _t05_fib(source, toks, fns) -> List[Candidate]:
    out = []
    for f in fns:
        params = _split_top(toks[f.open_p + 1:f.close_p], ",")
        if len(params) != 1 or len(params[0]) < 2 or any(h.text in ("&", "*", "template") for h in f.head):
            continue
        p = params[0]
        if p[-1].kind != IDENT or any(x.text in ("&", "*", "const") for x in p):
            continue
        n = p[-1].text
        ptype = " ".join(x.text for x in p[:-1])
        rtype = " ".join(h.text for h in f.head if h.text not in ("static", "inline"))
        words = [w for w in ptype.split() if w not in ("std", "::", "long", "unsigned", "signed", "short")]
        if ptype != rtype or (words and any(w not in _INT_TYPES for w in words)) or \
                (not words and not any(w in ptype.split() for w in ("long", "unsigned", "short"))):
            continue
        body = [t.text for t in toks[f.body_open + 1:f.body_close] if t.text not in ("{", "}")]
        s = " ".join(body)
        fn = f.name
        cond = rf"if \( {n} (?:<= 1|< 2) \) return {n} ;"
        a = rf"{fn} \( {n} - 1 \)"
        b = rf"{fn} \( {n} - 2 \)"
        if not re.fullmatch(rf"{cond} return (?:{a} \+ {b}|{b} \+ {a}) ;", s):
            continue
        ind = _line_indent(source, toks[f.body_open].pos)
        i2 = ind + "    "
        new = (f"\n{i2}if ({n} <= 1) return {n};\n"
               f"{i2}{rtype} _gsc_a = 0, _gsc_b = 1;\n"
               f"{i2}for ({rtype} _gsc_i = 2; _gsc_i <= {n}; ++_gsc_i) {{\n"
               f"{i2}    {rtype} _gsc_t = _gsc_a + _gsc_b;\n"
               f"{i2}    _gsc_a = _gsc_b;\n"
               f"{i2}    _gsc_b = _gsc_t;\n"
               f"{i2}}}\n"
               f"{i2}return _gsc_b;\n{ind}")
        out.append(Candidate("OPT-T05", toks[f.name_idx].line, f"{fn}() is exponential-time naive recursion",
                             f"{fn}(n) recomputes the same sub-problems ~phi^n times. The loop computes the same "
                             "sequence (same results, same wrap-around for unsigned) in n steps.",
                             "O(1.6^n) -> O(n), recursion depth n -> 1",
                             [(toks[f.body_open].pos + 1, toks[f.body_close].pos, new)],
                             before=f"return {fn}({n}-1) + {fn}({n}-2);", after="iterative loop"))
    return out



# ───────────────────────────── T06: range-for by value ─────────────────────────────
def _container_elem_heavy(toks, cname: str) -> Optional[bool]:
    """True/False = element type of `vector<...> cname` / `T cname` is (not) a heavy type; None = unknown"""
    for i, t in enumerate(toks):
        if t.kind == IDENT and t.text == cname and i > 0:
            j = i - 1
            while j >= 0 and toks[j].text in ("&", "const"):
                j -= 1
            if j >= 0 and toks[j].text in (">", ">>"):
                d, k = 0, j
                while k >= 0:
                    d += 1 if toks[k].text == ">" else 2 if toks[k].text == ">>" else -1 if toks[k].text == "<" else 0
                    if d <= 0:
                        break
                    k -= 1
                args = toks[k + 1:j]
                if any(a.text == "bool" for a in args):
                    return None
                return any(a.kind == IDENT and a.text in _HEAVY for a in args)
    return None


def _t06_rangefor(source, toks, fns) -> List[Candidate]:
    out = []
    for i, t in enumerate(toks):
        if t.kind != IDENT or t.text != "for" or i + 1 >= len(toks) or toks[i + 1].text != "(":
            continue
        close = _match(toks, i + 1, "(", ")")
        if close < 0 or close + 1 >= len(toks) or toks[close + 1].text != "{":
            continue
        hdr = toks[i + 2:close]
        colon = next((k for k, x in enumerate(hdr) if x.text == ":"), None)
        if colon is None or colon < 2 or any(x.text in ("&", "*", "&&", ";", "[") for x in hdr[:colon]):
            continue
        decl, cont = hdr[:colon], hdr[colon + 1:]
        if len(cont) != 1 or cont[0].kind != IDENT or decl[-1].kind != IDENT:
            continue
        name, cname = decl[-1].text, cont[0].text
        typ = decl[:-1]
        is_const = typ and typ[0].text == "const"
        core = typ[1:] if is_const else typ
        if not core:
            continue
        if core[0].text == "auto" and len(core) == 1:
            heavy = _container_elem_heavy(toks, cname)
            ty_txt = "auto"
        else:
            tmp = _param_info(list(core) + [decl[-1]])
            heavy = tmp is not None
            ty_txt = source[core[0].pos:_end(core[-1])]
        if not heavy:
            continue
        be = _match(toks, close + 1, "{", "}")
        body = toks[close + 2:be] if be > 0 else None
        fn = next((f for f in fns if f.body_open < i < f.body_close), None)
        if body is None or fn is None or _body_modifies(body, name):
            continue
        locals_ = _local_names(list(toks[fn.open_p:fn.close_p + 1]) + list(toks[fn.body_open + 1:fn.body_close]))
        if cname not in locals_ or not _function_is_local_only(body, locals_, "", toks):
            continue
        if _body_modifies(body, cname) or any(x.kind == IDENT and x.text == cname and k > 0
                                              and body[k - 1].text in ("(", ",") for k, x in enumerate(body)):
            continue
        out.append(Candidate("OPT-T06", t.line, f"range-for copies each element into '{name}'",
                             f"`for ({ty_txt} {name} : {cname})` makes a full copy of every element (a heap allocation "
                             f"per string / vector). The loop never modifies '{name}' or '{cname}', so a const reference "
                             "is identical and free.",
                             "removes one copy (and allocation) per element",
                             [(typ[0].pos, decl[-1].pos, f"const {ty_txt}& ")],
                             before=source[typ[0].pos:_end(decl[-1])], after=f"const {ty_txt}& {name}",
                             caveat="assumes nothing else changes the container's elements while the loop runs"))
    return out


# ───────────────────────────── T07: vector reserve ─────────────────────────────
def _is_vector_decl(toks, name: str) -> bool:
    """`vector<...> name` declared (by value, not a reference/pointer) among toks"""
    for i, t in enumerate(toks):
        if t.kind == IDENT and t.text == name and i > 0 and toks[i - 1].text in (">", ">>"):
            d, k = 0, i - 1
            while k >= 0:
                d += 1 if toks[k].text == ">" else 2 if toks[k].text == ">>" else -1 if toks[k].text == "<" else 0
                if d <= 0:
                    break
                k -= 1
            nxt = toks[i + 1].text if i + 1 < len(toks) else ""
            if k >= 1 and toks[k - 1].text == "vector" and nxt in (";", "=", "(", "{", ","):
                return True
    return False


def _t07_reserve(source, toks) -> List[Candidate]:
    out = []
    for i, t in enumerate(toks):
        if t.kind != IDENT or t.text != "for" or i + 1 >= len(toks) or toks[i + 1].text != "(" or not _stmt_start(toks, i):
            continue
        close = _match(toks, i + 1, "(", ")")
        if close < 0 or close + 1 >= len(toks) or toks[close + 1].text != "{":
            continue
        parts = _split_top(toks[i + 2:close], ";", angles=False)
        if len(parts) != 3:
            continue
        init, cond, incr = parts
        it = init[-3:] if len(init) >= 3 else []
        if len(it) != 3 or it[0].kind != IDENT or it[1].text != "=" or it[2].text != "0" or len(init) < 4:
            continue
        iv = it[0].text
        if len(cond) < 3 or cond[0].text != iv or cond[1].text != "<":
            continue
        bound = cond[2:]
        inc = [x.text for x in incr]
        if inc not in (["++", iv], [iv, "++"], [iv, "+=", "1"]):
            continue
        if len(bound) == 1 and bound[0].kind == "NUMBER" if False else (len(bound) == 1 and bound[0].text.isdigit() and int(bound[0].text) > 0):
            ntxt, guard = bound[0].text, ""
        elif len(bound) == 1 and bound[0].kind == IDENT:
            ntxt, guard = bound[0].text, f"if ({bound[0].text} > 0) "
        elif len(bound) == 5 and bound[0].kind == IDENT and [x.text for x in bound[1:]] == [".", "size", "(", ")"] \
                or (len(bound) == 5 and [x.text for x in bound[1:]] == [".", "size", "(", ")"]):
            ntxt, guard = "".join(x.text for x in bound), ""
        else:
            continue
        be = _match(toks, close + 1, "{", "}")
        if be < 0:
            continue
        body = toks[close + 2:be]
        pushes = [k for k, x in enumerate(body) if x.kind == IDENT and x.text in ("push_back", "emplace_back")
                  and k >= 2 and body[k - 1].text == "." and body[k - 2].kind == IDENT
                  and k + 1 < len(body) and body[k + 1].text == "("]
        if len(pushes) != 1:
            continue
        k = pushes[0]
        v = body[k - 2].text
        depth = sum(1 if x.text == "{" else -1 if x.text == "}" else 0 for x in body[:k])
        prev = body[k - 3].text if k >= 3 else ";"
        if depth != 0 or prev not in (";", "{", "}") and k - 3 >= 0:
            continue
        # the vector must be declared before the loop, never reserved/cleared/reassigned, bound not modified
        if not _is_vector_decl(toks[:i], v) or any(x.kind == IDENT and x.text in ("reserve", "clear", "shrink_to_fit") for x in toks):
            continue
        if any(x.kind == IDENT and x.text == v and k2 + 1 < len(body) and body[k2 + 1].text in _ASSIGN
               for k2, x in enumerate(body)):
            continue
        if len(bound) == 1 and bound[0].kind == IDENT and _body_modifies(body, bound[0].text):
            continue
        if any(x.kind == IDENT and x.text == iv and k2 + 1 < len(body) and (body[k2 + 1].text in _ASSIGN or body[k2 + 1].text in ("++", "--"))
               for k2, x in enumerate(body)):
            continue                                              # loop variable changed inside the body
        ind = _line_indent(source, t.pos)
        ins = f"{guard}{v}.reserve({ntxt});\n{ind}"
        out.append(Candidate("OPT-T07", t.line, f"'{v}' grows by push_back without reserve()",
                             f"The loop appends one element per iteration to '{v}'; without reserve() the vector "
                             "reallocates and moves all elements about log2(n) times. Reserving the known count "
                             "once avoids that.",
                             "removes ~log2(n) reallocations and element moves",
                             [(t.pos, t.pos, ins)], before="(nothing)", after=f"{guard}{v}.reserve({ntxt});",
                             caveat="capacity() becomes larger earlier; behaviour of the program is otherwise identical"))
    return out


# ───────────────────────────── T08: size() == 0  ->  empty() ─────────────────────────────
_EMPTY_TYPES = {"vector", "string", "map", "set", "multimap", "multiset", "unordered_map", "unordered_set", "unordered_multimap",
                "unordered_multiset", "deque", "list", "basic_string", "wstring", "u16string", "u32string"}
_PRE_OK = {"(", "&&", "||", "!", ",", ";", "{", "}", "return", "?", ":", "="}
_POST_OK = {")", "&&", "||", ";", ",", "?", ":"}


def _std_container_vars(toks) -> dict:
    """name -> number of declarations, for names declared with a std container type (`std::vector<T> v`, `std::string s`)."""
    found: dict = {}
    for i, t in enumerate(toks):
        if t.kind != IDENT or i < 3 or i + 1 >= len(toks) or toks[i + 1].text not in ("(", ";", ",", "=", "{", ")", "["):
            continue
        j = i - 1
        while j >= 0 and toks[j].text in ("&", "*", "const"):
            j -= 1
        if j < 0:
            continue
        ti = j
        if toks[j].text == ">":                                   # template: walk back to the matching '<'; the type word precedes it
            depth, k = 0, j
            while k >= 0:
                depth += 1 if toks[k].text == ">" else -1 if toks[k].text == "<" else 0
                if depth == 0:
                    break
                k -= 1
            ti = k - 1
        if ti >= 2 and toks[ti].text in _EMPTY_TYPES and toks[ti - 1].text == "::" and toks[ti - 2].text == "std":
            found[t.text] = found.get(t.text, 0) + 1
    return found


def _t08_empty(source, toks) -> List[Candidate]:
    decls = _std_container_vars(toks)
    out = []
    for i, t in enumerate(toks):
        if t.kind != IDENT or decls.get(t.text) != 1:
            continue
        if i + 6 >= len(toks) or [x.text for x in toks[i + 1:i + 5]] != [".", "size", "(", ")"]:
            continue
        if i > 0 and toks[i - 1].text in (".", "->", "::"):
            continue
        op, zero = toks[i + 5].text, toks[i + 6].text
        if zero != "0" or op not in ("==", "!=", ">"):
            continue
        prev = toks[i - 1].text if i > 0 else ";"
        nxt = toks[i + 7].text if i + 7 < len(toks) else ";"
        if prev not in _PRE_OK or nxt not in _POST_OK:
            continue
        neg = "" if op == "==" else "!"
        txt = f"{neg}{t.text}.empty()"
        out.append(Candidate("OPT-T08", t.line, f"'{t.text}.size() {op} 0' can be '{txt}'",
                             "empty() is guaranteed O(1) for every standard container; size() may be O(n) (std::list before C++11) and says "
                             "more than the code means.", "O(1) emptiness test, clearer intent",
                             [(t.pos, _end(toks[i + 6]), txt)], before=f"{t.text}.size() {op} 0", after=txt,
                             caveat="identical result for std containers"))
    return out


# ───────────────────────────── driver ─────────────────────────────
def propose(source: str, path: str = "<source>", other_names: Optional[set] = None) -> List[Candidate]:
    toks = tokenize(source)
    loops = _loop_ranges(toks)
    idents = {t.text for t in toks if t.kind == IDENT}
    fns = _functions(toks)
    counter = [0]
    cands: List[Candidate] = []
    cands += _t01_endl(source, toks, loops, idents)
    cands += _t02_append(source, toks, loops)
    cands += _t03_strlen(source, toks, counter)
    cands += _t04_constref(source, toks, fns, other_names or set())
    cands += _t05_fib(source, toks, fns)
    cands += _t06_rangefor(source, toks, fns)
    cands += _t07_reserve(source, toks)
    cands += _t08_empty(source, toks)
    cands.sort(key=lambda c: c.span)
    chosen: List[Candidate] = []
    last_end = -1
    for c in cands:
        a, b = c.span
        if a >= last_end:
            chosen.append(c)
            last_end = b
        # overlapping candidates are dropped (they would be proposed again on a later pass)
    for c in chosen:
        c.file = path
    return chosen


def apply(source: str, cands: Sequence[Candidate]) -> str:
    edits = sorted((e for c in cands for e in c.edits), key=lambda e: (e[0], e[1]), reverse=True)
    out = source
    for a, b, txt in edits:
        out = out[:a] + txt + out[b:]
    return out
