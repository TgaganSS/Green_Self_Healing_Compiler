"""pyanalyzer.py - Python analyst: syntax errors + verified syntax healing + AST-level quality/security checks."""
from __future__ import annotations

import ast
import re
import sys
from typing import Dict, List, Optional, Tuple

from .core import Edit, Finding, Fix, TIER_AUTO, TIER_NONE, TIER_PROPOSED, apply_edits, pysrc

_STDLIB = getattr(sys, "stdlib_module_names", frozenset())


# ─────────────────────────────────────────────────────────────────────────────
# syntax
# ─────────────────────────────────────────────────────────────────────────────
def syntax_error(text: str, name: str = "<src>") -> Optional[SyntaxError]:
    try:
        compile(pysrc(text), name, "exec", dont_inherit=True)
        return None
    except SyntaxError as e:                 # includes IndentationError / TabError
        return e
    except (ValueError, RecursionError, MemoryError) as e:         # null bytes, absurd nesting
        se = SyntaxError(str(e))
        se.lineno, se.offset = 1, 0
        return se


def _err_line(e: SyntaxError) -> int:
    return e.lineno or 1


_EXPLAIN = {
    "expected ':'": "A block header (if/for/while/def/class/else/try/with) must end with a colon.",
    "was never closed": "An opening bracket has no matching closing bracket; Python reports the line where it was opened.",
    "unterminated string": "A string literal is missing its closing quote.",
    "indent": "Indentation is inconsistent: Python uses it to define blocks.",
    "Missing parentheses": "Python 3 made print a function; Python 2 style 'print x' is a syntax error.",
    "forgot a comma": "Two items in a list/tuple/dict/call are not separated by a comma.",
    "'=' alone": "'=' assigns; use '==' to compare.",
    "invalid syntax": "The parser could not make sense of this statement.",
}


def syntax_finding(e: SyntaxError, rel: str, lines: List[str]) -> Finding:
    msg = e.msg or "invalid syntax"
    why = next((v for k, v in _EXPLAIN.items() if k in msg), "The file cannot be compiled, so nothing in it can run.")
    ln = _err_line(e)
    return Finding(file=rel, line=ln, column=e.offset or 0, language="python", category="error", rule_id="PY-SYNTAX",
                   title=f"Syntax error: {msg}", severity="High", confidence=1.0, agent="python",
                   message=why, recommendation="Fix the statement shown; the self-healing pass attempts the common cases.",
                   snippet=(lines[ln - 1].strip()[:160] if 0 < ln <= len(lines) else ""))


def _strip_comment(line: str) -> Tuple[str, str]:
    """Split a line into (code, trailing comment) without breaking '#' inside strings."""
    q = None
    for i, ch in enumerate(line):
        if q:
            if ch == "\\":
                continue
            if ch == q:
                q = None
        elif ch in "\"'":
            q = ch
        elif ch == "#":
            return line[:i].rstrip(), line[i:]
    return line.rstrip(), ""


def _candidates(text: str, e: SyntaxError) -> List[Tuple[str, str]]:
    """Candidate repaired texts for one syntax error, each with a description (verified by the caller)."""
    lines = text.split("\n")
    ln = _err_line(e)
    idx = ln - 1
    msg = e.msg or ""
    out: List[Tuple[str, str]] = []
    if not (0 <= idx < len(lines)):
        return out

    def with_line(i, new):
        ls = list(lines)
        ls[i] = new
        return "\n".join(ls)

    code, comment = _strip_comment(lines[idx])
    tail = (" " + comment) if comment else ""
    if "expected ':'" in msg:
        out.append((with_line(idx, code + ":" + tail), "added the missing ':'"))
    if "Missing parentheses in call to 'print'" in msg:
        m = re.match(r"^(\s*)print\s+(.*\S)\s*$", code)
        if m:
            arg = m.group(2).rstrip(",")
            out.append((with_line(idx, f"{m.group(1)}print({arg}){tail}"), "print statement -> print() call"))
    if "Maybe you meant '=='" in msg or "cannot assign to" in msg or "'=' alone" in msg:
        m = re.match(r"^(\s*(?:if|elif|while)\s+)(.*?)(\s*:\s*)$", code)
        if m and "==" not in m.group(2):
            out.append((with_line(idx, m.group(1) + re.sub(r"(?<![=!<>:])=(?!=)", "==", m.group(2), count=1) + m.group(3) + tail),
                        "'=' -> '==' in a condition"))
    if "forgot a comma" in msg:
        end_ln = getattr(e, "end_lineno", None) or ln
        for li in range(idx, min(end_ln - 1, len(lines))):         # comma missing at a line break
            c3, cm3 = _strip_comment(lines[li])
            if c3.strip() and not c3.rstrip().endswith(","):
                out.append((with_line(li, c3 + "," + ((" " + cm3) if cm3 else "")), "inserted a missing comma"))
        for li in range(idx, min(end_ln, len(lines))):
            seg = lines[li]
            for mm in re.finditer(r"(?<=[\w\)\]\}\"'])\s+(?=[\w\(\[\{\"'])", seg):
                out.append((with_line(li, seg[:mm.start()] + "," + seg[mm.start():]), "inserted a missing comma"))
    if "was never closed" in msg or "unexpected EOF" in msg or "'(' was never" in msg:
        opener = re.search(r"'([\(\[\{])'", msg)
        closer = {"(": ")", "[": "]", "{": "}"}.get(opener.group(1) if opener else "(")
        for li in range(idx, min(idx + 8, len(lines))):
            c2, cm2 = _strip_comment(lines[li])
            out.append((with_line(li, c2 + closer + ((" " + cm2) if cm2 else "")), f"closed the '{opener.group(1) if opener else '('}'"))
    if "unmatched" in msg:
        m = re.search(r"unmatched '(.)'", msg)
        if m:
            col = (e.offset or 1) - 1
            ln_s = lines[idx]
            if 0 <= col < len(ln_s) and ln_s[col] == m.group(1):
                out.append((with_line(idx, ln_s[:col] + ln_s[col + 1:]), f"removed the stray '{m.group(1)}'"))
    if "unterminated string literal" in msg:
        col = (e.offset or 1) - 1
        quote = lines[idx][col] if 0 <= col < len(lines[idx]) else '"'
        out.append((with_line(idx, code + quote + tail), "closed the string literal"))
    if isinstance(e, IndentationError) or "indent" in msg:
        if "expected an indented block" in msg:
            prev = idx - 1
            while prev >= 0 and not lines[prev].strip():
                prev -= 1
            base = len(lines[prev]) - len(lines[prev].lstrip()) if prev >= 0 else 0
            ls = list(lines)
            ls.insert(prev + 1, " " * (base + 4) + "pass")
            out.append(("\n".join(ls), "inserted 'pass' for the empty block"))
        if "unindent does not match" in msg or "unexpected indent" in msg:
            indents = sorted({len(l) - len(l.lstrip()) for l in lines[:idx] if l.strip()})
            cur = len(lines[idx]) - len(lines[idx].lstrip())
            below = [x for x in indents if x <= cur]
            tgt = below[-1] if below else 0
            if "unexpected indent" in msg:
                prev = idx - 1
                while prev >= 0 and not lines[prev].strip():
                    prev -= 1
                tgt = len(lines[prev]) - len(lines[prev].lstrip()) if prev >= 0 else 0
            out.append((with_line(idx, " " * tgt + lines[idx].lstrip()), "re-aligned the indentation"))
    if "inconsistent use of tabs" in msg or isinstance(e, TabError):
        out.append(("\n".join(l.expandtabs(4) for l in lines), "tabs -> 4 spaces"))
    return out


def heal_syntax(text: str, name: str = "<src>", max_attempts: int = 10) -> Tuple[str, List[dict]]:
    """Repeat: parse -> candidate repairs -> keep the first one that compiles or moves the error LATER in the file."""
    history: List[dict] = []
    cur = text
    for attempt in range(1, max_attempts + 1):
        e = syntax_error(cur, name)
        if e is None:
            break
        before = _err_line(e)
        chosen = None
        best_progress = None
        for cand, desc in _candidates(cur, e):
            e2 = syntax_error(cand, name)
            if e2 is None:
                chosen = (cand, desc, None)
                break
            if best_progress is None and _err_line(e2) > before:      # nearest candidate that makes progress
                best_progress = (cand, desc, e2)
        chosen = chosen or best_progress
        if not chosen:
            history.append({"attempt": attempt, "line": before, "message": e.msg, "result": "no safe repair found"})
            break
        history.append({"attempt": attempt, "line": before, "message": e.msg, "result": chosen[1]})
        cur = chosen[0]
    return cur, history


# ─────────────────────────────────────────────────────────────────────────────
# AST checks
# ─────────────────────────────────────────────────────────────────────────────
class _Scope(ast.NodeVisitor):
    def __init__(self):
        self.used: set = set()

    def visit_Name(self, n):
        self.used.add(n.id)

    def visit_Attribute(self, n):
        self.generic_visit(n)


def _mk(rel, node, rule, title, sev, conf, msg, rec, cat="quality", cwe=(), fix=None, lines=None):
    ln = getattr(node, "lineno", 1)
    return Finding(file=rel, line=ln, column=getattr(node, "col_offset", 0) + 1, language="python", category=cat,
                   rule_id=rule, title=title, severity=sev, confidence=conf, message=msg, recommendation=rec, cwe=cwe,
                   snippet=(lines[ln - 1].strip()[:160] if lines and 0 < ln <= len(lines) else ""), agent="python", fix=fix)


def analyze_ast(text: str, rel: str) -> List[Finding]:
    try:
        tree = ast.parse(pysrc(text))
    except (SyntaxError, ValueError, RecursionError):
        return []
    lines = text.splitlines()
    out: List[Finding] = []
    is_init = rel.endswith("__init__.py")
    scope = _Scope()
    scope.visit(tree)
    used = scope.used
    exported = set()
    for n in ast.walk(tree):
        if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "__all__" for t in n.targets) \
                and isinstance(n.value, (ast.List, ast.Tuple)):
            exported |= {e.value for e in n.value.elts if isinstance(e, ast.Constant) and isinstance(e.value, str)}
    in_try = set()
    for n in ast.walk(tree):                       # imports guarded by try/except ImportError are feature probes
        if isinstance(n, ast.Try):
            for sub in ast.walk(n):
                if isinstance(sub, (ast.Import, ast.ImportFrom)):
                    in_try.add(id(sub))

    # ---- unused imports (single-line statements only: removal is then exact) -------------------
    for n in tree.body:
        if not isinstance(n, (ast.Import, ast.ImportFrom)) or is_init or id(n) in in_try:
            continue
        if isinstance(n, ast.ImportFrom) and (n.module == "__future__" or any(a.name == "*" for a in n.names)):
            continue
        if n.lineno != n.end_lineno:
            continue
        line = lines[n.lineno - 1] if n.lineno <= len(lines) else ""
        if "noqa" in line:
            continue
        dead = []
        for a in n.names:
            bound = (a.asname or a.name).split(".")[0]
            if bound not in used and bound not in exported and not re.search(rf"[\"']{re.escape(bound)}[\"']", text):
                dead.append(a)
        if not dead:
            continue
        keep = [a for a in n.names if a not in dead]
        indent = line[:len(line) - len(line.lstrip())]
        stdlib = (getattr(n, "module", None) or n.names[0].name).split(".")[0] in _STDLIB
        if keep:
            parts = ", ".join(a.name + (f" as {a.asname}" if a.asname else "") for a in keep)
            new = [f"{indent}from {n.module} import {parts}" if isinstance(n, ast.ImportFrom) else f"{indent}import {parts}"]
        else:
            new = []
        names = ", ".join(a.asname or a.name for a in dead)
        fx = Fix(f"Remove unused import: {names}", [Edit(n.lineno, n.lineno, new)], TIER_AUTO if stdlib else TIER_PROPOSED,
                 behavior_note="" if stdlib else "Third-party imports can have side effects (plugin registration); confirm none is needed.")
        out.append(_mk(rel, n, "PY-UNUSED-IMPORT", f"Unused import: {names}", "Low", 0.85,
                       "Imported but never used: dead weight, slower start-up and a misleading dependency list.",
                       "Delete the import (or use it).", fix=fx, lines=lines))

    # ---- walk functions / loops / handlers -----------------------------------------------------
    for n in ast.walk(tree):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
            muts = [(a, d) for a, d in zip(reversed(n.args.args), reversed(n.args.defaults))
                    if isinstance(d, (ast.List, ast.Dict, ast.Set)) or
                    (isinstance(d, ast.Call) and isinstance(d.func, ast.Name) and d.func.id in ("list", "dict", "set") and not d.args)]
            muts.reverse()                                  # source order
            if muts:
                fx = _mutable_default_fix(n, muts, lines)
                names = ", ".join(a.arg for a, _ in muts)
                out.append(_mk(rel, n, "PY-MUTABLE-DEFAULT", f"Mutable default argument: {names}", "Medium", 0.9,
                               "The default object is created once at definition time and shared by every call, so "
                               "changes leak between calls (a classic state-corruption bug).",
                               "Default to None and create the object inside the function.", fix=fx, lines=lines))
        if isinstance(n, ast.ExceptHandler):
            if len(n.body) == 1 and isinstance(n.body[0], ast.Pass):
                out.append(_mk(rel, n, "PY-SWALLOWED", "Exception silently swallowed", "Low", 0.7,
                               "'except ...: pass' hides failures; the program continues in an unknown state.",
                               "Log the exception (logging.exception) or handle/re-raise it.", cwe=(390,), lines=lines))
        if isinstance(n, ast.Assert):
            src = ast.get_source_segment(text, n.test) or ""
            if re.search(r"(?i)admin|authenticated|permission|authorized|is_staff|role|owner|csrf|token", src):
                out.append(_mk(rel, n, "PY-ASSERT-AUTH", "assert used for an authorisation check", "Medium", 0.6,
                               "assert statements are removed when Python runs with -O, silently disabling the check.",
                               "Use an explicit 'if not allowed: raise PermissionError(...)'.", cat="security", cwe=(617, 285), lines=lines))
        if isinstance(n, (ast.For, ast.While)):
            for sub in ast.walk(n):
                if isinstance(sub, ast.AugAssign) and isinstance(sub.op, ast.Add) and isinstance(sub.target, ast.Name):
                    if _assigned_str(tree, sub.target.id) and not _is_num(sub.value):
                        out.append(_mk(rel, sub, "PY-STR-CONCAT-LOOP", "String built with += in a loop", "Low", 0.5,
                                       "Repeated concatenation copies the growing string each time (O(n^2) in the worst case).",
                                       "Collect the pieces in a list and ''.join(parts) once after the loop.", cat="performance", lines=lines))
                        break
    # ---- unreachable code ---------------------------------------------------------------------
    for n in ast.walk(tree):
        body = getattr(n, "body", None)
        if isinstance(body, list):
            for a, b in zip(body, body[1:]):
                if isinstance(a, (ast.Return, ast.Raise, ast.Continue, ast.Break)) and isinstance(b, ast.stmt):
                    out.append(_mk(rel, b, "PY-UNREACHABLE", "Unreachable code", "Low", 0.9,
                                   "Statements after return/raise/break/continue never run.", "Delete them or fix the control flow.", lines=lines))
                    break
    return out


def _is_num(v) -> bool:
    return isinstance(v, ast.Constant) and isinstance(v.value, (int, float))


def _assigned_str(tree, name: str) -> bool:
    for n in ast.walk(tree):
        if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == name for t in n.targets):
            v = n.value
            if (isinstance(v, ast.Constant) and isinstance(v.value, str)) or isinstance(v, ast.JoinedStr):
                return True
    return False


def _mutable_default_fix(fn, muts, lines: List[str]) -> Optional[Fix]:
    """def f(a, x=[]):  ->  def f(a, x=None):  + 'if x is None: x = []' as the first statement."""
    hdr = fn.lineno
    if fn.args.args and fn.body and fn.body[0].lineno == hdr:          # one-line def: skip
        return None
    first = fn.body[0]
    sig_end = first.lineno - 1
    # the signature must fit on one line to be rewritten safely
    if any(a.lineno != hdr for a, _ in muts) or any(d.lineno != hdr for _, d in muts):
        return None
    sig = lines[hdr - 1]
    inits = []
    for a, d in muts:
        lit = ast.unparse(d)
        pat = re.compile(rf"(\b{re.escape(a.arg)}\s*(?::[^=,)]+)?\s*=\s*){re.escape(lit)}")
        if lit == "set()" or lit in ("list()", "dict()"):
            pass
        if not pat.search(sig):
            return None
        sig = pat.sub(r"\1None", sig, count=1)
        inits.append((a.arg, lit))
    indent = " " * first.col_offset
    ins_at = first.lineno
    has_doc = isinstance(first, ast.Expr) and isinstance(getattr(first, "value", None), ast.Constant) and isinstance(first.value.value, str)
    if has_doc:
        ins_at = first.end_lineno + 1
    new_lines = []
    for name, lit in inits:
        new_lines += [f"{indent}if {name} is None:", f"{indent}    {name} = {lit}"]
    return Fix("Use None as the default and create the object inside the function",
               [Edit(hdr, hdr, [sig]), Edit(ins_at, ins_at - 1, new_lines)], TIER_PROPOSED,
               behavior_note="Callers that (accidentally) relied on the shared default object will now get a fresh one per call.")
