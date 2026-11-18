"""
toolcheck.py - syntax / compile diagnostics from real parsers, never executing the code under test:
    JavaScript  node --check          C  gcc -fsyntax-only        shell  bash -n        JSON  json        YAML  PyYAML
Each checker returns Findings; healers return (new_text, history) and are VERIFIED by re-running the same parser.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
from typing import Callable, Dict, List, Optional, Tuple

from .core import Finding
from .pyanalyzer import _strip_comment

_ENV = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LC_ALL": "C", "LANG": "C", "HOME": "/nonexistent"}


def have(tool: str) -> bool:
    return shutil.which(tool) is not None


def _run(cmd: List[str], cwd: Optional[str] = None, timeout: int = 30) -> Tuple[int, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, cwd=cwd, env=_ENV, stdin=subprocess.DEVNULL)
        return p.returncode, (p.stderr or "") + (p.stdout or "")
    except subprocess.TimeoutExpired:
        return 124, "timeout"
    except OSError as e:
        return 127, str(e)


def _err(rel, line, col, lang, rule, msg, why, rec, snippet="", sev="High"):
    return Finding(file=rel, line=max(1, line), column=col, language=lang, category="error", rule_id=rule,
                   title=msg[:140], severity=sev, confidence=1.0, message=why, recommendation=rec, snippet=snippet, agent=lang)


# ─────────────────────────────────────────────────────────────────────────────
# JavaScript
# ─────────────────────────────────────────────────────────────────────────────
def _js_parse(text: str, ext: str = ".js") -> Optional[Tuple[int, str]]:
    """None if it parses, else (line, message)."""
    with tempfile.TemporaryDirectory(prefix="cd1_js_") as d:
        p = os.path.join(d, "x" + ext)
        with open(p, "w", encoding="utf-8", errors="surrogateescape") as f:
            f.write(text)
        rc, out = _run(["node", "--check", p], cwd=d, timeout=20)
    if rc == 0:
        return None
    m = re.search(r"x\.\w+:(\d+)", out)
    msg = re.search(r"(SyntaxError:.*)", out)
    return (int(m.group(1)) if m else 1, msg.group(1).strip() if msg else out.strip().splitlines()[-1][:200] if out.strip() else "syntax error")


def check_js(text: str, rel: str) -> List[Finding]:
    if not have("node") or rel.endswith((".jsx", ".ts", ".tsx", ".vue")):
        return []
    ext = ".mjs" if re.search(r"^\s*(import|export)\s", text, re.M) else ".cjs" if "require(" in text else ".js"
    r = _js_parse(text, ext)
    if not r:
        return []
    line, msg = r
    lines = text.splitlines()
    return [_err(rel, line, 0, "javascript", "JS-SYNTAX", msg, "The JavaScript parser rejected this file; it cannot load or run.",
                 "Fix the statement at this line (the self-healing pass handles unbalanced brackets).",
                 lines[line - 1].strip()[:160] if 0 < line <= len(lines) else "")]


def _js_delims(text: str):
    """Scan brackets outside strings/comments. Returns (unclosed openers stack, [positions of stray closers])."""
    pairs = {")": "(", "]": "[", "}": "{"}
    stack, stray = [], []
    i, n = 0, len(text)
    while i < n:
        c, two = text[i], text[i:i + 2]
        if two == "//":
            i = text.find("\n", i)
            i = n if i < 0 else i
        elif two == "/*":
            j = text.find("*/", i + 2)
            i = n if j < 0 else j + 2
        elif c in "\"'`":
            q, i = c, i + 1
            while i < n and text[i] != q:
                if text[i] == "\\":
                    i += 1
                elif text[i] == "\n" and q != "`":
                    break
                i += 1
            i += 1
        else:
            if c in "([{":
                stack.append((c, i))
            elif c in pairs:
                if stack and stack[-1][0] == pairs[c]:
                    stack.pop()
                else:
                    stray.append(i)
            i += 1
    return stack, stray


def heal_js(text: str, rel: str = "x.js") -> Tuple[str, List[dict]]:
    history: List[dict] = []
    ext = ".mjs" if re.search(r"^\s*(import|export)\s", text, re.M) else ".js"
    if _js_parse(text, ext) is None:
        return text, history
    stack, stray = _js_delims(text)
    cand, desc = text, ""
    if stray:
        pos = stray[-1]
        cand, desc = text[:pos] + text[pos + 1:], f"removed the stray '{text[pos]}'"
    elif stack:
        close = {"(": ")", "[": "]", "{": "}"}
        cand = text.rstrip("\n") + "\n" + "".join(close[c] for c, _ in reversed(stack)) + "\n"
        desc = "closed unbalanced " + " ".join(f"'{c}'" for c, _ in stack)
    if cand != text and _js_parse(cand, ext) is None:
        history.append({"attempt": 1, "line": 1, "message": "unbalanced delimiters", "result": desc})
        return cand, history
    history.append({"attempt": 1, "line": 1, "message": "syntax error", "result": "no safe repair found"})
    return text, history


# ─────────────────────────────────────────────────────────────────────────────
# C (gcc)
# ─────────────────────────────────────────────────────────────────────────────
_GCC = re.compile(r"^(?P<file>[^:\n]+):(?P<line>\d+):(?:(?P<col>\d+):)?\s*(?P<kind>fatal error|error|warning):\s*(?P<msg>.*?)(?:\s*\[(?P<opt>-W[\w=+\-]+)\])?$", re.M)
_SEC_OPTS = {"-Wformat-security", "-Wformat-overflow", "-Wstringop-overflow", "-Wuninitialized", "-Wmaybe-uninitialized",
             "-Warray-bounds", "-Wformat-nonliteral", "-Wnonnull", "-Wfree-nonheap-object", "-Wuse-after-free", "-Wreturn-local-addr",
             "-Wstringop-truncation", "-Wrestrict", "-Wformat"}


def _gcc_diags(text: str, include_dirs: List[str]) -> List[dict]:
    if not have("gcc"):
        return []
    with tempfile.TemporaryDirectory(prefix="cd1_c_") as d:
        try:                                    # same safety gate as the C++ engine: no host-file includes, no spawn primitives
            import compiler_runner as CR
            viol = CR.scan_source(text, include_dir=d, confine_root=include_dirs[0] if include_dirs else d)
        except Exception as e:                  # fail closed: if the gate cannot run, the file is not compiled
            viol = [type("V", (), {"__str__": lambda self: f"gate unavailable ({type(e).__name__})", "line": 1})()]
        if viol:
            return [{"line": int(getattr(viol[0], "line", 0) or 1), "col": 0, "kind": "gate", "msg": str(viol[0]), "opt": ""}]
        p = os.path.join(d, "x.c")
        with open(p, "w", encoding="utf-8", errors="surrogateescape") as f:
            f.write(text)
        cmd = ["gcc", "-fsyntax-only", "-x", "c", "-Wall", "-Wextra", "-Wformat=2", "-Wformat-security", "-fdiagnostics-color=never",
               "-Wno-unused-parameter"] + [a for inc in include_dirs for a in ("-I", inc)] + [p]
        rc, out = _run(cmd, cwd=d, timeout=30)
    res = []
    for m in _GCC.finditer(out):
        if os.path.basename(m.group("file")) != "x.c":
            continue
        res.append({"line": int(m.group("line")), "col": int(m.group("col") or 0), "kind": m.group("kind"),
                    "msg": m.group("msg"), "opt": m.group("opt") or ""})
    return res


def check_c(text: str, rel: str, include_dirs: List[str]) -> List[Finding]:
    lines = text.splitlines()
    out: List[Finding] = []
    for d in _gcc_diags(text, include_dirs):
        snippet = lines[d["line"] - 1].strip()[:160] if 0 < d["line"] <= len(lines) else ""
        if d["kind"] == "gate":
            out.append(Finding(file=rel, line=d["line"], column=0, language="c", category="security", rule_id="C-GATE-BLOCKED",
                               title="Safety gate: not compiled - " + d["msg"][:100], severity="High", confidence=0.9, cwe=(78,), agent="c",
                               message="A forbidden construct (process execution, host-file include, system header) was found, so the file was not compiled.",
                               recommendation="Remove it or review it manually.", snippet=snippet))
        elif d["kind"] in ("error", "fatal error"):
            missing = "No such file or directory" in d["msg"]
            out.append(_err(rel, d["line"], d["col"], "c", "C-COMPILE", d["msg"],
                            "A header is not in the project (add it, or pass the include path)." if missing else "The C compiler rejects this statement.",
                            "Fix the reported statement." if not missing else "Include the missing header file in the upload.", snippet))
        elif d["opt"] in _SEC_OPTS or "format" in d["opt"]:
            out.append(Finding(file=rel, line=d["line"], column=d["col"], language="c", category="security", rule_id="C-WARN" + re.sub(r"[^A-Z0-9]+", "-", d["opt"].upper()).rstrip("-"),
                               title=d["msg"][:140], severity="Medium", confidence=0.8, cwe=(119,), agent="c",
                               message="The compiler's own flow analysis flags this as a memory-safety or format problem.",
                               recommendation="Fix the reported operation; compile with -Wall -Wextra -Wformat=2 -fsanitize=address,undefined while testing.",
                               snippet=snippet))
        elif d["kind"] == "warning":
            out.append(Finding(file=rel, line=d["line"], column=d["col"], language="c", category="quality", rule_id="C-WARN" + re.sub(r"[^A-Z0-9]+", "-", d["opt"].upper()).rstrip("-"),
                               title=d["msg"][:140], severity="Low", confidence=0.7, agent="c",
                               message="Compiler warning: usually a latent bug.", recommendation="Fix it so the build is warning-free.", snippet=snippet))
    return out


def heal_c(text: str, include_dirs: List[str], max_attempts: int = 8) -> Tuple[str, List[dict]]:
    """Missing ';' (reported at the NEXT token) - add it to the previous code line, verified by gcc."""
    history, cur = [], text
    for attempt in range(1, max_attempts + 1):
        errs = [d for d in _gcc_diags(cur, include_dirs) if d["kind"] == "error"]
        if not errs:
            break
        e = errs[0]
        lines = cur.split("\n")
        cands = []
        if ("expected" in e["msg"] and "before" in e["msg"] and re.search(r"[;,)]", e["msg"])) or "expected ';' after" in e["msg"]:
            li2 = e["line"] - 1                                    # A: error is reported at the end of the unfinished line
            if 0 <= li2 < len(lines):
                code, cm = _strip_comment(lines[li2])
                if code and e["col"] >= len(code) and not code.endswith((";", "{", "}", ",", ":")) and not code.lstrip().startswith("#"):
                    cands.append((li2, code + ";" + ((" " + cm) if cm else ""), "added the missing ';'"))
            li = e["line"] - 2                                     # B: reported at the next token -> previous code line
            while li >= 0 and not lines[li].strip():
                li -= 1
            if li >= 0:
                code, cm = _strip_comment(lines[li])
                if code and not code.endswith((";", "{", "}", ",", ":")) and not code.lstrip().startswith("#"):
                    cands.append((li, code + ";" + ((" " + cm) if cm else ""), "added the missing ';'"))
        ok = False
        for li, new, desc in cands:
            ls = list(lines)
            ls[li] = new
            t2 = "\n".join(ls)
            e2 = [d for d in _gcc_diags(t2, include_dirs) if d["kind"] == "error"]
            if len(e2) < len(errs) or (e2 and (e2[0]["line"], e2[0]["col"]) > (e["line"], e["col"])):
                history.append({"attempt": attempt, "line": e["line"], "message": e["msg"], "result": desc})
                cur, ok = t2, True
                break
        if not ok:
            history.append({"attempt": attempt, "line": e["line"], "message": e["msg"], "result": "no safe repair found"})
            break
    return cur, history


# ─────────────────────────────────────────────────────────────────────────────
# shell / JSON / YAML
# ─────────────────────────────────────────────────────────────────────────────
def check_shell(text: str, rel: str) -> List[Finding]:
    if not have("bash") or text.startswith("#!/usr/bin/env zsh") or "#!/bin/zsh" in text[:30]:
        return []
    with tempfile.TemporaryDirectory(prefix="cd1_sh_") as d:
        p = os.path.join(d, "x.sh")
        with open(p, "w", encoding="utf-8", errors="surrogateescape") as f:
            f.write(text)
        rc, out = _run(["bash", "-n", p], cwd=d, timeout=15)       # -n: parse only, never executes
    if rc == 0:
        return []
    m = re.search(r"line (\d+): (.*)", out)
    line = int(m.group(1)) if m else 1
    lines = text.splitlines()
    return [_err(rel, line, 0, "shell", "SH-SYNTAX", (m.group(2) if m else out.strip())[:140], "bash cannot parse this script.",
                 "Close the open quote/if/do/case or fix the reported construct.", lines[line - 1].strip()[:160] if 0 < line <= len(lines) else "")]


# language -> (tool, file name, argv builder, line regex).  Every command is PARSE-ONLY: nothing the upload contains is executed.
_PARSERS = {
    "php": ("php", "x.php", lambda p: ["php", "-n", "-l", p], r"on line (\d+)"),
    "ruby": ("ruby", "x.rb", lambda p: ["ruby", "-c", p], r":(\d+):"),
    "go": ("gofmt", "x.go", lambda p: ["gofmt", "-e", p], r":(\d+):\d+:"),
    "rust": ("rustfmt", "x.rs", lambda p: ["rustfmt", "--edition", "2021", "--emit", "stdout", p], r"x\.rs:(\d+)"),
    "java": ("javac", "X.java", None, r"X\.java:(\d+):"),
}


def check_syntax_tool(text: str, rel: str, lang: str) -> List[Finding]:
    """Parse-only syntax check with the language's own front end (php -l, ruby -c, gofmt -e, rustfmt, javac parse phase)."""
    spec = _PARSERS.get(lang)
    if not spec or not have(spec[0]) or len(text) > 2_000_000:
        return []
    tool, fname, argv, rx = spec
    with tempfile.TemporaryDirectory(prefix="cd1_syn_") as d:
        if lang == "java":
            mj = re.search(r"\b(?:class|interface|enum|record)\s+([A-Za-z_]\w*)", text)
            fname = (mj.group(1) if mj else "X") + ".java"
        p = os.path.join(d, fname)
        with open(p, "w", encoding="utf-8", errors="surrogateescape") as f:
            f.write(text)
        if lang == "java":                      # -proc:none: no annotation processors; should-stop at PARSE: syntax errors only (no classpath needed)
            cmd = ["javac", "-proc:none", "-XDshould-stop.at=PARSE", "-XDshould-stop.ifError=PARSE", "-d", d, p]
        else:
            cmd = argv(p)
        rc, out = _run(cmd, cwd=d, timeout=25)
    if "rustup" in out or "could not choose" in out or "command not found" in out:
        return []                                # the tool exists but is not usable here: say nothing rather than invent an error
    if lang == "java":                           # keep parse-phase errors only; missing classpath symbols are not the file's fault
        syn_lines = [l for l in out.splitlines() if re.search(
            r"error: (illegal start|.* expected|reached end of file|unclosed|not a statement|class, interface|invalid method declaration|"
            r"orphaned|'else' without|unmatched|illegal character|malformed|empty character)", l)]
        out = "\n".join(syn_lines)
    bad = rc != 0 and (lang != "java" or bool(out))
    if not bad:
        return []
    m = re.search(rx, out)
    line = int(m.group(1)) if m else 1
    msg = re.sub(r"\s+", " ", out.replace(d, "")).strip()[:140]
    lines = text.splitlines()
    return [_err(rel, line, 0, lang, f"{lang.upper()}-SYNTAX", msg or f"{tool} cannot parse this file",
                 f"{tool} (parse only) rejected the file.", "Fix the reported construct; the compiler front end points at the line.",
                 lines[line - 1].strip()[:160] if 0 < line <= len(lines) else "")]


def check_json(text: str, rel: str) -> List[Finding]:
    if len(text) > 5_000_000:
        return []
    try:
        json.loads(text)
        return []
    except json.JSONDecodeError as e:
        lines = text.splitlines()
        return [_err(rel, e.lineno, e.colno, "json", "JSON-SYNTAX", e.msg, "Invalid JSON: tools that read this file will fail.",
                     "Fix the syntax (trailing commas and comments are not allowed in JSON).", lines[e.lineno - 1].strip()[:160] if 0 < e.lineno <= len(lines) else "")]
    except RecursionError:
        return [_err(rel, 1, 0, "json", "JSON-DEPTH", "nesting too deep", "Excessively nested JSON can crash parsers.", "Flatten the structure.")]


def heal_json(text: str) -> Tuple[str, List[dict]]:
    try:
        json.loads(text)
        return text, []
    except json.JSONDecodeError:
        pass
    cand = re.sub(r",(\s*[}\]])", r"\1", text)
    try:
        json.loads(cand)
        return cand, [{"attempt": 1, "line": 1, "message": "trailing comma", "result": "removed trailing commas"}]
    except json.JSONDecodeError:
        return text, [{"attempt": 1, "line": 1, "message": "invalid JSON", "result": "no safe repair found"}]


def check_yaml(text: str, rel: str) -> List[Finding]:
    if len(text) > 1_000_000 or "{{" in text and "{%" in text:                  # skip helm/jinja templates, oversize
        return []
    try:
        import yaml
    except ImportError:
        return []
    try:
        list(yaml.safe_load_all(text))                               # safe loader: never constructs Python objects
        return []
    except yaml.YAMLError as e:
        mark = getattr(e, "problem_mark", None)
        line = (mark.line + 1) if mark else 1
        lines = text.splitlines()
        return [_err(rel, line, (mark.column + 1) if mark else 0, "yaml", "YAML-SYNTAX", (getattr(e, "problem", None) or str(e))[:140],
                     "Invalid YAML: deployment / CI tools will reject it.", "Check indentation (spaces only) and quoting.",
                     lines[line - 1].strip()[:160] if 0 < line <= len(lines) else "")]
    except Exception:
        return []


def secure_shell_header_fix(text: str):
    """(Edit-like tuple) for 'set -euo pipefail' - used by the shell analyst as a PROPOSED fix."""
    return None
