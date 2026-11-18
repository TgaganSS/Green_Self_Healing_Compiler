"""
rules.py - comment-aware, multi-language security / quality rule engine.

Every rule says WHAT is wrong, WHY it matters, the BEST REPLACEMENT, and (when a mechanical fix is safe)
carries a Fix with a tier:  auto (strictly safer)  |  proposed (may change behaviour -> human review).
Rules match on a "code view" of the file where comments are blanked out (columns preserved), so a vulnerable
call mentioned in a comment is not reported.
"""
from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Sequence, Tuple

from .core import Edit, Finding, Fix, TIER_AUTO, TIER_NONE, TIER_PROPOSED, pysrc

# ─────────────────────────────────────────────────────────────────────────────
# comment blanking
# ─────────────────────────────────────────────────────────────────────────────
_SLASH = {"c", "cpp", "java", "kotlin", "scala", "go", "rust", "javascript", "typescript", "php", "csharp",
          "swift", "groovy"}
_HASH = {"python", "shell", "ruby", "yaml", "dockerfile", "env", "perl", "toml", "ini", "powershell",
         "makefile", "requirements", "terraform", "php"}
_DASH = {"sql"}


def code_view(text: str, lang: str, with_mask: bool = False):
    """Return ``text`` with comments (and python docstring / triple-quoted blocks) replaced by spaces.
    Newlines and column positions are preserved.  A scanner, not a parser: good enough to stop comments
    and prose from producing findings.  With ``with_mask`` also returns a bytearray marking characters
    that sit inside a single-line string literal (so call-shaped text in a message is not a finding)."""
    slash, hashc, dash = lang in _SLASH, lang in _HASH, lang in _DASH
    triple = lang == "python"
    out = list(text)
    n, i = len(text), 0
    mask = bytearray(n)
    quote = None                     # current single-line string quote
    tmpl = lang in ("javascript", "typescript", "go")          # backtick strings may span lines

    def blank(a, b):
        for k in range(a, b):
            if out[k] not in "\r\n":
                out[k] = " "

    while i < n:
        c = text[i]
        two = text[i:i + 2]
        if quote:
            mask[i] = 1
            if c == "\\":
                if i + 1 < n:
                    mask[i + 1] = 1
                i += 2
                continue
            if c == quote or (c == "\n" and quote != "`"):
                quote = None
            i += 1
            continue
        if triple and text[i:i + 3] in ('"""', "'''"):
            q = text[i:i + 3]
            j = text.find(q, i + 3)
            j = n if j < 0 else j + 3
            blank(i, j)
            i = j
            continue
        if c in "\"'" or (c == "`" and tmpl):
            quote = c
            mask[i] = 1
            i += 1
            continue
        if slash and two == "//":
            j = text.find("\n", i)
            j = n if j < 0 else j
            blank(i, j)
            i = j
            continue
        if slash and two == "/*":
            j = text.find("*/", i + 2)
            j = n if j < 0 else j + 2
            blank(i, j)
            i = j
            continue
        if hashc and c == "#":
            prev = text[i - 1] if i else "\n"
            if lang in ("shell", "dockerfile") and prev not in " \t\n;":
                i += 1
                continue
            if lang == "php" and two == "#[":
                i += 1
                continue
            j = text.find("\n", i)
            j = n if j < 0 else j
            blank(i, j)
            i = j
            continue
        if dash and two == "--":
            j = text.find("\n", i)
            j = n if j < 0 else j
            blank(i, j)
            i = j
            continue
        i += 1
    return ("".join(out), mask) if with_mask else "".join(out)


# ─────────────────────────────────────────────────────────────────────────────
# fix helpers
# ─────────────────────────────────────────────────────────────────────────────
FixFn = Callable[[List[str], int, "re.Match"], Optional[Fix]]


def sub(pattern: str, repl: str, desc: str, tier: str = TIER_AUTO, note: str = "") -> FixFn:
    rx = re.compile(pattern)

    def fn(lines: List[str], i: int, m) -> Optional[Fix]:
        new = rx.sub(repl, lines[i], count=1)
        if new == lines[i]:
            return None
        return Fix(desc, [Edit(i + 1, i + 1, [new])], tier, behavior_note=note)
    return fn


def py_import_edit(lines: List[str], module: str) -> Optional[Edit]:
    """Edit that adds ``import module`` after shebang / docstring / __future__ imports (None if present)."""
    text = "\n".join(lines)
    if re.search(rf"^\s*(import\s+{module}\b|from\s+{module}\s+import)", text, re.M):
        return None
    at = 0
    try:
        tree = ast.parse(pysrc(text))
        body = tree.body
        k = 0
        if body and isinstance(body[0], ast.Expr) and isinstance(getattr(body[0], "value", None), ast.Constant) \
                and isinstance(body[0].value.value, str):
            at = body[0].end_lineno
            k = 1
        while k < len(body) and isinstance(body[k], ast.ImportFrom) and body[k].module == "__future__":
            at = body[k].end_lineno
            k += 1
    except SyntaxError:
        while at < len(lines) and (lines[at].startswith("#!") or lines[at].startswith("#")):
            at += 1
    return Edit(at + 1, at, [f"import {module}"])


def _balanced_call_end(line: str, start: int) -> Optional[int]:
    """Index of the ')' closing the call whose '(' is at/after ``start`` (same line only)."""
    depth, quote = 0, None
    for k in range(start, len(line)):
        ch = line[k]
        if quote:
            if ch == "\\":
                continue
            if ch == quote:
                quote = None
            continue
        if ch in "\"'":
            quote = ch
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return k
    return None


def add_kwarg(call_regex: str, kwarg: str, desc: str, absent: str) -> FixFn:
    rx = re.compile(call_regex)

    def fn(lines: List[str], i: int, m) -> Optional[Fix]:
        line = lines[i]
        if re.search(absent, line):
            return None
        mm = rx.search(line)
        if not mm:
            return None
        end = _balanced_call_end(line, mm.end() - 1)
        if end is None:
            return None
        inner = line[mm.end():end].strip()
        new = line[:end] + ((", " if inner else "") + kwarg) + line[end:]
        return Fix(desc, [Edit(i + 1, i + 1, [new])], TIER_AUTO)
    return fn


def py_eval_fix(lines: List[str], i: int, m) -> Optional[Fix]:
    if m.group(1) != "eval":
        return None
    new = re.sub(r"(?<![\w.])eval\s*\(", "ast.literal_eval(", lines[i], count=1)
    edits = [Edit(i + 1, i + 1, [new])]
    imp = py_import_edit(lines, "ast")
    if imp:
        edits.append(imp)
    return Fix("Replace eval() with ast.literal_eval() (parses Python literals only, never runs code)", edits,
               TIER_PROPOSED, behavior_note="eval() accepted arbitrary expressions; literal_eval() raises "
               "ValueError for anything that is not a literal (numbers, strings, lists, dicts, tuples, sets, bools, None).")


# ─────────────────────────────────────────────────────────────────────────────
# rule table
# ─────────────────────────────────────────────────────────────────────────────
@dataclass
class Rule:
    id: str
    langs: Tuple[str, ...]
    rx: "re.Pattern"
    title: str
    sev: str
    conf: float
    cwe: Tuple[int, ...]
    why: str
    rec: str
    fix: Optional[FixFn] = None
    unless: Optional[Callable[[str, "re.Match"], bool]] = None
    cat: str = "security"
    max_per_file: int = 50
    in_strings: bool = False          # True: the pattern is meant to match string contents


def R(id, langs, pattern, title, sev, conf, cwe, why, rec, fix=None, unless=None, cat="security", flags=0,
      max_per_file=50, in_strings=False):
    return Rule(id, tuple(langs.split()), re.compile(pattern, flags), title, sev, conf, tuple(cwe), why, rec,
                fix, unless, cat, max_per_file, in_strings)


_NO_MASK = {"shell", "dockerfile", "yaml", "makefile", "env", "powershell", "terraform", "toml", "ini",
            "requirements", "sql", "batch"}


_SECWORDS = r"(?i:token|secret|passw|otp\b|nonce|salt|session|api_?key|csrf|auth|reset|verification|signature)"
_literal_only = lambda line, m: re.match(r"""\s*(["'])[^"'{}]*\1\s*\)""", line[m.end():]) is not None
_not_null_cmp = lambda line, m: bool(re.search(r"[!=]=\s*null\b|null\s*[!=]=", line))

RULES: List[Rule] = [
    # ── Python ──────────────────────────────────────────────────────────────
    R("PY-EVAL", "python", r"(?<![\w.])(eval|exec)\s*\(", "Dynamic code execution (eval/exec)", "High", 0.85, (95,),
      "eval()/exec() run whatever string they are given. If any part can be influenced by a user, a file or the "
      "network, the attacker runs code in your process.",
      "Parse data with json.loads() or ast.literal_eval(); dispatch with a dict of allowed functions instead of "
      "evaluating text.", py_eval_fix, unless=_literal_only),
    R("PY-DESERIALIZE", "python", r"\b(pickle|cPickle|dill|marshal|jsonpickle)\.(loads?|Unpickler)\s*\(",
      "Unsafe deserialization", "High", 0.8, (502,),
      "Unpickling executes arbitrary code embedded in the data (a crafted payload gives remote code execution).",
      "Use json (or msgpack/protobuf) for data from outside your trust boundary; sign + verify if pickle is unavoidable."),
    R("PY-YAML", "python", r"\byaml\.load\s*\(", "yaml.load() without a safe loader", "High", 0.85, (502,),
      "yaml.load() with the default/Full loader can construct arbitrary Python objects.",
      "Use yaml.safe_load().", sub(r"\byaml\.load\(", "yaml.safe_load(", "yaml.load -> yaml.safe_load"),
      unless=lambda l, m: "Loader" in l and "SafeLoader" in l),
    R("PY-SHELL", "python", r"\bsubprocess\.\w+\(.*shell\s*=\s*True", "subprocess with shell=True", "High", 0.8, (78,),
      "With shell=True the command string is parsed by /bin/sh; any interpolated value can inject extra commands.",
      "Pass an argument list: subprocess.run(['ls', '-l', path], check=True) and leave shell at its default (False)."),
    R("PY-OS-SYSTEM", "python", r"\bos\.(system|popen)\s*\(", "os.system / os.popen shell execution", "High", 0.8, (78,),
      "os.system() always goes through the shell, so untrusted text in the command becomes command injection.",
      "Use subprocess.run([...args], check=True) with a list of arguments (no shell)."),
    R("PY-WEAKHASH", "python", r"\bhashlib\.(md5|sha1)\s*\(", "Weak hash (MD5/SHA-1)", "Medium", 0.6, (327, 328),
      "MD5 and SHA-1 are collision-broken. Fine for non-security checksums, wrong for passwords, signatures or tokens.",
      "Use hashlib.sha256()/sha3_256() for integrity; for passwords use bcrypt/argon2/scrypt (hashlib.scrypt).",
      sub(r"hashlib\.(md5|sha1)\(", "hashlib.sha256(", "md5/sha1 -> sha256", TIER_PROPOSED,
          "Digest values change; anything that stored or compares the old hash must be migrated.")),
    R("PY-TLS-OFF", "python", r"\bverify\s*=\s*False\b", "TLS certificate verification disabled", "High", 0.9, (295,),
      "Without certificate checks any network attacker can impersonate the server (man-in-the-middle).",
      "Remove verify=False. For private CAs pass verify='/path/ca.pem'.",
      sub(r"\bverify\s*=\s*False\b", "verify=True", "verify=False -> verify=True")),
    R("PY-TLS-CTX", "python", r"ssl\._create_unverified_context|ssl\.CERT_NONE|check_hostname\s*=\s*False",
      "TLS verification disabled in ssl context", "High", 0.9, (295,),
      "The SSL context accepts any certificate / hostname.", "Use ssl.create_default_context() and keep hostname "
      "checking and CERT_REQUIRED on.",
      lambda lines, i, m: _first_fix(lines, i, [
          (r"ssl\._create_unverified_context", "ssl.create_default_context", "unverified context -> default context"),
          (r"ssl\.CERT_NONE", "ssl.CERT_REQUIRED", "CERT_NONE -> CERT_REQUIRED"),
          (r"check_hostname\s*=\s*False", "check_hostname = True", "check_hostname False -> True")])),
    R("PY-NO-TIMEOUT", "python", r"\brequests\.(get|post|put|delete|patch|head|request)\s*\(",
      "HTTP request without timeout", "Low", 0.8, (400,),
      "requests waits forever by default; one stalled server can hang a worker permanently (denial of service).",
      "Always pass timeout=(connect, read), e.g. timeout=10.",
      add_kwarg(r"\brequests\.(get|post|put|delete|patch|head|request)\s*\(", "timeout=10",
                "add timeout=10", absent=r"timeout\s*="),
      unless=lambda l, m: "timeout" in l, cat="quality"),
    R("PY-MKTEMP", "python", r"\btempfile\.mktemp\s*\(", "Insecure temporary file (mktemp)", "Medium", 0.85, (377,),
      "mktemp() returns a name without creating the file: a race lets an attacker pre-create/symlink it.",
      "Use tempfile.NamedTemporaryFile() or tempfile.mkstemp() / TemporaryDirectory()."),
    R("PY-RANDOM", "python", rf"(?:{_SECWORDS}.*\brandom\.(random|randint|choice|choices|randrange|getrandbits)\s*\(|"
      rf"\brandom\.(random|randint|choice|choices|randrange|getrandbits)\s*\(.*{_SECWORDS})",
      "Predictable random numbers used for a secret", "Medium", 0.7, (338,),
      "random is a Mersenne Twister: outputs can be predicted from earlier ones. Not for tokens/passwords/OTPs.",
      "Use the secrets module: secrets.token_urlsafe(32), secrets.choice(), secrets.randbelow()."),
    R("PY-DEBUG", "python", r"\.run\s*\([^)]*\bdebug\s*=\s*True", "Flask/werkzeug debug mode enabled", "High", 0.85, (489, 94),
      "The Werkzeug debugger gives an interactive Python console to anyone who can reach the page.",
      "Never ship debug=True; drive it from an environment variable that defaults to off.",
      sub(r"\bdebug\s*=\s*True", "debug=False", "debug=True -> debug=False")),
    R("PY-DJANGO-DEBUG", "python", r"^\s*DEBUG\s*=\s*True\b", "Django DEBUG = True", "Medium", 0.6, (489,),
      "DEBUG=True leaks settings, SQL and stack traces and disables host checks.",
      "Set DEBUG from the environment and default to False.",
      sub(r"DEBUG\s*=\s*True", "DEBUG = False", "DEBUG = False", TIER_PROPOSED, "Local development needs DEBUG=True; "
          "load it from an environment variable instead."), cat="security"),
    R("PY-BARE-EXCEPT", "python", r"^\s*except\s*:", "Bare except clause", "Low", 0.9, (396,),
      "A bare except also swallows KeyboardInterrupt/SystemExit and hides real bugs.",
      "Catch the specific exceptions you expect; at minimum 'except Exception:'.",
      sub(r"except\s*:", "except Exception:", "except: -> except Exception:", TIER_PROPOSED,
          "A bare except also catches SystemExit/KeyboardInterrupt; code that relies on that changes behaviour."), cat="quality"),
    R("PY-NONE-CMP", "python", r"[^=!<>]\s*[!=]=\s*None\b", "Comparison to None with ==", "Low", 0.95, (),
      "None is a singleton; '== None' can be overridden by __eq__ and is slower.", "Use 'is None' / 'is not None'.",
      lambda lines, i, m: Fix("== None -> is None", [Edit(i + 1, i + 1, [
          re.sub(r"!=\s*None\b", "is not None", re.sub(r"==\s*None\b", "is None", lines[i]))])], TIER_PROPOSED,
          behavior_note="Classes that override __eq__ (numpy, SQLAlchemy) behave differently with 'is None'."), cat="quality"),
    R("PY-EXTRACTALL", "python", r"\.extractall\s*\(", "Archive extraction without path validation (Zip Slip)", "Medium",
      0.6, (22,), "Members named '../../x' or absolute paths escape the target folder and overwrite arbitrary files.",
      "Validate every member (resolve and check it stays under the target) or use tarfile's filter='data' (3.12+)."),
    R("PY-SQLI", "python", r"""\.(execute|executemany|executescript)\s*\(\s*(f["']|["'][^"']*["']\s*(%|\+|\.format\s*\())""",
      "SQL built by string formatting (SQL injection)", "High", 0.8, (89,),
      "User input concatenated into SQL can rewrite the query (dump tables, bypass login, delete data).",
      "Use bound parameters: cursor.execute('SELECT * FROM t WHERE id = %s', (user_id,)) (or '?' for sqlite3)."),
    R("PY-AUTOESCAPE", "python", r"autoescape\s*=\s*False", "Template auto-escaping disabled", "Medium", 0.8, (79,),
      "Without auto-escaping, any variable rendered into HTML can carry a script (XSS).",
      "Keep autoescape on (select_autoescape(['html','xml']))",
      sub(r"autoescape\s*=\s*False", "autoescape=True", "autoescape=True", TIER_PROPOSED,
          "Templates that intentionally emit raw HTML must mark that output explicitly with |safe.")),
    R("PY-JWT", "python", r"verify_signature['\"]?\s*:\s*False|algorithms\s*=\s*\[\s*['\"]none['\"]|verify\s*=\s*False.*jwt",
      "JWT signature verification disabled", "High", 0.9, (347,),
      "Tokens are accepted without checking the signature, so anyone can forge an identity.",
      "Always verify with a fixed algorithm list: jwt.decode(t, key, algorithms=['HS256'])",
      sub(r"(verify_signature['\"]?\s*:\s*)False", r"\1True", "verify_signature True")),
    R("PY-CHMOD", "python", r"os\.chmod\s*\([^)]*0o?777", "World-writable permissions", "Medium", 0.8, (732,),
      "0777 lets every local user modify the file.", "Use 0o600 (private file), 0o644 or 0o755 as appropriate.",
      sub(r"0o?777", "0o755", "0777 -> 0o755", TIER_PROPOSED, "Other users lose write access; confirm no one relied on it.")),
    R("PY-XML", "python", r"\b(ElementTree|etree|minidom|ET)\.(parse|fromstring|parseString)\s*\(",
      "XML parsing of possibly untrusted input", "Low", 0.4, (611,),
      "Stock XML parsers can expand entities (billion-laughs) and may fetch external resources (XXE).",
      "Use defusedxml.ElementTree.parse()/fromstring() for anything not fully trusted."),

    # ── JavaScript / TypeScript ────────────────────────────────────────────
    R("JS-EVAL", "javascript typescript", r"(?<![\w.$])eval\s*\(", "eval() on dynamic data", "High", 0.85, (95,),
      "eval() executes a string as code with full page/process privileges (XSS or remote code execution).",
      "Use JSON.parse() for data, a lookup table for dispatch, and never build code from strings.",
      sub(r"(?<![\w.$])eval\s*\(", "JSON.parse(", "eval -> JSON.parse", TIER_PROPOSED,
          "Only valid when the string is JSON; JSON.parse throws on anything else.")),
    R("JS-NEWFUNC", "javascript typescript", r"\bnew\s+Function\s*\(", "new Function() code construction", "High", 0.85, (95,),
      "Equivalent to eval(): the string becomes executable code.", "Replace with a real function or a safe expression parser."),
    R("JS-TIMER-STR", "javascript typescript", r"\bset(Timeout|Interval)\s*\(\s*[\"'`]", "String passed to setTimeout/setInterval",
      "Medium", 0.8, (95,), "A string argument is evaluated like eval().", "Pass a function: setTimeout(() => work(), 100)."),
    R("JS-INNERHTML", "javascript typescript", r"\.(innerHTML|outerHTML)\s*\+?=(?!\s*[\"'`][^\"'`$]*[\"'`]\s*;?\s*$)",
      "HTML injected from a dynamic value (XSS)", "High", 0.75, (79,),
      "Assigning strings to innerHTML parses them as markup: a user-supplied value can carry <script>/onerror handlers.",
      "Use textContent for text, or sanitise with DOMPurify.sanitize() when HTML is genuinely needed.",
      sub(r"\.(innerHTML|outerHTML)(\s*\+?=)", r".textContent\2", "innerHTML -> textContent", TIER_PROPOSED,
          "Markup in the value will be shown as text instead of rendered.")),
    R("JS-DOCWRITE", "javascript typescript", r"\bdocument\.write(ln)?\s*\(", "document.write()", "Medium", 0.8, (79,),
      "Writes raw HTML into the page; classic DOM XSS sink and blocks parsing.", "Create nodes with createElement/textContent."),
    R("JS-EXEC", "javascript typescript", r"\b(exec|execSync)\s*\(\s*(`[^`]*\$\{|[^)]*[\"'`]\s*\+|[^\"'`)\s][^)]*\+)",
      "Shell command built from variables", "High", 0.8, (78,),
      "child_process.exec runs through a shell; interpolated input becomes command injection.",
      "Use execFile('cmd', [args...]) or spawn() with an argument array and shell:false."),
    R("JS-SHELL-TRUE", "javascript typescript", r"\bshell\s*:\s*true\b", "child_process with shell: true", "Medium", 0.7, (78,),
      "Arguments are re-parsed by the shell.", "Drop shell:true and pass arguments as an array."),
    R("JS-RANDOM", "javascript typescript", rf"(?:{_SECWORDS}.*\bMath\.random\s*\(|\bMath\.random\s*\(.*{_SECWORDS})",
      "Math.random() used for a secret", "Medium", 0.7, (338,),
      "Math.random() is not cryptographically secure and is predictable.",
      "Use crypto.randomBytes(32).toString('hex') / crypto.randomUUID() / crypto.getRandomValues()."),
    R("JS-TLS", "javascript typescript", r"rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*[\"']?0",
      "TLS certificate verification disabled", "High", 0.9, (295,),
      "Any attacker on the path can impersonate the server.", "Remove it; trust a private CA via the 'ca' option.",
      lambda lines, i, m: _first_fix(lines, i, [
          (r"rejectUnauthorized\s*:\s*false", "rejectUnauthorized: true", "rejectUnauthorized: true"),
          (r"(NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*[\"']?)0", r"\g<1>1", "NODE_TLS_REJECT_UNAUTHORIZED=1")])),
    R("JS-LOOSE-EQ", "javascript typescript", r"(?<![=!<>])[!=]=(?!=)", "Loose equality (== / !=)", "Low", 0.6, (),
      "== performs type coercion ('0' == 0, [] == false) and causes subtle bugs.", "Use === / !==.",
      lambda lines, i, m: Fix("== -> ===", [Edit(i + 1, i + 1, [
          re.sub(r"(?<![=!<>])!=(?!=)", "!==", re.sub(r"(?<![=!<>])==(?!=)", "===", lines[i]))])], TIER_PROPOSED,
          behavior_note="Comparisons that relied on coercion (e.g. '5' == 5) will now be false."),
      unless=_not_null_cmp, cat="quality", max_per_file=20),
    R("JS-VAR", "javascript typescript", r"^\s*var\s+\w", "'var' declaration", "Low", 0.7, (),
      "var is function-scoped and hoisted, a frequent source of bugs.", "Use const (default) or let.",
      sub(r"^(\s*)var\b", r"\1let", "var -> let", TIER_PROPOSED, "Block scoping and no redeclaration; check closures "
          "in loops."), cat="quality", max_per_file=10),
    R("JS-SQLI", "javascript typescript", r"\.(query|execute|raw)\s*\(\s*(`[^`]*\$\{|[\"'][^\"']*[\"']\s*\+)",
      "SQL built by concatenation / template string", "High", 0.8, (89,),
      "User input can change the meaning of the query (SQL injection).",
      "Use placeholders: db.query('SELECT * FROM users WHERE id = $1', [id])."),
    R("JS-REACT-HTML", "javascript typescript", r"dangerouslySetInnerHTML", "dangerouslySetInnerHTML", "Medium", 0.7, (79,),
      "Bypasses React's escaping; unsanitised input becomes XSS.", "Sanitise with DOMPurify or render as text."),
    R("JS-CORS", "javascript typescript", r"origin\s*:\s*[\"']\*[\"']|Access-Control-Allow-Origin[\"']?\s*[,:]\s*[\"']\*",
      "CORS allows every origin", "Medium", 0.6, (942,), "Any website can read responses from your API with the user's context.",
      "Allow an explicit list of trusted origins."),
    R("JS-JWT-NONE", "javascript typescript", r"algorithms\s*:\s*\[\s*[\"']none[\"']|ignoreExpiration\s*:\s*true",
      "JWT verification weakened", "High", 0.85, (347,), "Unsigned / expired tokens are accepted.",
      "Pin algorithms: ['HS256'|'RS256'] and honour expiry."),
    R("JS-PROTO", "javascript typescript", r"__proto__\s*[\[=]", "Prototype manipulation", "Medium", 0.6, (1321,),
      "Writing to __proto__ with attacker-controlled keys pollutes every object.",
      "Use Object.create(null) / Map, and reject '__proto__', 'constructor', 'prototype' keys."),
    R("JS-WEAKHASH", "javascript typescript", r"createHash\s*\(\s*[\"'](md5|sha1)[\"']", "Weak hash", "Medium", 0.6, (327, 328),
      "MD5/SHA-1 are collision-broken.", "Use sha256, and bcrypt/argon2/scrypt for passwords.",
      sub(r"createHash\(\s*([\"'])(md5|sha1)\1", r"createHash(\1sha256\1", "md5/sha1 -> sha256", TIER_PROPOSED,
          "Digest values change.")),
    R("JS-LOG-SECRET", "javascript typescript", r"console\.(log|info|debug)\s*\(.*(?i:password|passwd|secret|token|api_?key)",
      "Sensitive value written to logs", "Low", 0.5, (532,), "Logs are widely readable and long-lived.",
      "Redact or remove the value from the log call.", cat="security"),
    R("JS-DYN-REQUIRE", "javascript", r"\brequire\s*\(\s*(?![\"'])[^)]", "require() with a dynamic path", "Medium", 0.4, (829,),
      "If the path can be influenced, arbitrary modules/files load and execute.", "Use a fixed allow-list map of modules."),

    # ── C (C++ is handled by the dedicated compiler-backed engine) ─────────
    R("C-GETS", "c", r"(?<![\w.])gets\s*\(", "gets() - unbounded read", "Critical", 0.95, (242, 120),
      "gets() cannot limit input length: a long line overflows the buffer (removed from C11).",
      "Use fgets(buf, sizeof buf, stdin) and strip the trailing newline.",
      lambda lines, i, m: _gets_fix(lines, i)),
    R("C-STRCPY", "c", r"(?<![\w.])(strcpy|strcat|sprintf|vsprintf|stpcpy)\s*\(", "Unbounded string copy/format", "High", 0.75, (120, 787),
      "These functions never check the destination size, so oversized input overflows the buffer.",
      "Use snprintf(dst, sizeof dst, \"%s\", src), strlcpy/strlcat, or memcpy with a checked length."),
    R("C-SYSTEM", "c", r"(?<![\w.])(system|popen)\s*\(", "Shell command execution", "High", 0.8, (78,),
      "The command runs through the shell; input in the string becomes command injection.",
      "Use execv()/posix_spawn() with an argument vector, and validate every argument."),
    R("C-SCANF", "c", r"\b(f?scanf|sscanf)\s*\(\s*(stdin\s*,\s*)?\"[^\"]*%s", "scanf %s without width", "High", 0.85, (120,),
      "%s reads until whitespace with no limit.", "Give a width: scanf(\"%63s\", buf) or use fgets()."),
    R("C-FORMAT", "c", r"(?<![\w.])(printf|syslog)\s*\(\s*[A-Za-z_]\w*\s*\)|(?<![\w.])fprintf\s*\(\s*\w+\s*,\s*[A-Za-z_]\w*\s*\)",
      "Format string controlled by a variable", "High", 0.85, (134,),
      "If the variable holds attacker text, %n/%x directives read or write memory.",
      "Always use a constant format: printf(\"%s\", s).",
      lambda lines, i, m: Fix("printf(x) -> printf(\"%s\", x)", [Edit(i + 1, i + 1, [
          re.sub(r"(?<![\w.])(printf|syslog)\s*\(\s*([A-Za-z_]\w*)\s*\)", r'\1("%s", \2)',
                 re.sub(r"(?<![\w.])fprintf\s*\(\s*(\w+)\s*,\s*([A-Za-z_]\w*)\s*\)", r'fprintf(\1, "%s", \2)', lines[i]))])])),
    R("C-TEMP", "c", r"(?<![\w.])(mktemp|tmpnam|tempnam)\s*\(", "Predictable temporary file name", "Medium", 0.85, (377,),
      "Name/creation race: another user can pre-create or symlink the file.", "Use mkstemp() / tmpfile()."),
    R("C-ATOI", "c", r"(?<![\w.])(atoi|atol|atof)\s*\(", "atoi/atof without error checking", "Low", 0.7, (190,),
      "No way to detect overflow or non-numeric input.", "Use strtol()/strtod() and check errno and endptr.", cat="quality"),
    R("C-RAND", "c", rf"(?:{_SECWORDS}.*(?<![\w.])rand\s*\(|(?<![\w.])rand\s*\(.*{_SECWORDS})", "rand() used for a secret",
      "Medium", 0.6, (338,), "rand() is a weak, predictable generator.", "Use getrandom()/arc4random()/RAND_bytes()."),

    # ── Java / Kotlin / Scala ──────────────────────────────────────────────
    R("JV-EXEC", "java kotlin scala", r"Runtime\.getRuntime\(\)\.exec\s*\(", "Runtime.exec()", "High", 0.7, (78,),
      "Single-string exec tokenises on spaces and invites argument/command injection.",
      "Use new ProcessBuilder(List.of(cmd, arg1, ...)) and validate arguments."),
    R("JV-HASH", "java kotlin scala", r"MessageDigest\.getInstance\s*\(\s*\"(MD5|SHA-?1)\"", "Weak message digest", "Medium", 0.6, (327, 328),
      "MD5/SHA-1 are collision-broken.", "Use \"SHA-256\"; passwords need BCrypt/Argon2/PBKDF2.",
      sub(r"\"(MD5|SHA-?1)\"", "\"SHA-256\"", "digest -> SHA-256", TIER_PROPOSED, "Digest values change.")),
    R("JV-DESER", "java kotlin scala", r"\bnew\s+ObjectInputStream\s*\(|readObject\s*\(\s*\)", "Java native deserialization", "High", 0.7, (502,),
      "Deserialising untrusted streams has produced many remote-code-execution gadget chains.",
      "Use JSON/Protobuf, or set an ObjectInputFilter allow-list."),
    R("JV-SQLI", "java kotlin scala", r"(executeQuery|executeUpdate|execute|prepareStatement|createQuery)\s*\(\s*\"[^\"]*\"\s*\+",
      "SQL built by concatenation", "High", 0.8, (89,),
      "User input changes the query structure (SQL injection).",
      "Use PreparedStatement with ? placeholders and setString()/setInt()."),
    R("JV-RANDOM", "java kotlin scala", rf"(?:{_SECWORDS}.*new\s+(java\.util\.)?Random\s*\(|new\s+(java\.util\.)?Random\s*\(.*{_SECWORDS})",
      "java.util.Random used for a secret", "Medium", 0.7, (338,), "Linear congruential generator: predictable.",
      "Use java.security.SecureRandom."),
    R("JV-TRUSTALL", "java kotlin scala", r"ALLOW_ALL_HOSTNAME_VERIFIER|NoopHostnameVerifier|TrustAllStrategy|trustAllCerts|TrustSelfSignedStrategy",
      "TLS validation disabled (trust-all)", "High", 0.9, (295,), "Any certificate / hostname is accepted.",
      "Use the default SSLContext and hostname verifier."),
    R("JV-XXE", "java kotlin scala", r"(DocumentBuilderFactory|SAXParserFactory|XMLInputFactory|TransformerFactory)\.newInstance\s*\(",
      "XML parser factory (XXE risk)", "Medium", 0.5, (611,),
      "Default parsers resolve external entities and DTDs.",
      "factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true) and disable DOCTYPE declarations."),
    R("JV-CIPHER", "java kotlin scala", r"Cipher\.getInstance\s*\(\s*\"(DES|DESede|RC4|AES|AES/ECB[^\"]*|[^\"]*/ECB/[^\"]*)\"",
      "Weak cipher or ECB mode", "High", 0.85, (327,), "ECB leaks plaintext patterns; DES/RC4 are broken.",
      "Use \"AES/GCM/NoPadding\" with a fresh random 96-bit IV per message."),
    R("JV-STACKTRACE", "java kotlin scala", r"\.printStackTrace\s*\(\s*\)", "printStackTrace()", "Low", 0.6, (209,),
      "Prints internals to stderr/response and bypasses the logging framework.", "Log with a logger: log.error(\"msg\", e).",
      cat="quality", max_per_file=5),

    # ── Go ─────────────────────────────────────────────────────────────────
    R("GO-TLS", "go", r"InsecureSkipVerify\s*:\s*true", "TLS verification disabled", "High", 0.9, (295,),
      "The client accepts any certificate.", "Remove it; supply RootCAs for private CAs.",
      sub(r"InsecureSkipVerify\s*:\s*true", "InsecureSkipVerify: false", "InsecureSkipVerify: false")),
    R("GO-SHELL", "go", r"exec\.Command\s*\(\s*\"(sh|bash|zsh|cmd|powershell)(\.exe)?\"\s*,\s*\"(-c|/c|-Command)\"",
      "Shell invoked via exec.Command", "High", 0.8, (78,), "The command string is parsed by a shell (injection).",
      "exec.Command(\"prog\", arg1, arg2) with separate arguments."),
    R("GO-HASH", "go", r"\b(md5|sha1)\.(New|Sum)\s*\(", "Weak hash", "Medium", 0.6, (327, 328), "Collision-broken digest.",
      "crypto/sha256 (or argon2/bcrypt for passwords)."),
    R("GO-RAND", "go", rf"(?:{_SECWORDS}.*\brand\.(Int|Intn|Int31|Int63|Read|Seed)\w*\s*\(|\brand\.(Int|Intn|Int31|Int63|Seed)\w*\s*\(.*{_SECWORDS})",
      "math/rand used for a secret", "Medium", 0.65, (338,), "math/rand is deterministic.", "Use crypto/rand."),
    R("GO-SQLI", "go", r"\.(Query|QueryRow|Exec|QueryContext|ExecContext)\s*\(\s*(\w+\s*,\s*)?(fmt\.Sprintf|\"[^\"]*\"\s*\+)",
      "SQL built with Sprintf/concatenation", "High", 0.85, (89,), "Input changes the query (SQL injection).",
      "db.Query(\"... WHERE id = $1\", id) with placeholders."),
    R("GO-SERVER", "go", r"\bhttp\.ListenAndServe(TLS)?\s*\(", "HTTP server without timeouts", "Low", 0.5, (400,),
      "The default server has no read/write timeouts (Slowloris).", "Use &http.Server{ReadHeaderTimeout: ..., ReadTimeout: ..., WriteTimeout: ...}.",
      cat="quality"),
    R("GO-PERM", "go", r"\b(os\.(Chmod|OpenFile|MkdirAll|Mkdir|WriteFile)|ioutil\.WriteFile)\s*\(.*\b0?777\b", "World-writable permissions", "Medium", 0.8, (732,),
      "Everyone can modify the file/dir.", "Use 0o600/0o640 for files, 0o750 for directories.",
      sub(r"\b0?777\b", "0750", "0777 -> 0750", TIER_PROPOSED, "Other users lose write access.")),
    R("GO-HTML", "go", r"template\.(HTML|JS|URL)\s*\(", "html/template escaping bypass", "Medium", 0.6, (79,),
      "Marks input as already-safe, disabling contextual escaping.", "Pass plain strings and let html/template escape them."),

    # ── Rust ───────────────────────────────────────────────────────────────
    R("RS-UNSAFE", "rust", r"\bunsafe\s*(\{|fn\b|impl\b)", "unsafe block", "Low", 0.5, (119,),
      "unsafe turns off the borrow checker's guarantees; memory errors become possible.",
      "Keep unsafe minimal, document the invariants with a // SAFETY: comment, wrap in a safe API.", max_per_file=10),
    R("RS-SHELL", "rust", r"Command::new\s*\(\s*\"(sh|bash|cmd|powershell)(\.exe)?\"", "Shell command", "High", 0.7, (78,),
      "Shell parses interpolated text.", "Command::new(\"prog\").arg(a).arg(b)."),
    R("RS-TLS", "rust", r"danger_accept_invalid_(certs|hostnames)\s*\(\s*true\s*\)", "TLS verification disabled", "High", 0.9, (295,),
      "Accepts forged certificates.", "Remove the call.",
      sub(r"(danger_accept_invalid_(?:certs|hostnames)\s*\(\s*)true", r"\1false", "accept_invalid -> false")),
    R("RS-MEM", "rust", r"\b(mem::transmute|from_raw_parts(_mut)?|get_unchecked(_mut)?|mem::uninitialized|set_len)\s*[(<:]",
      "Unchecked memory operation", "Medium", 0.6, (119, 787), "Bypasses bounds/validity checks.", "Use safe slices/iterators."),
    R("RS-UNWRAP", "rust", r"\.unwrap\s*\(\s*\)", "unwrap() can panic", "Info", 0.5, (248,),
      "A None/Err value aborts the thread, a DoS risk on input-driven paths.", "Propagate with ? or handle the error.",
      cat="quality", max_per_file=5),

    # ── PHP ────────────────────────────────────────────────────────────────
    R("PH-EVAL", "php", r"(?<![\w$>:])(eval|assert|create_function)\s*\(", "Dynamic code execution", "Critical", 0.85, (95,),
      "Runs a string as PHP code.", "Remove; use real functions / a dispatch table."),
    R("PH-EXEC", "php", r"(?<![\w$>:])(system|exec|shell_exec|passthru|popen|proc_open)\s*\([^;]*\$", "Command execution with variables",
      "High", 0.8, (78,), "Variable text reaches a shell.", "Avoid; or escapeshellarg() every argument and use a fixed command."),
    R("PH-UNSERIALIZE", "php", r"(?<![\w$>:])unserialize\s*\(", "unserialize()", "High", 0.8, (502,),
      "Object injection can trigger gadget chains (RCE).", "json_decode(); or unserialize($x, ['allowed_classes' => false])."),
    R("PH-SQLI", "php", r"(mysqli?_query|->query|->exec)\s*\([^;]*(\"[^\"]*\$|\"\s*\.\s*\$|\.\s*\$_)", "SQL built from variables",
      "High", 0.8, (89,), "Input changes the query (SQL injection).", "PDO prepared statements: $stmt = $pdo->prepare('... WHERE id = ?'); $stmt->execute([$id])."),
    R("PH-INCLUDE", "php", r"\b(include|require)(_once)?\b[^;]*\$_(GET|POST|REQUEST|COOKIE)", "File inclusion from user input", "Critical", 0.9, (98,),
      "Local/remote file inclusion leads to code execution.", "Map IDs to fixed files with an allow-list."),
    R("PH-XSS", "php", r"\b(echo|print)\b[^;]*\$_(GET|POST|REQUEST|COOKIE)", "User input echoed without escaping", "High", 0.8, (79,),
      "Reflected XSS.", "echo htmlspecialchars($v, ENT_QUOTES, 'UTF-8');",
      unless=lambda l, m: bool(re.search(r"htmlspecialchars|htmlentities|intval|\(int\)|esc_", l))),
    R("PH-EXTRACT", "php", r"\bextract\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)", "extract() on request data", "High", 0.9, (621,),
      "Lets the client overwrite any variable.", "Read the specific keys you expect."),
    R("PH-PWHASH", "php", r"\b(md5|sha1)\s*\([^)]*(?i:pass|pwd)", "Password hashed with md5/sha1", "High", 0.8, (916, 327),
      "Fast hashes are brute-forced at billions/second.", "password_hash($p, PASSWORD_DEFAULT) / password_verify()."),
    R("PH-DISPLAY", "php", r"ini_set\s*\(\s*['\"]display_errors['\"]\s*,\s*['\"]?(1|On|true)", "display_errors enabled", "Low", 0.7, (209,),
      "Errors expose paths and queries to users.", "Set display_errors=0 in production; log instead.",
      sub(r"(display_errors['\"]\s*,\s*)['\"]?(1|On|true)['\"]?", r"\g<1>'0'", "display_errors off")),

    # ── Ruby ───────────────────────────────────────────────────────────────
    R("RB-EVAL", "ruby", r"(?<![\w.:])(eval|instance_eval|class_eval|module_eval)\s*[\(\s]\s*[^)\s]", "Dynamic code evaluation", "High", 0.8, (95,),
      "Runs a string as Ruby.", "Use define_method / public_send with an allow-list."),
    R("RB-SHELL", "ruby", r"(?<![\w.:])(system|exec|spawn|popen)\s*\(?\s*[\"'][^\"']*#\{|%x[\{\(\[]|`[^`]*#\{", "Shell command with interpolation", "High", 0.8, (78,),
      "Interpolated text is parsed by a shell.", "system('prog', arg1, arg2) (array form, no shell)."),
    R("RB-YAML", "ruby", r"\bYAML\.load\s*\(", "YAML.load", "High", 0.8, (502,), "Can instantiate arbitrary objects.", "YAML.safe_load().",
      sub(r"YAML\.load\(", "YAML.safe_load(", "YAML.load -> safe_load")),
    R("RB-MARSHAL", "ruby", r"\bMarshal\.load\s*\(", "Marshal.load", "High", 0.8, (502,), "Executes gadget chains.", "JSON.parse()."),
    R("RB-SQLI", "ruby", r"\.(where|find_by_sql|order|group|joins|execute)\s*\(\s*\"[^\"]*#\{", "SQL built with interpolation", "High", 0.85, (89,),
      "Input changes the query.", "where('name = ?', name) or where(name: name)."),
    R("RB-HTMLSAFE", "ruby", r"\.html_safe\b|\braw\s*\(", "html_safe / raw", "Medium", 0.6, (79,), "Disables escaping (XSS).", "Let Rails escape; sanitize() for rich text."),
    R("RB-TLS", "ruby", r"OpenSSL::SSL::VERIFY_NONE", "TLS verification disabled", "High", 0.9, (295,), "Accepts forged certs.", "VERIFY_PEER.",
      sub(r"VERIFY_NONE", "VERIFY_PEER", "VERIFY_NONE -> VERIFY_PEER")),
    R("RB-CSRF", "ruby", r"skip_before_action\s*:verify_authenticity_token|protect_from_forgery\s+with:\s*:null_session", "CSRF protection off", "Medium", 0.6, (352,),
      "State-changing requests can be forged from other sites.", "Keep protect_from_forgery with: :exception."),
    R("RB-HASH", "ruby", r"Digest::(MD5|SHA1)\b", "Weak digest", "Medium", 0.6, (327, 328), "Collision-broken.", "Digest::SHA256 / bcrypt for passwords.",
      sub(r"Digest::(MD5|SHA1)", "Digest::SHA256", "digest -> SHA256", TIER_PROPOSED, "Digest values change.")),

    # ── C# ─────────────────────────────────────────────────────────────────
    R("CS-DESER", "csharp", r"\b(BinaryFormatter|NetDataContractSerializer|SoapFormatter|LosFormatter|ObjectStateFormatter)\b", "Insecure .NET deserializer", "High", 0.85, (502,),
      "These formatters execute attacker-chosen types (BinaryFormatter is obsolete/unsafe).", "System.Text.Json or DataContractSerializer with known types."),
    R("CS-PROC", "csharp", r"Process\.Start\s*\([^;]*(\+|\$\")", "Process.Start with concatenated input", "High", 0.7, (78,),
      "Argument injection / command execution.", "ProcessStartInfo with ArgumentList and UseShellExecute=false."),
    R("CS-HASH", "csharp", r"\b(MD5|SHA1)(CryptoServiceProvider|Managed|\.Create)\b", "Weak hash", "Medium", 0.6, (327, 328), "Collision-broken.", "SHA256.Create(); Rfc2898DeriveBytes/Argon2 for passwords.",
      sub(r"\b(MD5|SHA1)(CryptoServiceProvider|Managed|\.Create)", "SHA256.Create", "hash -> SHA256", TIER_PROPOSED, "Digest values change.")),
    R("CS-SQLI", "csharp", r"new\s+(Sql|MySql|Npgsql|Oracle)Command\s*\(\s*(\$\"|\"[^\"]*\"\s*\+)", "SQL built by concatenation", "High", 0.85, (89,),
      "Input changes the query.", "cmd.Parameters.AddWithValue(\"@id\", id) with a constant query."),
    R("CS-TLS", "csharp", r"ServerCertificateValidationCallback\s*\+?=.*true|DangerousAcceptAnyServerCertificateValidator", "TLS validation disabled", "High", 0.9, (295,),
      "Accepts every certificate.", "Remove the callback."),
    R("CS-RANDOM", "csharp", rf"(?:{_SECWORDS}.*new\s+Random\s*\(|new\s+Random\s*\(.*{_SECWORDS})", "System.Random for a secret", "Medium", 0.7, (338,),
      "Predictable generator.", "RandomNumberGenerator.GetBytes()."),
    R("CS-RAW", "csharp", r"Html\.Raw\s*\(", "Html.Raw", "Medium", 0.6, (79,), "Bypasses encoding (XSS).", "@Model.Value (auto-encoded)."),
    R("CS-DTD", "csharp", r"DtdProcessing\s*=\s*DtdProcessing\.Parse", "DTD processing enabled (XXE)", "High", 0.85, (611,),
      "External entities can read files / call internal URLs.", "DtdProcessing.Prohibit.",
      sub(r"DtdProcessing\.Parse", "DtdProcessing.Prohibit", "DTD Parse -> Prohibit")),

    # ── Shell / PowerShell / Docker (shared) ───────────────────────────────
    R("SH-CURLBASH", "shell dockerfile makefile", r"\b(curl|wget)\b[^|\n;]*\|\s*(sudo\s+)?(ba|z|da)?sh\b", "Pipe-to-shell installer", "High", 0.85, (494,),
      "Runs whatever the server returns, unverified, with your privileges.",
      "Download to a file, verify a pinned checksum/signature, review, then run."),
    R("SH-EVAL", "shell", r"(?<![\w-])eval\s+[\"']?[^\n]*\$", "eval with variables", "High", 0.7, (78,), "Variable text becomes code.", "Avoid eval; use arrays and \"${arr[@]}\"."),
    R("SH-CHMOD", "shell dockerfile", r"\bchmod\s+(-R\s+)?0?777\b", "World-writable permissions", "Medium", 0.85, (732,), "Anyone can modify it.", "chmod 755 (dirs/executables) or 644 (files).",
      sub(r"\b0?777\b", "755", "777 -> 755", TIER_PROPOSED, "Other users lose write access.")),
    R("SH-RMVAR", "shell", r"\brm\s+-[a-zA-Z]*[rR][a-zA-Z]*\s+[\"']?\$\{?\w+\}?/?\*?[\"']?\s*($|;|&)", "rm -rf on an unchecked variable", "Medium", 0.6, (73,),
      "If the variable is empty the command becomes 'rm -rf /' or 'rm -rf *'.", "rm -rf -- \"${DIR:?must be set}\"/..."),
    R("SH-TMP", "shell", r">\s*/tmp/\w", "Predictable /tmp file", "Low", 0.6, (377,), "Symlink/race attacks on shared /tmp.", "tmp=$(mktemp) and trap 'rm -f \"$tmp\"' EXIT."),
    R("PS-IEX", "powershell", r"\b(Invoke-Expression|iex)\b", "Invoke-Expression", "High", 0.8, (95,), "Executes a string as PowerShell.", "Call the command directly with parameters."),
    R("DK-LATEST", "dockerfile", r"^\s*FROM\s+(\S+:latest|[^:@\s]+)(\s+AS\s+\w+)?\s*$", "Unpinned base image", "Low", 0.8, (1104,),
      "Builds are not reproducible and silently pick up changes / compromised tags.", "Pin a version tag, ideally a digest: FROM python:3.12-slim@sha256:...", cat="quality",
      unless=lambda l, m: bool(re.search(r"FROM\s+scratch|\$\{?\w+\}?", l, re.I))),
    R("DK-ADD", "dockerfile", r"^\s*ADD\s+https?://", "ADD from a remote URL", "Medium", 0.8, (494,), "Unverified remote content baked into the image.",
      "RUN curl -fsSLO <url> && echo '<sha256>  file' | sha256sum -c -"),

    # ── YAML (compose / Kubernetes / CI) and Terraform ─────────────────────
    R("YM-PRIV", "yaml", r"^\s*privileged\s*:\s*true|^\s*hostNetwork\s*:\s*true|^\s*hostPID\s*:\s*true", "Privileged container / host namespace", "High", 0.85, (250,),
      "A container escape gives full control of the host.", "Remove privileged/host* and grant only the capabilities required."),
    R("YM-ESC", "yaml", r"^\s*allowPrivilegeEscalation\s*:\s*true", "Privilege escalation allowed", "Medium", 0.85, (250,), "Processes can gain more privileges than their parent.",
      "allowPrivilegeEscalation: false", sub(r"true", "false", "allowPrivilegeEscalation: false")),
    R("YM-ROOT", "yaml", r"^\s*runAsUser\s*:\s*0\b|^\s*runAsNonRoot\s*:\s*false", "Container runs as root", "Medium", 0.8, (250,), "Root in the container widens every other flaw.",
      "runAsNonRoot: true with a non-zero runAsUser."),
    R("YM-LATEST", "yaml", r"^\s*-?\s*image\s*:\s*\S+:latest\s*$", "Image pinned to :latest", "Low", 0.8, (1104,), "Non-reproducible deployments.", "Pin a tag or digest.", cat="quality"),
    R("YM-CI-INJECT", "yaml", r"\$\{\{\s*github\.(event\.(issue|pull_request|comment|head_commit)\.[\w.]*(title|body|message|ref|name)|head_ref)\s*\}\}",
      "GitHub Actions script injection", "High", 0.7, (94,), "Attacker-controlled text interpolated into a run: step executes as shell.",
      "Pass it through an environment variable and quote it: env: TITLE: ${{ ... }} then \"$TITLE\"."),
    R("TF-OPEN", "terraform", r"cidr_blocks\s*=\s*\[\s*\"0\.0\.0\.0/0\"", "Open to the whole internet", "Medium", 0.7, (284,), "Any host can reach this port.", "Restrict to known CIDR ranges."),
    R("TF-PUBLIC", "terraform", r"acl\s*=\s*\"public-read(-write)?\"", "Public bucket ACL", "High", 0.9, (284,), "Anyone can read (or write) the bucket.", "acl = \"private\" and use signed URLs.",
      sub(r"\"public-read(-write)?\"", "\"private\"", "acl -> private", TIER_PROPOSED, "Public consumers lose access; use CloudFront/signed URLs.")),
    R("TF-ENC", "terraform", r"encrypted\s*=\s*false", "Storage encryption disabled", "Medium", 0.85, (311,), "Data at rest is readable if the disk/snapshot leaks.", "encrypted = true",
      sub(r"false", "true", "encrypted = true", TIER_PROPOSED, "Changing this may force resource replacement.")),
]


def _first_fix(lines: List[str], i: int, subs: Sequence[Tuple[str, str, str]]) -> Optional[Fix]:
    for pat, repl, desc in subs:
        new = re.sub(pat, repl, lines[i], count=1)
        if new != lines[i]:
            return Fix(desc, [Edit(i + 1, i + 1, [new])], TIER_AUTO)
    return None


def _gets_fix(lines: List[str], i: int) -> Optional[Fix]:
    m = re.search(r"(?<![\w.])gets\s*\(\s*(\w+)\s*\)", lines[i])
    if not m:
        return None
    buf = m.group(1)
    declared = any(re.search(rf"\bchar\s+{buf}\s*\[", l) for l in lines[:i + 1])
    if not declared:
        return None
    new = lines[i][:m.start()] + f"fgets({buf}, sizeof({buf}), stdin)" + lines[i][m.end():]
    return Fix("gets(buf) -> fgets(buf, sizeof(buf), stdin)", [Edit(i + 1, i + 1, [new])], TIER_PROPOSED,
               behavior_note="fgets keeps the trailing newline; strip it if the rest of the code assumes it is gone.")


_BY_LANG: Dict[str, List[Rule]] = {}
for _r in RULES:
    for _l in _r.langs:
        _BY_LANG.setdefault(_l, []).append(_r)


def supported_languages() -> List[str]:
    return sorted(_BY_LANG)


def scan_text(text: str, rel: str, lang: str, agent: str = "rules") -> List[Finding]:
    rules = _BY_LANG.get(lang)
    if not rules or not text:
        return []
    use_mask = lang not in _NO_MASK
    if use_mask:
        vtext, mask = code_view(text, lang, with_mask=True)
    else:
        vtext, mask = code_view(text, lang), None
    view = vtext.splitlines()
    lines = text.splitlines()
    offsets, pos = [], 0                                   # char offset of each line start in ``text``
    for ln in text.splitlines(keepends=True):
        offsets.append(pos)
        pos += len(ln)
    findings: List[Finding] = []
    counts: Dict[str, int] = {}
    for i, vline in enumerate(view):
        if not vline.strip() or len(vline) > 4000:                         # minified / generated lines
            continue
        for r in rules:
            if counts.get(r.id, 0) >= r.max_per_file:
                continue
            m = r.rx.search(vline)
            if not m:
                continue
            if mask is not None and not r.in_strings:
                at = offsets[i] + m.start()
                if at < len(mask) and mask[at]:
                    continue                                # the match begins inside a string literal
            if r.unless and r.unless(vline, m):
                continue
            fix = None
            if r.fix:
                try:
                    fix = r.fix(lines, i, m)
                except Exception:
                    fix = None
            counts[r.id] = counts.get(r.id, 0) + 1
            findings.append(Finding(
                file=rel, line=i + 1, column=m.start() + 1, language=lang, category=r.cat, rule_id=r.id,
                title=r.title, severity=r.sev, confidence=r.conf, message=r.why, recommendation=r.rec,
                cwe=r.cwe, snippet=lines[i].strip()[:200], agent=agent, fix=fix))
    return findings
