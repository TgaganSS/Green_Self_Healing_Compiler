"""secrets.py - hard-coded credential detection (patterns + entropy), with redaction and env-var fixes."""
from __future__ import annotations

import math
import re
from typing import List, Optional

from .core import Edit, Finding, Fix, TIER_PROPOSED
from .rules import py_import_edit

# (id, title, regex, severity, confidence)
TOKEN_PATTERNS = [
    ("SEC-AWS-KEY", "AWS access key id", r"\b(AKIA|ASIA)[0-9A-Z]{16}\b", "Critical", 0.95),
    ("SEC-PRIVKEY", "Private key material", r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----", "Critical", 0.98),
    ("SEC-GITHUB", "GitHub token", r"\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b|\bgithub_pat_[A-Za-z0-9_]{50,}\b", "Critical", 0.95),
    ("SEC-SLACK", "Slack token", r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b", "High", 0.9),
    ("SEC-GOOGLE", "Google API key", r"\bAIza[0-9A-Za-z_\-]{35}\b", "High", 0.9),
    ("SEC-STRIPE", "Stripe live key", r"\b(sk|rk)_live_[0-9A-Za-z]{20,}\b", "Critical", 0.95),
    ("SEC-ANTHROPIC", "Anthropic API key", r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b", "Critical", 0.95),
    ("SEC-OPENAI", "OpenAI-style API key", r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{32,}\b", "High", 0.8),
    ("SEC-JWT", "JSON Web Token", r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b", "Medium", 0.7),
    ("SEC-URLCRED", "Credentials embedded in a URL", r"\b[a-z][a-z0-9+.\-]{2,12}://[^\s:/@\"']{2,}:[^\s:/@\"']{4,}@[\w.\-]+", "High", 0.8),
    ("SEC-WEBHOOK", "Chat webhook URL", r"https://hooks\.slack\.com/services/[A-Z0-9/]{20,}|https://discord(?:app)?\.com/api/webhooks/\d+/[\w-]+", "High", 0.9),
]
_GENERIC = re.compile(
    r"""(?ix)\b(?P<name>[\w.\-]*?(?:pass(?:word|wd)?|pwd|secret|token|api[_\-]?key|access[_\-]?key|private[_\-]?key|"""
    r"""client[_\-]?secret|auth[_\-]?key|credential)s?[\w.\-]*)["']?\s*[:=]\s*(?P<q>["'])(?P<val>[^"'\s]{8,})(?P=q)""")
_PLACEHOLDER = re.compile(r"(?i)^(change.?me|your[_\-]|<.*>|\$\{.*\}|\{\{.*\}\}|%\(.*\)s|xxx+|\*{3,}|example|sample|dummy|"
                          r"placeholder|todo|fixme|none|null|true|false|test|password|secret|token|insert|replace|"
                          r"enter|my[_\-]?(secret|pass|key|token)|env|os\.|process\.|getenv)")
_ENV_REF = re.compile(r"(?i)(os\.environ|getenv|process\.env|ENV\[|System\.getenv|Environment\.GetEnvironmentVariable|\$\{?[A-Z_]+)")


def shannon(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in freq.values())


def redact(value: str) -> str:
    """Never echo a credential back in a report: keep a short non-reversible hint."""
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:3]}…{value[-2:]} ({len(value)} chars)"


def _env_expr(lang: str, name: str) -> Optional[str]:
    return {"python": f'os.environ["{name}"]', "javascript": f"process.env.{name}", "typescript": f"process.env.{name}",
            "java": f'System.getenv("{name}")', "kotlin": f'System.getenv("{name}")', "go": f'os.Getenv("{name}")',
            "php": f"getenv('{name}')", "ruby": f"ENV['{name}']", "csharp": f'Environment.GetEnvironmentVariable("{name}")',
            }.get(lang)


def _fix_for(lines: List[str], i: int, lang: str, name: str, val: str) -> Optional[Fix]:
    env = _env_expr(lang, re.sub(r"[^A-Za-z0-9]+", "_", name).strip("_").upper() or "SECRET")
    if not env:
        return None
    line = lines[i]
    new = re.sub(r"""(["'])""" + re.escape(val) + r"""\1""", lambda m: env, line, count=1)
    if new == line:
        return None
    edits = [Edit(i + 1, i + 1, [new])]
    if lang == "python":
        imp = py_import_edit(lines, "os")
        if imp:
            edits.append(imp)
    return Fix(f"Read the value from the environment ({env}) instead of the source file", edits, TIER_PROPOSED,
               behavior_note="The program now fails at runtime if that environment variable is not set. "
                             "The old secret stays in git history: ROTATE it.")


def scan_secrets(text: str, rel: str, lang: str) -> List[Finding]:
    if not text or len(text) > 3_000_000:
        return []
    lines = text.splitlines()
    out: List[Finding] = []
    seen = set()
    for i, line in enumerate(lines):
        if len(line) > 2000:
            continue
        for rid, title, rx, sev, conf in TOKEN_PATTERNS:
            m = re.search(rx, line)
            if not m or (i, rid) in seen:
                continue
            seen.add((i, rid))
            seen.add((i, "SEC-GENERIC"))                       # the specific pattern wins over the generic one
            fx = None
            am = re.search(r"""(?P<name>[\w.\-]+)["']?\s*[:=]\s*(?P<q>["'])(?P<val>[^"']*""" + re.escape(m.group(0)) + r"""[^"']*)(?P=q)""", line)
            if am and rid != "SEC-PRIVKEY":
                fx = _fix_for(lines, i, lang, am.group("name"), am.group("val"))
            out.append(Finding(
                file=rel, line=i + 1, column=m.start() + 1, language=lang, category="secret", rule_id=rid,
                title=title, severity=sev, confidence=conf, cwe=(798, 321 if rid == "SEC-PRIVKEY" else 798),
                message="A credential is committed in source code. Anyone with read access to the repo, a backup, or a "
                        "leaked zip can use it, and deleting the line does not remove it from history.",
                recommendation="Revoke/rotate it NOW, load the replacement from an environment variable or a secret "
                               "manager (Vault, AWS Secrets Manager, GitHub Actions secrets), and add the file to .gitignore if it is a key file.",
                snippet=line.strip().replace(m.group(0), redact(m.group(0)))[:160], agent="secrets", fix=fx))
        g = _GENERIC.search(line)
        if g and (i, "SEC-GENERIC") not in seen:
            val = g.group("val")
            if _PLACEHOLDER.match(val) or _ENV_REF.search(val) or len(set(val)) < 4:
                continue
            if re.search(r"(?i)(is_|has_|_type|_name|_url|_path|_file|_field|_len|_label|_id\b)", g.group("name")):
                continue
            ent = shannon(val)
            if ent < 2.5 and not re.search(r"\d", val):
                continue
            seen.add((i, "SEC-GENERIC"))
            conf = 0.85 if ent >= 3.5 else 0.6
            out.append(Finding(
                file=rel, line=i + 1, column=g.start() + 1, language=lang, category="secret", rule_id="SEC-GENERIC",
                title="Hard-coded password / secret / token", severity="High", confidence=conf, cwe=(798, 259),
                message=f"'{g.group('name')}' is assigned a literal value ({redact(val)}). Source code is copied, "
                        "zipped, emailed and cloned; secrets in it should be assumed leaked.",
                recommendation="Move it to configuration outside the repository (environment variable / secret manager) "
                               "and rotate it.",
                snippet=line.strip().replace(val, redact(val))[:160], agent="secrets",
                fix=_fix_for(lines, i, lang, g.group("name"), val)))
    return out
