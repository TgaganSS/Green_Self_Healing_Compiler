"""Shared data model: findings, fixes, edits, trace log."""
from __future__ import annotations
import re

import hashlib
import json
import threading
import time
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Tuple

SEVERITIES = ("Critical", "High", "Medium", "Low", "Info")
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}          # lower = worse
SEV_BASE = {"Critical": 90.0, "High": 65.0, "Medium": 35.0, "Low": 12.0, "Info": 3.0}

# categories: error | security | secret | malware | quality | performance
TIER_AUTO = "auto"            # strictly safer / semantics-preserving: applied after verification
TIER_PROPOSED = "proposed"    # may change behaviour: written to proposed.patch for a human to accept
TIER_NONE = "advice"          # no safe mechanical fix: explanation only


@dataclass
class Edit:
    """Replace lines [start, end] (1-based, inclusive) by ``new_lines``.  end == start-1 inserts before ``start``."""
    start: int
    end: int
    new_lines: List[str]


@dataclass
class Fix:
    description: str
    edits: List[Edit]
    tier: str = TIER_AUTO
    source: str = "rule"              # rule | llm
    behavior_note: str = ""           # what could change for callers (shown for proposed fixes)

    def span(self) -> Tuple[int, int]:
        return (min(e.start for e in self.edits), max(max(e.end, e.start) for e in self.edits))


@dataclass
class Finding:
    file: str
    line: int
    language: str
    category: str
    rule_id: str
    title: str
    severity: str
    confidence: float                 # 0..1
    message: str                      # why this is a problem
    recommendation: str               # the best replacement, in words
    cwe: Tuple[int, ...] = ()
    snippet: str = ""
    column: int = 0
    agent: str = ""
    risk: float = 0.0                 # filled by the risk agent (0..100)
    fix: Optional[Fix] = None
    status: str = "open"              # open | fixed | proposed | quarantined | wontfix
    verified_by: str = ""             # how the fix was verified
    fix_note: str = ""                # why a fix was rejected / rolled back

    @property
    def id(self) -> str:
        raw = f"{self.file}|{self.rule_id}|{self.line}|{self.snippet.strip()}".encode("utf-8", "replace")
        h = hashlib.sha256(raw).hexdigest()
        return h[:10]

    def to_dict(self) -> dict:
        d = asdict(self)
        d["id"] = self.id
        d["cwe"] = [f"CWE-{c}" for c in self.cwe]
        d["confidence"] = round(self.confidence, 2)
        d["risk"] = round(self.risk, 1)
        if self.fix:
            d["fix"] = {"description": self.fix.description, "tier": self.fix.tier, "source": self.fix.source,
                        "behavior_note": self.fix.behavior_note,
                        "edits": [asdict(e) for e in self.fix.edits]}
        return d


def pysrc(text: str):
    """What to hand to compile()/ast.parse(): the original BYTES when the text carries undecodable bytes (read with
    surrogateescape), so Python applies its own encoding rules (coding cookies, utf-8 validity)."""
    if text.startswith("\ufeff"):                 # a UTF-8 BOM is legal in Python source; compile() of str would reject it
        text = text[1:]
    try:
        text.encode("utf-8")
        return text
    except UnicodeEncodeError:
        return text.encode("utf-8", "surrogateescape")


def apply_edits(text: str, edits: List[Edit]) -> str:
    """Apply non-overlapping line edits bottom-up so earlier line numbers stay valid."""
    nl = "\r\n" if "\r\n" in text else "\n"
    trailing = text.endswith(("\n", "\r\n"))
    lines = text.splitlines()
    for e in sorted(edits, key=lambda e: (e.start, e.end), reverse=True):
        lo = max(0, e.start - 1)
        hi = max(lo, e.end)                      # python slice end (exclusive) == 1-based inclusive end
        lines[lo:hi] = list(e.new_lines)
    out = nl.join(lines)
    return out + nl if trailing else out


def edits_overlap(a: Edit, b: Edit) -> bool:
    a_lo, a_hi = a.start, max(a.end, a.start - 1)
    b_lo, b_hi = b.start, max(b.end, b.start - 1)
    if a.end < a.start and b.end < b.start:                     # two pure insertions at one spot
        return a.start == b.start
    return not (a_hi < b_lo or b_hi < a_lo)


class Trace:
    """Thread-safe audit trail of what every agent did (written to trace.jsonl)."""

    def __init__(self):
        self._lock = threading.Lock()
        self.events: List[dict] = []
        self._t0 = time.time()

    def log(self, agent: str, event: str, **data) -> None:
        with self._lock:
            self.events.append({"t": round(time.time() - self._t0, 3), "agent": agent, "event": event, **data})

    def jsonl(self) -> str:
        return "\n".join(json.dumps(e, default=str) for e in self.events) + "\n"


@dataclass
class FileInfo:
    rel: str
    language: str                     # "" for binary / unknown
    size: int
    sha256: str
    is_binary: bool = False
    is_test: bool = False
    exposed: bool = False             # looks network-facing (web framework / server socket)
    quarantined: bool = False
    quarantine_reason: str = ""
    notes: List[str] = field(default_factory=list)


_CTRL = re.compile("[\x00-\x1f\x7f-\x9f\u2028\u2029\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]")


def safe(s: object) -> str:
    """Make an untrusted string (file name, title, code snippet) safe to print or embed in Markdown: control characters
    (newline, ESC, bidi overrides ...) become visible escapes and markdown/HTML metacharacters are neutralised."""
    t = _CTRL.sub(lambda m: "\\x%02x" % ord(m.group(0)) if ord(m.group(0)) < 256 else "\\u%04x" % ord(m.group(0)), str(s))
    return t.replace("`", "'").replace("<", "\u2039").replace(">", "\u203a").replace("[", "(").replace("]", ")")


def scrub(s: str) -> str:
    """Escape control characters (except newline and tab) in a whole text; used on text that embeds code snippets."""
    return re.sub("[\x00-\x08\x0b-\x1f\x7f-\x9f\u202a-\u202e\u2066-\u2069]", lambda m: "\\x%02x" % ord(m.group(0)) if ord(m.group(0)) < 256 else "\\u%04x" % ord(m.group(0)), s)
