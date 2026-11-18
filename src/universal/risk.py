"""
risk.py - transparent risk scoring (0-100).

finding risk   = severity_base x confidence x context
                 context: x1.25 network-facing file, x0.35 tests/examples/docs, x1.5 malware category, x0.9 already fixed-by-rule
file / project = noisy-OR of finding risks:  100 * (1 - prod(1 - r_i/100))   (many Lows never outrank one Critical)
grade          = A (<10) B (<25) C (<50) D (<75) F
priority       = risk / effort, where effort is 1 for auto fixes, 2 for proposed, 4 for advice-only (fix-first list)
"""
from __future__ import annotations

from typing import Dict, Iterable, List

from .core import FileInfo, Finding, SEV_BASE, TIER_AUTO, TIER_PROPOSED


def finding_risk(f: Finding, fi: FileInfo = None) -> float:
    r = SEV_BASE.get(f.severity, 3.0) * max(0.05, min(1.0, f.confidence))
    if fi is not None:
        if fi.is_test:
            r *= 0.35
        elif fi.exposed:
            r *= 1.25
    if f.category == "malware":
        r *= 1.5
    return min(100.0, r)


def combine(risks: Iterable[float]) -> float:
    p = 1.0
    for r in risks:
        p *= 1.0 - min(100.0, max(0.0, r)) / 100.0
    return round(100.0 * (1.0 - p), 1)


def grade(score: float) -> str:
    return "A" if score < 10 else "B" if score < 25 else "C" if score < 50 else "D" if score < 75 else "F"


def score_all(findings: List[Finding], files: Dict[str, FileInfo]) -> None:
    for f in findings:
        f.risk = finding_risk(f, files.get(f.file))


def open_findings(findings: List[Finding]) -> List[Finding]:
    return [f for f in findings if f.status in ("open", "proposed")]


def project_score(findings: List[Finding]) -> float:
    return combine(f.risk for f in findings if f.category != "quality" or f.severity in ("High", "Critical"))


def per_file(findings: List[Finding]) -> Dict[str, float]:
    by: Dict[str, List[float]] = {}
    for f in findings:
        by.setdefault(f.file, []).append(f.risk)
    return {k: combine(v) for k, v in by.items()}


def fix_first(findings: List[Finding], n: int = 10) -> List[Finding]:
    def eff(f):
        if f.fix is None:
            return 4.0
        return 1.0 if f.fix.tier == TIER_AUTO else 2.0
    live = [f for f in findings if f.status in ("open", "proposed")]
    return sorted(live, key=lambda f: -(f.risk / eff(f)))[:n]
