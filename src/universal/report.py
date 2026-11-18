"""report.py - REPORT.md, report.json, report.sarif, changes.patch, proposed.patch, QUARANTINE.md"""
from __future__ import annotations

import difflib
import json
from collections import Counter
from typing import Dict, List

from . import risk as RK
from .llm import redact_for_llm
from .core import SEV_RANK, Finding, safe, scrub

_ICON = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🔵", "Info": "⚪"}
_STATUS = {"fixed": "✅ fixed + verified", "proposed": "📝 proposed (needs review)", "open": "⚠️ open",
           "quarantined": "🚫 quarantined", "wontfix": "—"}


def udiff(rel: str, a: str, b: str) -> str:
    """Unified diff with credentials redacted: patches get attached to tickets / CI artifacts."""
    return redact_for_llm("".join(difflib.unified_diff(a.splitlines(True), b.splitlines(True), f"a/{safe(rel)}", f"b/{safe(rel)}", n=3)))


def changes_patch(ctx) -> str:
    out = []
    for rel in sorted(ctx.texts):
        if ctx.texts[rel] != ctx.orig.get(rel):
            out.append(udiff(rel, ctx.orig.get(rel, ""), ctx.texts[rel]))
    return "".join(out)


def proposed_patch(ctx) -> str:
    out = []
    for rel in sorted(ctx.proposed_text):
        out.append(udiff(rel, ctx.texts[rel], ctx.proposed_text[rel]))
    for p in ctx.llm_proposals:
        out.append(f"# LLM-authored proposal for {p['rule']} in {p['file']}: {p['explanation']}\n")
        out.append(udiff(p["file"], p["before"], p["after"]))
    return "".join(out)


def _sorted(fs: List[Finding]) -> List[Finding]:
    return sorted(fs, key=lambda f: (SEV_RANK.get(f.severity, 9), -f.risk, f.file, f.line))


def render_markdown(ctx) -> str:
    fs = [f for f in ctx.findings]
    langs = Counter(fi.language for fi in ctx.files.values() if fi.language)
    st = Counter(f.status for f in fs)
    cat = Counter(f.category for f in fs)
    L: List[str] = []
    a = L.append
    a(f"# Audit report: {ctx.name}\n")
    a("| | |\n|---|---|")
    a(f"| Files seen / analysed | {len(ctx.files)} / {len(ctx.texts) + len(ctx.quarantined)} |")
    a(f"| Languages | {', '.join(f'{k} ({v})' for k, v in langs.most_common()) or '-'} |")
    a(f"| **Risk before** | **{ctx.risk_before} / 100  (grade {RK.grade(ctx.risk_before)})** |")
    a(f"| **Risk after** (fresh re-scan of the output) | **{ctx.risk_after} / 100  (grade {RK.grade(ctx.risk_after)})** |")
    c = ctx.counts
    if c:
        a(f"| **Critical + High findings** | **{c['high_before']} before → {c['high_after']} after** (→ {c['high_if_proposed']} if proposed changes are accepted) |")
    if ctx.risk_if_proposed < ctx.risk_after:
        a(f"| Risk if the proposed changes are accepted | {ctx.risk_if_proposed} / 100  (grade {RK.grade(ctx.risk_if_proposed)}) |")
    a(f"| Findings | {len(fs)} total: {st.get('fixed', 0)} fixed, {st.get('proposed', 0)} proposed, {st.get('open', 0)} open, {st.get('quarantined', 0)} in quarantined files |")
    a(f"| By category | {', '.join(f'{k} {v}' for k, v in cat.most_common())} |")
    a(f"| Quarantined files | {len(ctx.quarantined)} |")
    if ctx.cpp:
        c = ctx.cpp
        a(f"| C++ engine | {c.get('sources', 0)} sources: compile {'OK' if c.get('compile_ok_after', c.get('compile_ok')) else 'FAILS'}, "
          f"link {'OK' if c.get('link_ok_after', c.get('link_ok')) else 'FAILS'} (before: compile {'OK' if c.get('compile_ok') else 'FAILS'}, link {'OK' if c.get('link_ok') else 'FAILS'}) |")
    ag = (ctx.cpp or {}).get("agentic")
    if ag:
        a(f"| C++ agent pipeline | verdict **{ag['verdict']}**: {ag['changes']} verified change(s), {ag['rejected']} rejected/rolled back |")
        d = ctx.cpp.get("dynamic")
        if d:
            a(f"| C++ sandboxed run | exit {d['exit']}, {d['sanitizer_reports']} sanitizer report(s), behaviour {'identical' if d['same_behaviour'] else 'changed'}; "
              f"{'private filesystem root' if d['confined'] else 'NO filesystem confinement (run trusted code only)'} |")
    a("")
    if ag and ctx.cpp.get("agentic_changes"):
        a("## C++ changes made by the agents (each rebuilt, relinked and re-audited by an independent Verifier)\n")
        for c in ctx.cpp["agentic_changes"][:60]:
            a(f"- `{c['file']}`:{c['line'] or '-'} **{c['agent']}** {c['title']} - {c['why']}" + (f" ({c['impact']})" if c.get("impact") else ""))
        a("")
    a("> **How to read this.** Every applied change passed the verification gate: the file still parses/compiles, the finding is gone, "
      "no new finding appeared, the module's public API is unchanged, malware score did not rise, and cross-file imports still resolve. "
      "Changes that may alter behaviour are NOT applied; they are in `proposed.patch`.\n")
    if ctx.quarantined:
        a("## 🚫 Quarantined (removed from the output; your upload is untouched)\n")
        a("These files matched malware behaviours. Do not run them. If you did not write them, treat the source as compromised and rotate credentials.\n")
        for rel, q in sorted(ctx.quarantined.items()):
            a(f"- `{safe(rel)}` — {safe(q['reason'])}  (sha256 `{q['sha256'][:16]}…`)")
        a("")
    ff = RK.fix_first([f for f in fs if f.status in ("open", "proposed")], 8)
    if ff:
        a("## Fix first\n")
        for i, f in enumerate(ff, 1):
            a(f"{i}. {_ICON[f.severity]} **{safe(f.title)}**: `{safe(f.file)}:{f.line}`  (risk {f.risk:.0f}, {_STATUS.get(f.status)})")
        a("")
    if ctx.applied:
        a("## Changes applied\n")
        for ap in ctx.applied:
            a(f"- `{ap['file']}`: {ap['what']}  — verified by *{ap['verified_by']}*" + ("  — **LLM-authored**" if ap.get("source") == "llm" else ""))
        a("")
    if ctx.proposed_text or ctx.llm_proposals:
        a("## Proposed changes (verified, but they change behaviour: review `proposed.patch`)\n")
        for rel in sorted(ctx.proposed_text):
            a(f"- `{safe(rel)}`")
        for p in ctx.llm_proposals:
            a(f"- `{p['file']}` ({p['rule']}): LLM proposal — {p['explanation']}")
        a("")
    if ctx.rejected:
        a("## Fixes the verifier rejected\n")
        for r in ctx.rejected:
            a(f"- `{r['file']}:{r['line']}` {r['rule']} ({r['source']}): {r['why']}")
        a("")
    if ctx.integrity:
        a("## Integration warnings\n")
        for w in ctx.integrity:
            a(f"- {w}")
        a("")
    a("## Findings by file\n")
    by: Dict[str, List[Finding]] = {}
    for f in fs:
        by.setdefault(f.file, []).append(f)
    scores = RK.per_file(fs)
    for rel in sorted(by, key=lambda r: -scores.get(r, 0)):
        a(f"### `{safe(rel)}`  — file risk {scores.get(rel, 0)}\n")
        for f in _sorted(by[rel]):
            cwe = (", " + ", ".join(f"CWE-{c}" for c in f.cwe)) if f.cwe else ""
            a(f"**{_ICON[f.severity]} {safe(f.title)}** `[{safe(f.rule_id)}]` line {f.line}  \n"
              f"{f.severity} · confidence {f.confidence:.0%} · risk {f.risk:.0f} · {f.category}{cwe} · {_STATUS.get(f.status, f.status)}  ")
            if f.snippet:
                a("```\n" + scrub(redact_for_llm(f.snippet)).replace("```", "'''") + "\n```")
            a(f"- **Why it matters:** {safe(f.message)}")
            a(f"- **Best replacement:** {f.recommendation}")
            if f.fix:
                a(f"- **Automatic fix:** {f.fix.description} ({f.fix.tier})" + (f" — *behaviour note:* {f.fix.behavior_note}" if f.fix.behavior_note else ""))
            if f.verified_by:
                a(f"- **Verified by:** {f.verified_by}")
            if f.fix_note:
                a(f"- **Note:** {f.fix_note}")
            a("")
    if ctx.notes or ctx.skipped:
        a("## Notes\n")
        for n in ctx.notes + ctx.skipped:
            a(f"- {n}")
        a("")
    a("## Limits (read before trusting)\n")
    a("- Nothing in your upload is ever executed; checks are static + parser/compiler based. Behavioural bugs and logic flaws are out of reach.\n"
      "- Languages without a parser here (Java, Go, Rust, PHP, Ruby, C#, ...) get pattern rules + bracket-balance checks only: fixes there are marked accordingly.\n"
      "- Malware triage is heuristic (behaviour indicators + entropy), not antivirus. No hit != safe; use ClamAV / your EDR for assurance.\n"
      "- No dependency CVE database is bundled (offline). Run `pip-audit`, `npm audit`, or `osv-scanner` on the output.\n"
      "- Python undefined-name and type errors are not detected; run your test-suite and `mypy`/`ruff` on the output.\n")
    return scrub("\n".join(L))


def render_json(ctx) -> str:
    fs = ctx.findings
    out = json.dumps({
        "name": ctx.name, "risk_before": ctx.risk_before, "risk_after": ctx.risk_after, "risk_if_proposed": ctx.risk_if_proposed, "counts": ctx.counts,
        "grade_before": RK.grade(ctx.risk_before), "grade_after": RK.grade(ctx.risk_after),
        "files": {r: {"language": f.language, "sha256": f.sha256, "size": f.size, "tests": f.is_test, "quarantined": f.quarantined}
                  for r, f in ctx.files.items()},
        "quarantined": ctx.quarantined, "applied": ctx.applied, "rejected": ctx.rejected, "integrity": ctx.integrity,
        "cpp": {k: v for k, v in ctx.cpp.items() if k != "heal_history"}, "notes": ctx.notes + ctx.skipped,
        "llm": {"requests": ctx.llm_calls, "proposals": [{k: v for k, v in p.items() if k not in ("before", "after")} for p in ctx.llm_proposals]},
        "findings": [f.to_dict() for f in _sorted(fs)],
        "remaining_after": [f.to_dict() for f in _sorted(ctx.findings_after)],
    }, indent=2, default=str)
    return redact_for_llm(out)


def render_sarif(ctx) -> str:
    level = {"Critical": "error", "High": "error", "Medium": "warning", "Low": "note", "Info": "note"}
    rules, seen = [], set()
    results = []
    for f in _sorted(ctx.findings_after or ctx.findings):
        if f.rule_id not in seen:
            seen.add(f.rule_id)
            rules.append({"id": f.rule_id, "name": f.rule_id, "shortDescription": {"text": f.title[:200]}, "fullDescription": {"text": f.message[:1000]},
                          "help": {"text": f.recommendation[:1000]},
                          "properties": {"tags": [f.category] + [f"CWE-{c}" for c in f.cwe], "security-severity": str(round(f.risk / 10, 1))}})
        results.append({"ruleId": f.rule_id, "level": level.get(f.severity, "note"),
                        "message": {"text": f"{f.title}. {f.recommendation}"[:1500]},
                        "locations": [{"physicalLocation": {"artifactLocation": {"uri": f.file}, "region": {"startLine": max(1, f.line)}}}],
                        "properties": {"risk": f.risk, "confidence": round(f.confidence, 2), "status": f.status}})
    return json.dumps({"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
                       "runs": [{"tool": {"driver": {"name": "cd1-universal", "version": "2.0.0", "rules": rules}}, "results": results}]}, indent=2)


def render_quarantine(ctx) -> str:
    L = ["# Quarantine log\n", "Files removed from the secured output. They are NOT deleted from your original upload.\n"]
    for rel, q in sorted(ctx.quarantined.items()):
        L.append(f"## `{safe(rel)}`\n- reason: {safe(q['reason'])}\n- sha256: `{q['sha256']}`\n- size: {q['size']} bytes\n- indicators: {', '.join(q['indicators']) or '-'}\n")
    return scrub("\n".join(L))
