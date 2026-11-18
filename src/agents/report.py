"""Reporter agent - writes the final file / zip / folder, a patch, and a human-readable report."""
import json
import os
import re
from typing import Dict, List, Optional

import project as P
from secure_fixer import unified_diff

LIMITS = [
    "The Sentinel is a heuristic indicator scanner, not an antivirus: a CLEAN verdict means no known suspicious "
    "patterns were found, not that the code is proven harmless.",
    "The safety gate and the sandbox are best-effort defences. Untrusted code should still be run in a container or VM.",
    "Optimisations are limited to a small catalogue of transformations with stated preconditions; they are verified "
    "by compiling and linking, and by comparing behaviour only when --run is used.",
    "Rule-based repair fixes common syntax-level errors only. Logic errors, missing definitions and design problems "
    "are reported and explained but never guessed at.",
    "No CMake / Makefile parsing: all .cpp files are compiled with the same flags (use --cxxflags / --link-flags).",
]


def _sev_counts(findings) -> Dict[str, int]:
    c = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for f in findings:
        c[f.severity] = c.get(f.severity, 0) + 1
    return c


def summary(res) -> dict:
    b = res.baseline
    a = res.after
    return {
        "project": res.proj.name,
        "verdict": res.verdict,
        "sentinel": res.board.facts["sentinel0"].verdict,
        "files_changed": sorted(res.final_changed),
        "before": None if b is None else {
            "errors": b.error_count, "link_errors": len(b.link_errors), "built": b.built,
            "security_findings": len(b.security_findings), "risk": b.risk,
            "optimisation_advice": len(b.optimization_findings)},
        "after": None if a is None else {
            "errors": a.error_count, "link_errors": len(a.link_errors), "built": a.built,
            "security_findings": len(a.security_findings), "risk": a.risk,
            "optimisation_advice": len(a.optimization_findings)},
        "verified_stage": res.board.facts.get("verified_stage"),
    }


def to_dict(res) -> dict:
    d = summary(res)
    d["changes"] = [vars(c) for c in res.board.changes]
    d["rejected"] = [vars(c) for c in res.board.rejected]
    d["trace"] = [vars(t) for t in res.board.trace]
    sen = res.board.facts["sentinel0"]
    d["sentinel_report"] = {"score": sen.score, "indicators": [vars(i) for i in sen.indicators],
                            "quarantined": sen.quarantined, "gate_blocked": sen.gate_blocked}
    dyn = res.board.facts.get("dynamic")
    if dyn:
        d["dynamic"] = {k: (vars(v) if hasattr(v, "__dict__") else v) for k, v in dyn.items()}
    return d


def _trunc(s: str, n: int = 160) -> str:
    s = " ".join((s or "").split())
    return s if len(s) <= n else s[:n - 1] + "…"


def render_markdown(res) -> str:
    b, a, board = res.baseline, res.after, res.board
    sen = board.facts["sentinel0"]
    L: List[str] = []
    w = L.append
    w(f"# Agentic analysis report: {res.proj.name}\n")
    icon = {"VERIFIED": "VERIFIED", "UNCHANGED": "NO CHANGES NEEDED", "PARTIAL": "PARTIALLY IMPROVED",
            "BLOCKED": "BLOCKED"}[res.verdict]
    w(f"**Result: {icon}** · Sentinel: **{sen.verdict}** (score {sen.score}) · "
      f"files changed: **{len(res.final_changed)}**\n")
    if res.verdict == "BLOCKED":
        w(f"> {board.facts['halt']}\n")
    if b is not None and a is not None:
        w("## Before → after\n")
        w("| | Before | After |\n|---|---|---|")
        w(f"| Builds and links | {'yes' if b.built else 'no'} | {'yes' if a.built else 'no'} |")
        w(f"| Compile errors | {b.error_count} | {a.error_count} |")
        w(f"| Link errors | {len(b.link_errors)} | {len(a.link_errors)} |")
        w(f"| Security findings | {len(b.security_findings)} | {len(a.security_findings)} |")
        w(f"| Risk score | {b.risk} | {a.risk} |")
        w(f"| Optimisation advice still open | {len(b.optimization_findings)} | {len(a.optimization_findings)} |\n")
    det = board.facts.get("detected_flags")
    if det and (det.cxxflags or det.link_flags or det.ignored):
        w(f"Build flags read from {', '.join(det.sources)}: `{' '.join(det.cxxflags + det.link_flags)}`"
          + (f" (rejected as unsafe: `{' '.join(det.ignored)}`)" if det.ignored else "") + "\n")
    w("## What each agent did\n")
    w("| t (s) | Agent | Action | Detail |\n|---|---|---|---|")
    for t in board.trace:
        mark = "" if t.ok is None else (" ✔" if t.ok else " ✖")
        w(f"| {t.t} | {t.agent} | {t.action}{mark} | {_trunc(t.detail, 140)} |")
    w("")
    if b is not None and b.unique_errors():
        w("## Errors detected, classified and explained\n")
        fixed_at = {(c.file, c.line) for c in board.changes if c.agent == "Repairer"}
        for e in b.unique_errors()[:40]:
            if e.error_type != "error":
                continue
            rel = e.file
            status = "fixed" if (rel, e.line) in fixed_at else ("fixed" if a is not None and a.compile_ok and b.compile_ok is False else "needs attention")
            w(f"- **{rel}:{e.line}** `{_trunc(e.message, 100)}` — category **{e.category}** ({status})")
            if e.explanation:
                w(f"  - Why: {_trunc(e.explanation, 300)}")
            if e.suggestion:
                w(f"  - Fix: {_trunc(e.suggestion, 300)}")
        w("")
    if board.changes:
        w("## Changes applied (each one verified)\n")
        by_file: Dict[str, list] = {}
        for c in board.changes:
            by_file.setdefault(c.file, []).append(c)
        for f, cs in by_file.items():
            w(f"### {f}\n")
            for c in cs:
                loc = f"line {c.line}" if c.line else "file"
                w(f"- **[{c.agent} · {c.rule}]** {c.title} ({loc})")
                w(f"  - Why: {_trunc(c.why, 400)}")
                if c.impact:
                    w(f"  - Impact: {c.impact}")
                if c.before and c.after and len(c.before) < 200 and len(c.after) < 200:
                    w(f"  - Before: `{_trunc(c.before, 150)}`  \n  - After: `{_trunc(c.after, 150)}`")
            w("")
    if board.rejected:
        w("## Proposals rejected (not applied)\n")
        for c in board.rejected:
            w(f"- {c.agent} {c.rule} {c.file}{':' + str(c.line) if c.line else ''}: {c.title} — {_trunc(c.why, 200)}")
        w("")
    if a is not None:
        left = [e for e in a.unique_errors() if e.error_type == "error"]
        if left or a.link_errors:
            w("## Still needs a human\n")
            for e in left[:30] + a.link_errors[:10]:
                w(f"- **{e.file}:{e.line}** `{_trunc(e.message, 110)}` ({e.category})")
                if e.explanation:
                    w(f"  - {_trunc(e.explanation, 300)}")
            w("")
        if a.security_findings:
            w("## Security findings that remain\n")
            for f in a.security_findings[:40]:
                w(f"- **{f.severity}** {f.file}:{f.line} {f.vulnerability_type} "
                  f"({', '.join('CWE-%s' % c for c in f.cwe)}) — {_trunc(f.recommendation, 220)}")
            w("")
        if a.optimization_findings:
            w("## Optimisation advice not auto-applied\n")
            for o in a.optimization_findings[:25]:
                w(f"- **{o.impact}** {o.file}:{o.line} {o.description} → {_trunc(o.suggestion, 200)}")
            w("")
    w("## Malware / supply-chain scan\n")
    if sen.indicators:
        for i in sen.indicators[:30]:
            w(f"- `{i.rule}` {i.file}:{i.line} (weight {i.weight}) {i.message}")
    else:
        w("No indicators found.")
    for rel, why in sen.quarantined:
        w(f"- **Quarantined (removed from the output):** `{rel}` — {why}")
    w("")
    w("## Testing evidence\n")
    w(f"- Static verification passed at stage **{board.facts.get('verified_stage')}**: from-scratch compile of every "
      "file, whole-project link, no new security findings, no new sentinel indicators.")
    dyn = board.facts.get("dynamic")
    if dyn is None:
        w("- Dynamic testing was not requested (`--run`). Behaviour equivalence of optimisations is therefore "
          "**not** tested by execution.")
    elif not dyn.get("ran"):
        w(f"- Dynamic testing: {dyn.get('note')}")
    else:
        r0, r1 = dyn.get("original"), dyn.get("final")
        w(f"- Sandboxed run with AddressSanitizer + UBSanitizer: exit code {r1.rc}, "
          f"{len(r1.sanitizer)} sanitizer report(s). Isolation: no network, "
          + ("private filesystem root (host files not visible)." if getattr(r1, "confined", False)
             else "NO filesystem confinement was available on this machine - the program could touch host files; run only trusted code.")
          + " A matching result means the behaviour is unchanged, not that the program is safe.")
        if r0 is not None:
            if dyn["same"]:
                w("- Original vs final: stdout and exit code identical.")
            elif dyn.get("original_bad"):
                w(f"- The ORIGINAL crashed or tripped sanitizers ({len(r0.sanitizer)} report(s), exit {r0.rc}); the final "
                  f"version has {len(r1.sanitizer)} (exit {r1.rc}). The behaviour change is the fix.")
            else:
                w("- Original vs final: behaviour DIFFERS (changes were rolled back).")
        else:
            w("- No baseline run to compare with (the original did not build).")
        if dyn.get("time_before") and dyn.get("time_after"):
            w(f"- Measured (-O2, best of 3): {dyn['time_before']}s → {dyn['time_after']}s.")
        for s in r1.sanitizer:
            w(f"  - {s}")
    w("")
    w("## Limits\n")
    for l in LIMITS:
        w(f"- {l}")
    return "\n".join(L) + "\n"


def patch_text(res) -> str:
    return "".join(unified_diff(o, n, rel, "agentic") for rel, (o, n) in sorted(res.final_changed.items()))


def write_outputs(res, out: Optional[str] = None, in_place: bool = False) -> Dict[str, str]:
    """returns {'final': path, 'patch': path, 'report': path, 'json': path}"""
    proj = res.proj
    written: Dict[str, str] = {}
    if res.verdict == "BLOCKED":
        base = out or P.default_output(proj, "blocked")
        rep = re.sub(r"\.zip$", "", base)
        written["report"] = rep + ".report.md"
        with open(written["report"], "w", encoding="utf-8") as f:
            f.write(render_markdown(res))
        return written
    if res.final_changed or out:
        if in_place:
            P.write_in_place(proj, res.final_changed)
            written["final"] = proj.origin
        else:
            dest = out or P.default_output(proj, "final")
            written["final"] = _write_final(proj, dest)
    stem = re.sub(r"\.zip$", "", written.get("final") or P.default_output(proj, "final"))
    if res.final_changed:
        written["patch"] = stem + ".patch"
        with open(written["patch"], "w", encoding="utf-8") as f:
            f.write(patch_text(res))
    written["report"] = stem + ".report.md"
    with open(written["report"], "w", encoding="utf-8") as f:
        f.write(render_markdown(res))
    written["json"] = stem + ".agentic.json"
    with open(written["json"], "w", encoding="utf-8") as f:
        json.dump(to_dict(res), f, indent=2, default=str)
    return written


def _write_final(proj, dest: str) -> str:
    if proj.kind == "file":
        rel = proj.sources[0] if proj.sources else proj.all_code[0]
        dest = os.path.abspath(dest)
        with open(dest, "w", encoding="utf-8", newline="") as f:
            f.write(proj.read(rel))
        return dest
    return P.write_output(proj, dest)
