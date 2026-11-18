#!/usr/bin/env python3
"""
audit.py - multi-language, multi-agent audit / repair CLI.

    python3 src/audit.py project.zip                       # -> project.secured.zip (+ _cd1_report/ inside)
    python3 src/audit.py app.py                            # -> app.secured.py  + app.secured.REPORT.md ...
    python3 src/audit.py ./repo --out repo_fixed.zip --apply-proposed
    python3 src/audit.py repo.zip --llm anthropic          # optional LLM proposals (verified by the same gate)
    python3 src/audit.py repo.zip --report-only            # analyse, never change anything
    python3 src/audit.py repo.zip --fail-on high           # CI: exit 2 if anything >= high remains
"""
import argparse
import os
import shlex
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from universal.core import safe as _safe
from universal import risk as RK                       # noqa: E402
from universal.agents import Options                   # noqa: E402
from universal.core import SEV_RANK                    # noqa: E402
from universal.engine import run_audit                 # noqa: E402
from universal.llm import LLMError, get_provider       # noqa: E402

BOLD, RESET, DIM = "\033[1m", "\033[0m", "\033[2m"


def parse(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("input", help="a file, a folder, a .zip or a .tar.gz (any mix of languages)")
    p.add_argument("--out", help="where to write the secured result (.zip or folder, or a file for single-file input)")
    p.add_argument("--report-only", action="store_true", help="analyse and report; change nothing")
    p.add_argument("--apply-proposed", action="store_true", help="also apply verified fixes that change behaviour")
    p.add_argument("--llm", default="none", metavar="PROVIDER", help="none (default) | anthropic | openai | auto. Sends redacted code snippets to that service.")
    p.add_argument("--apply-llm", action="store_true", help="apply verified LLM-authored fixes (default: only write them to proposed.patch)")
    p.add_argument("--llm-budget", type=int, default=20, help="max LLM requests per run (default 20)")
    p.add_argument("--no-optimize", action="store_true", help="C++: skip the Optimizer agent")
    p.add_argument("--run", action="store_true", help="C++: also build with sanitizers and EXECUTE in a sandbox (opt-in; needs a CLEAN malware verdict)")
    p.add_argument("--no-cpp", action="store_true", help="skip the g++ based C++ engine")
    p.add_argument("--exclude", action="append", default=[], metavar="GLOB")
    p.add_argument("--cxxflags", default="")
    p.add_argument("--link-flags", default="")
    p.add_argument("--jobs", type=int, default=4)
    p.add_argument("--min-confidence", type=float, default=0.5, help="minimum rule confidence for an automatic fix (default 0.5)")
    p.add_argument("--keep-quarantined", action="store_true", help="do NOT remove files judged malicious from the output")
    p.add_argument("--fail-on", choices=("low", "medium", "high", "critical"), help="exit 2 if findings >= level remain in the output")
    p.add_argument("--format", choices=("text", "json", "sarif"), default="text", help="what to print on stdout")
    p.add_argument("-q", "--quiet", action="store_true")
    return p.parse_args(argv)


def main(argv=None) -> int:
    a = parse(argv)
    try:
        prov = get_provider(a.llm)
    except LLMError as e:
        print(f"error: {e}", file=sys.stderr)
        return 64
    if a.llm != "none" and not prov.available():
        print(f"error: --llm {a.llm} needs credentials (ANTHROPIC_API_KEY, or CD1_LLM_API_KEY/OPENAI_API_KEY, or a local CD1_LLM_BASE_URL).", file=sys.stderr)
        return 64
    o = Options(out=a.out, fix=not a.report_only, apply_proposed=a.apply_proposed, apply_llm=a.apply_llm, llm=prov, llm_budget=a.llm_budget,
                exclude=a.exclude, cxxflags=shlex.split(a.cxxflags), link_flags=shlex.split(a.link_flags), jobs=a.jobs,
                cpp_optimize=not a.no_optimize, run=a.run, min_conf=a.min_confidence, keep_quarantined=a.keep_quarantined, cpp=not a.no_cpp)
    try:
        ctx = run_audit(a.input, o)
    except Exception as e:                       # ProjectError (bad zip, zip bomb, ...) and I/O problems
        print(f"error: {e}", file=sys.stderr)
        return 1
    if a.format == "json":
        from universal.report import render_json
        print(render_json(ctx))
    elif a.format == "sarif":
        from universal.report import render_sarif
        print(render_sarif(ctx))
    elif not a.quiet:
        summary(ctx, a)
    if a.fail_on:
        thr = SEV_RANK[a.fail_on.capitalize()]
        if any(SEV_RANK.get(f.severity, 9) <= thr for f in ctx.findings_after if f.category != "quality" or f.severity in ("High", "Critical")):
            return 2
    return 0


def summary(ctx, a) -> None:
    fs = ctx.findings
    n = lambda s: sum(1 for f in fs if f.status == s)
    print(f"\n{BOLD}Audit of {_safe(ctx.name)}{RESET}   {len(ctx.files)} files, {len(ctx.texts) + len(ctx.quarantined)} analysed")
    print(f"  risk  {RK.grade(ctx.risk_before)} {ctx.risk_before:>5} → {BOLD}{RK.grade(ctx.risk_after)} {ctx.risk_after:>5}{RESET}   (0 = clean, 100 = critical)")
    if ctx.counts:
        k = ctx.counts
        print(f"  Critical+High  {k['high_before']} → {BOLD}{k['high_after']}{RESET}  (→ {k['high_if_proposed']} if proposed changes are accepted: --apply-proposed)")
    print(f"  findings {len(fs)}:  ✅ {n('fixed')} fixed   📝 {n('proposed')} proposed   ⚠️  {n('open')} open   🚫 {len(ctx.quarantined)} quarantined file(s)")
    for rel, q in sorted(ctx.quarantined.items()):
        print(f"    {BOLD}QUARANTINED{RESET} {_safe(rel)}: {_safe(q['reason'])}")
    top = RK.fix_first([f for f in fs if f.status in ("open", "proposed")], 5)
    if top:
        print(f"{BOLD}  fix first{RESET}")
        for f in top:
            print(f"    [{f.severity:8}] {_safe(f.file)}:{f.line}  {_safe(f.title)}  {DIM}(risk {f.risk:.0f}){RESET}")
    if ctx.rejected:
        print(f"  {len(ctx.rejected)} candidate fix(es) rejected by the verifier (see report)")
    if ctx.integrity:
        print(f"  {BOLD}integration warnings:{RESET} {len(ctx.integrity)} (see report)")
    if ctx.llm_calls:
        print(f"  LLM requests: {ctx.llm_calls}")
    if ctx.out_path:
        print(f"{BOLD}  output:{RESET} {ctx.out_path}")
    print(f"  report: {'inside the output (_cd1_report/)' if ctx.out_path.endswith('.zip') or os.path.isdir(ctx.out_path) else 'next to the output file'}\n")


if __name__ == "__main__":
    sys.exit(main())
