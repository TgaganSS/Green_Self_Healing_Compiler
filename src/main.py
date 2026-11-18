#!/usr/bin/env python3
"""
Self-Healing C++ Compiler - command line interface.

  python src/main.py file.cpp                    analyse (errors, security, optimisation)
  python src/main.py file.cpp -v                 + code context, timings, compiler notes
  python src/main.py file.cpp --format json      machine readable
  python src/main.py file.cpp --format sarif     SARIF 2.1.0 for CI / code scanning
  python src/main.py file.cpp --fail-on high     exit code 2 when a finding >= severity exists
  python src/main.py file.cpp --harden           verified secure rewrite -> file.hardened.cpp (+ diff)
  python src/main.py file.cpp --harden --in-place

Whole projects (a folder, .zip or .tar.gz of C++ files) - every file is compiled, then LINKED together:
  python src/main.py my_project.zip              compile + link + analyse all files
  python src/main.py my_project/ --format sarif  one SARIF report for the whole project
  python src/main.py my_project.zip --heal       self-heal syntax errors across files -> my_project.healed.zip
  python src/main.py my_project.zip --harden     verified security fixes in every file  -> my_project.hardened.zip
  python src/main.py my_project/ --exclude 'tests/*' --exclude legacy --link-flags "-lm"
"""

import argparse
import json
import os
import sys
import textwrap

from pipeline import analyze_file
from security_analyzer import format_security_report, risk_score
from perf_analyzer import format_optimization_report

RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
BLUE = "\033[95m"
BOLD = "\033[1m"
RESET = "\033[0m"

_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def parse_arguments(argv=None):
    p = argparse.ArgumentParser(description="C++ Error Explanation, Security & Optimization Tool")
    p.add_argument("source_file", help="C++ source file, or a project: a folder / .zip / .tar.gz of C++ files")
    p.add_argument("-j", "--json", action="store_true", help="shortcut for --format json")
    p.add_argument("--format", choices=("text", "json", "sarif"), default="text")
    p.add_argument("-v", "--verbose", action="store_true", help="show code context, notes and timings")
    p.add_argument("-c", "--context", type=int, default=2, help="number of context lines")
    p.add_argument("--all", action="store_true",
                   help="also show style / quality / performance warnings and cascading errors")
    p.add_argument("--no-optimize", action="store_true", help="skip optimisation advice")
    p.add_argument("--fail-on", choices=tuple(_SEV_RANK), default=None,
                   help="exit with status 2 if a security finding of at least this severity exists")
    p.add_argument("--harden", action="store_true",
                   help="apply verified secure-code fixes (writes <file>.hardened.cpp and prints a diff)")
    p.add_argument("--in-place", action="store_true", help="with --harden: overwrite the source file")
    p.add_argument("--project", action="store_true",
                   help="treat the input as a multi-file project (automatic for folders and archives)")
    p.add_argument("--heal", action="store_true",
                   help="project mode: self-heal compile errors across all files (writes <name>.healed.zip / folder)")
    p.add_argument("--exclude", action="append", default=[], metavar="PATTERN",
                   help="project mode: skip files/folders matching this glob (repeatable), e.g. 'tests/*'")
    p.add_argument("--cxxflags", default="", help="project mode: extra compiler flags, e.g. \"-DDEBUG -std=c++20\"")
    p.add_argument("--link-flags", default="", help="project mode: extra linker flags, e.g. \"-lm -lsqlite3\"")
    p.add_argument("--jobs", type=int, default=None, help="project mode: parallel compile jobs (default 4)")
    p.add_argument("--out", default=None, help="project mode: where to write the healed/hardened project")
    p.add_argument("--max-attempts", type=int, default=30, help="project mode: heal-loop limit (default 30)")
    p.add_argument("--universal", action="store_true",
                   help="multi-language, multi-agent audit + repair (auto-selected when the input is not only C++); see UNIVERSAL.md")
    p.add_argument("--agentic", action="store_true",
                   help="multi-agent pipeline on a file / zip / folder: sentinel, diagnose, repair, integrate, "
                        "harden, optimise, independent verification -> final file/zip + patch + report")
    p.add_argument("--run", action="store_true",
                   help="with --agentic: also build with sanitizers and EXECUTE in a sandbox, comparing original vs final")
    p.add_argument("--stdin", default=None, metavar="FILE", help="with --run: file fed to the program's stdin")
    p.add_argument("--llm", default=None, choices=("anthropic",),
                   help="with --agentic: let a model propose fixes the rules cannot make (sends file text to the "
                        "provider; every proposal is guard-checked)")
    p.add_argument("--skip", action="append", default=[], choices=("heal", "harden", "optimize"),
                   help="with --agentic: skip an agent (repeatable)")
    p.add_argument("--no-detect-build", action="store_true",
                   help="project / agentic mode: do not read flags from CMakeLists.txt or Makefile")
    p.add_argument("--no-cache", action="store_true", help="disable the build cache for this run")
    p.add_argument("--clear-cache", action="store_true", help="empty the build cache and exit")
    return p.parse_args(argv)


def print_error(error, verbose=False):
    etype = error.error_type.lower()
    color = RED if etype == "error" else YELLOW if etype == "warning" else BLUE
    print(f"\n{color}{BOLD}{etype.upper()}:{error.message}{RESET}")

    if error.file:
        location = f"{error.file}"
        if error.line is not None:
            location += f" (line {error.line}"
            if error.column is not None:
                location += f", column {error.column}"
            location += ")"
        print(f"  {BLUE}Location:{RESET} {location}")
    if error.category:
        cwe = (" " + "/".join(f"CWE-{c}" for c in error.cwe[:3])) if error.cwe else ""
        unc = " (uncertain)" if error.uncertain else ""
        print(f"  {BLUE}Category:{RESET} {error.category}{cwe}  "
              f"[{error.confidence:.0%} via {error.source or 'n/a'}]{unc}")

    if error.explanation:
        print(f"\n  {BLUE}{BOLD}Explanation:{RESET}")
        for block in error.explanation.split("\n\n"):
            print(f"  {BLUE}{textwrap.fill(block, width=80)}{RESET}\n")

    if error.suggestion:
        print(f"\n  {GREEN}{BOLD}Suggestion:{RESET}")
        for line in textwrap.fill(error.suggestion, width=80).split("\n"):
            print(f"  {GREEN}{line}{RESET}")

    if error.security_risk and error.security_risk not in ("None",) and \
            (error.security_risk != "Low" or error.group == "security" or verbose):
        print(f"\n  {YELLOW}{BOLD}Security Assessment:{RESET}")
        print(f"  {YELLOW}Risk Level: {error.security_risk}{RESET}")
        if error.risk_reason:
            print(f"  {YELLOW}{error.risk_reason}{RESET}")

    if verbose and error.notes:
        print(f"\n  {BOLD}Compiler notes:{RESET}")
        for n in error.notes[:4]:
            print(f"    - line {n.get('line')}: {n['message']}")
    if verbose and error.context and "lines" in error.context:
        print(f"\n  {BOLD}Code Context:{RESET}")
        start = error.context["start_line"]
        for i, line in enumerate(error.context["lines"], start=start):
            marker = "→" if i == error.line else " "
            print(f"  {marker} {i}: {line.rstrip()}")
    print()


def _result_dict(res, visible):
    errs = [e for e in visible if e.error_type == "error"]
    warns = [e for e in visible if e.error_type == "warning"]
    return {
        "status": "error" if errs else "success",
        "file": res.file,
        "blocked": res.blocked,
        "error_count": len(errs),
        "warning_count": len(warns),
        "errors": [e.to_dict() for e in visible],
        "security_findings": [f.to_dict() for f in res.security_findings],
        "security_report": format_security_report(res.security_findings),
        "risk_score": risk_score(res.security_findings),
        "optimization_findings": [o.to_dict() for o in res.optimization_findings],
        "preflight": res.preflight,
        "cached": res.cached,
        "timings": {k: round(v, 4) for k, v in res.timings.items()},
    }


def _fail_code(res, threshold):
    if not threshold:
        return 0
    limit = _SEV_RANK[threshold]
    return 2 if any(_SEV_RANK[f.severity.lower()] <= limit for f in res.security_findings) else 0


def run_harden(args):
    from secure_fixer import harden_source, unified_diff
    path = args.source_file
    with open(path, "rb") as fb:
        had_crlf = b"\r\n" in fb.read()           # keep the file's original line endings
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        source = f.read()
    r = harden_source(source, path)
    if r.error:
        print(f"{RED}{r.error}{RESET}")
        return 1
    if not r.applied:
        print("No verified automatic fixes available.")
        for rule, line, why in r.skipped:
            print(f"  skipped {rule} (line {line}): {why}")
        print()
        print(format_security_report(r.remaining), end="")
        return 0
    print(f"{GREEN}{BOLD}{len(r.applied)} verified fix(es) applied:{RESET}")
    for fx in r.applied:
        print(f"  line {fx.line:<4} {fx.rule:<14} {fx.description}")
    for rule, line, why in r.skipped:
        print(f"  {YELLOW}skipped{RESET} {rule} (line {line}): {why}")
    print("\n" + unified_diff(r.original, r.hardened, os.path.basename(path)))
    out = path if args.in_place else os.path.splitext(path)[0] + ".hardened.cpp"
    with open(out, "w", encoding="utf-8", newline="\r\n" if had_crlf else None) as f:
        f.write(r.hardened)
    print(f"{GREEN}Written: {out}{RESET}")
    print(f"\nRemaining findings: {len(r.remaining)}")
    print(format_security_report(r.remaining), end="")
    return 0


# ───────────────────────────── multi-file projects ─────────────────────────────

def _is_project_input(args) -> bool:
    if args.project or args.heal or args.exclude:
        return True
    p = args.source_file
    if os.path.isdir(p):
        return True
    try:
        import project as _P
        return _P._is_archive(p) is not None
    except Exception:
        return False


def _split_flags(text: str):
    import shlex
    return shlex.split(text) if text else []


def _file_status(res, proj_res):
    if res.blocked:
        return "BLOCKED"
    if res.error_count > 0:
        return "error"
    if any(e.error_type == "warning" for e in res.visible()) or res.security_findings:
        return "warn"
    return "ok"


def _project_dict(proj_res, show_all=False):
    return {
        "project": proj_res.name,
        "status": "blocked" if proj_res.blocked else ("error" if (proj_res.error_count or
                  (proj_res.targets and not proj_res.link_ok)) else "success"),
        "source_files": proj_res.n_sources, "header_files": proj_res.n_headers, "lines": proj_res.n_lines,
        "compile_ok": proj_res.compile_ok, "link_ok": proj_res.link_ok if proj_res.targets else None,
        "link_skipped": proj_res.link_skipped,
        "blocked_files": proj_res.blocked_files,
        "link_targets": [{"name": t.name, "entry": t.entry, "ok": t.ok, "files": t.files,
                          "errors": [e.to_dict() for e in t.errors]} for t in proj_res.targets],
        "files": {rel: _result_dict(r, r.visible(show_all=show_all)) for rel, r in proj_res.files.items()},
        "security_findings": [f.to_dict() for f in proj_res.security_findings],
        "security_report": format_security_report(proj_res.security_findings),
        "risk_score": proj_res.risk,
        "optimization_findings": [o.to_dict() for o in proj_res.optimization_findings],
        "skipped": [{"path": a, "reason": b} for a, b in proj_res.skipped],
        "notes": proj_res.notes,
        "timings": {k: round(v, 3) for k, v in proj_res.timings.items()},
    }


def _print_project_report(res, args):
    n_ok = sum(1 for r in res.files.values() if r.error_count == 0 and not r.blocked)
    print(f"\n{BOLD}Project: {res.name}{RESET}  ({res.n_sources} source file(s), {res.n_headers} header(s), "
          f"{res.n_lines:,} lines)")
    if res.blocked:
        status = f"{RED}BLOCKED by safety gate{RESET}"
    else:
        c = f"{GREEN}{n_ok}/{res.n_sources} compiled cleanly{RESET}" if res.compile_ok else \
            f"{RED}{n_ok}/{res.n_sources} compiled cleanly{RESET}"
        if res.targets:
            ok = res.link_ok
            names = ", ".join(t.name for t in res.targets[:3]) + (" ..." if len(res.targets) > 3 else "")
            l = f"{GREEN}link OK{RESET} [{names}]" if ok else f"{RED}link FAILED{RESET} [{names}]"
        elif res.link_skipped:
            l = f"{YELLOW}link skipped{RESET} ({res.link_skipped})"
        else:
            l = "link not run"
        status = f"{c} | {l}"
    print(f"  {status}")
    for n in res.notes:
        print(f"  {BLUE}note:{RESET} {n}")
    for rel, why in res.blocked_files.items():
        print(f"  {RED}blocked{RESET} {rel}: {why}")
    for rel, why in res.skipped[:8]:
        print(f"  {YELLOW}skipped{RESET} {rel}: {why}")
    if len(res.skipped) > 8:
        print(f"  ... and {len(res.skipped) - 8} more skipped")

    # per-file table
    width = max([len(r) for r in res.files] + [4])
    print(f"\n  {'File':<{width}}  {'Status':<8} {'Errors':>6} {'Warn':>5} {'Security':>8}")
    sev_by_file = {}
    for f in res.security_findings:
        sev_by_file[f.file] = sev_by_file.get(f.file, 0) + 1
    for rel, r in res.files.items():
        vis = r.visible(show_all=args.all)
        errs = sum(1 for e in vis if e.error_type == "error")
        warns = sum(1 for e in vis if e.error_type == "warning")
        st = _file_status(r, res)
        col = RED if st in ("error", "BLOCKED") else YELLOW if st == "warn" else GREEN
        print(f"  {rel:<{width}}  {col}{st:<8}{RESET} {errs:>6} {warns:>5} {sev_by_file.get(rel, 0):>8}")
    hdr_issues = {h: len(v) for h, v in res.header_findings.items() if v}
    for h, n in hdr_issues.items():
        print(f"  {h:<{width}}  {'header':<8} {'-':>6} {'-':>5} {n:>8}")

    # compile diagnostics, grouped by file, each unique diagnostic shown once
    seen = set()
    shown_any = False
    for rel, r in res.files.items():
        items = []
        for e in r.visible(show_all=args.all):
            k = res._ekey(e)
            if k not in seen:
                seen.add(k)
                items.append(e)
        if not items:
            continue
        if not shown_any:
            print(f"\n{BOLD}Compiler diagnostics{RESET}")
            shown_any = True
        print(f"\n{BOLD}── {rel} ──{RESET}")
        for e in items:
            print_error(e, verbose=args.verbose)
    hidden = sum(len(r.errors) - len(r.visible(show_all=args.all)) for r in res.files.values())
    if shown_any and hidden > 0:
        print(f"({hidden} style/quality/follow-on diagnostic(s) hidden; use --all to show)")

    # link stage
    if res.targets and not res.link_ok:
        print(f"\n{BOLD}Link errors{RESET}")
        for t in res.targets:
            if not t.ok:
                print(f"\n{RED}{BOLD}Link FAILED:{RESET} {t.name}")
        for e in res.link_errors:
            print_error(e, verbose=args.verbose)
    elif res.targets and res.link_ok:
        print(f"\n{GREEN}{BOLD}Link OK{RESET}: " + "; ".join(f"{t.name} ({len(t.files)} file(s))" for t in res.targets))

    print()
    print(format_security_report(res.security_findings), end="")
    if res.optimization_findings:
        print(f"\n{BOLD}Optimization advice{RESET}")
        print(format_optimization_report(res.optimization_findings), end="")
    if args.verbose:
        t = res.timings
        print(f"\n[timing] total {t.get('total', 0):.2f}s | gate {t.get('gate', 0):.3f}s | "
              f"compile {t.get('compile', 0):.2f}s ({res.flags_note}) | analysis {t.get('analysis', 0):.2f}s | "
              f"link {t.get('link', 0):.2f}s")


def _print_diffs(changed, label="hardened"):
    from secure_fixer import unified_diff
    for rel, (before, after) in changed.items():
        print("\n" + unified_diff(before, after, rel, label), end="")


def _final_summary(proj, args, label):
    """Re-analyse the fixed work tree so the user sees the real end state."""
    import project as P
    res = P.analyze_project(proj, optimize=False, jobs=args.jobs, cxxflags=_split_flags(args.cxxflags),
                            link_flags=_split_flags(args.link_flags))
    built = res.built
    print(f"\n{BOLD}Final check of the {label} project:{RESET} "
          f"{res.error_count} compile error(s), "
          f"link {'OK' if res.link_ok else ('FAILED' if res.targets else 'not run')}, "
          f"{len(res.security_findings)} security finding(s)  "
          f"{GREEN + 'BUILDS' + RESET if built else RED + 'DOES NOT BUILD' + RESET}")
    return res


def run_project(args):
    import project as P
    try:
        proj = P.open_project(args.source_file, args.exclude)
    except P.ProjectError as e:
        print(f"{RED}Cannot open project: {e}{RESET}")
        return 1
    cx, lf = _with_detected_flags(proj, _split_flags(args.cxxflags), _split_flags(args.link_flags), args)
    with proj:
        if args.heal or args.harden:
            return _run_project_fix(proj, args, cx, lf)
        res = P.analyze_project(proj, optimize=not args.no_optimize, jobs=args.jobs, cxxflags=cx, link_flags=lf)
        fmt = "json" if args.json else args.format
        code = 1 if (res.error_count > 0 or res.blocked or (res.targets and not res.link_ok)) else 0
        if code == 0 and args.fail_on:
            limit = _SEV_RANK[args.fail_on]
            if any(_SEV_RANK[f.severity.lower()] <= limit for f in res.security_findings):
                code = 2
        if fmt == "sarif":
            import sarif
            print(sarif.dumps(res.security_findings, res.optimization_findings))
        elif fmt == "json":
            print(json.dumps(_project_dict(res, args.all), indent=2))
        else:
            _print_project_report(res, args)
        return code


def _run_project_fix(proj, args, cx, lf):
    import project as P
    changed = {}
    if args.heal:
        print(f"{BOLD}Self-healing {proj.name}{RESET} ({len(proj.sources)} source file(s))")
        h = P.heal_project(proj, max_attempts=args.max_attempts, jobs=args.jobs, cxxflags=cx, link_flags=lf,
                           progress=lambda e: print(f"  attempt {e['attempt']}: [{e['category']}] "
                                                    f"{e['file']}:{e['line']} {e['message']} -> fixed"))
        for e in h.history:
            if e["status"] == "clean":
                print(f"  attempt {e['attempt']}: recompile -> {GREEN}CLEAN{RESET} ({e['message']})")
            elif e["status"] == "stopped":
                print(f"  attempt {e['attempt']}: {YELLOW}{e['message']}{RESET}")
        if h.clean:
            print(f"{GREEN}{BOLD}Healed: every file compiles and the project links.{RESET}")
        else:
            print(f"{YELLOW}Not fully healed: {h.reason}.{RESET}")
            for e in h.link_errors[:6]:
                print_error(e)
        _print_diffs(h.changed, "healed")
        changed.update(h.changed)
    if args.harden:
        print(f"\n{BOLD}Hardening {proj.name}{RESET}")
        hp = P.harden_project(proj, jobs=args.jobs, cxxflags=cx, link_flags=lf)
        n = sum(len(r.applied) for rel, r in hp.files.items() if rel in hp.changed)
        if n:
            print(f"{GREEN}{BOLD}{n} verified fix(es) applied in {len(hp.changed)} file(s):{RESET}")
            for rel in hp.changed:
                for fx in hp.files[rel].applied:
                    print(f"  {rel}:{fx.line:<4} {fx.rule:<14} {fx.description}")
        else:
            print("No verified automatic fixes available.")
        for rel, r in hp.files.items():
            for rule, line, why in r.skipped:
                print(f"  {YELLOW}skipped{RESET} {rel}:{line} {rule}: {why}")
            if r.error and rel not in hp.changed:
                print(f"  {YELLOW}not hardened{RESET} {rel}: {r.error}")
        for rel, why in hp.rolled_back.items():
            print(f"  {RED}rolled back{RESET} {rel}: {why}")
        if hp.build_ok_before is not None:
            print(f"Whole-project rebuild: before {'OK' if hp.build_ok_before else 'FAILED'}, "
                  f"after {'OK' if hp.build_ok_after else 'FAILED'}")
        _print_diffs(hp.changed)
        for rel, (b, a) in hp.changed.items():
            changed[rel] = (changed.get(rel, (b, a))[0], a)
        print(f"\nRemaining findings: {len(hp.remaining)}")
        print(format_security_report(hp.remaining), end="")
    if not changed:
        print("\nNo files were changed, so nothing was written.")
        return 0
    try:
        if args.in_place:
            written = P.write_in_place(proj, changed)
            print(f"\n{GREEN}Updated {len(written)} file(s) in place in {proj.origin}{RESET}")
        else:
            suffix = "fixed" if (args.heal and args.harden) else ("healed" if args.heal else "hardened")
            dest = args.out or P.default_output(proj, suffix)
            if proj.kind == "file" and not args.out:
                dest = P.default_output(proj, suffix)
            written = P.write_output(proj, dest) if proj.kind != "file" else _write_single(proj, dest)
            print(f"\n{GREEN}Written: {written}{RESET}")
    except P.ProjectError as e:
        print(f"{RED}{e}{RESET}")
        return 1
    res = _final_summary(proj, args, "fixed")
    return 0 if res.built else 1


def _write_single(proj, dest):
    shutil_copy = __import__("shutil").copyfile
    rel = proj.sources[0]
    shutil_copy(proj.abspath(rel), dest)
    return dest


def _with_detected_flags(proj, cx, lf, args):
    """flags found in CMakeLists.txt / Makefile come first; --cxxflags / --link-flags win on conflicts"""
    if getattr(args, "no_detect_build", False):
        return cx, lf
    import buildinfo
    bi = buildinfo.detect(proj.root)
    if bi.cxxflags or bi.link_flags:
        if not (args.json or args.format != "text"):
            print(f"{BOLD}build flags from {', '.join(bi.sources)}: {' '.join(bi.cxxflags + bi.link_flags)}{RESET}")
    return bi.cxxflags + cx, bi.link_flags + lf


_CPP_EXT = {".cpp", ".cc", ".cxx", ".c++", ".hpp", ".hh", ".hxx", ".h"}


def _wants_universal(args) -> bool:
    """Route to the multi-language audit when the input is not (only) C++: a non-C++ file, or a folder / archive
    that contains other source languages.  `--universal` forces it."""
    if getattr(args, "universal", False):
        return True
    src = getattr(args, "source_file", None)
    if not src or not os.path.exists(src):
        return False
    import zipfile, tarfile
    names = []
    try:
        if os.path.isdir(src):
            for _r, ds, fs in os.walk(src):
                ds[:] = [d for d in ds if d not in ("node_modules", ".git", "venv", ".venv", "__pycache__")]
                names += fs
                if len(names) > 5000:
                    break
        elif zipfile.is_zipfile(src):
            names = [os.path.basename(n) for n in zipfile.ZipFile(src).namelist()]
        elif tarfile.is_tarfile(src):
            names = [os.path.basename(n) for n in tarfile.open(src).getnames()]
        else:
            names = [os.path.basename(src)]
    except Exception:
        return False
    from universal.langdetect import EXT, CODE_LANGS
    other = {e for e, lang in EXT.items() if lang in CODE_LANGS and e not in _CPP_EXT}
    return any(os.path.splitext(n)[1].lower() in other for n in names)


def _run_universal(args) -> int:
    import audit
    argv = [args.source_file]
    if getattr(args, "out", None):
        argv += ["--out", args.out]
    if getattr(args, "fail_on", None):
        argv += ["--fail-on", args.fail_on.lower()]
    if getattr(args, "run", False):
        argv.append("--run")
    if getattr(args, "no_optimize", False):
        argv.append("--no-optimize")
    return audit.main(argv)


def run_agentic_cli(args):
    import project as P
    from agents import orchestrator as OR, report as RP, llm as LLM
    try:
        provider = LLM.make_provider(args.llm)
    except (RuntimeError, ValueError) as e:
        print(f"{RED}{e}{RESET}")
        return 1
    stdin = b""
    if args.stdin:
        with open(args.stdin, "rb") as f:
            stdin = f.read()

    def prog(ev):
        mark = "" if ev.ok is None else (f" {GREEN}ok{RESET}" if ev.ok else f" {YELLOW}!{RESET}")
        print(f"  {BOLD}{ev.agent:<13}{RESET} {ev.action:<9} {ev.detail[:110]}{mark}", flush=True)

    opt = OR.Options(heal="heal" not in args.skip, harden="harden" not in args.skip,
                     optimize="optimize" not in args.skip and not args.no_optimize, run=args.run, llm=provider,
                     stdin=stdin, jobs=args.jobs, cxxflags=_split_flags(args.cxxflags),
                     link_flags=_split_flags(args.link_flags), max_attempts=args.max_attempts,
                     exclude=tuple(args.exclude), detect_build=not args.no_detect_build, progress=None if args.json or args.format != "text" else prog)
    if not (args.json or args.format != "text"):
        print(f"{BOLD}Agentic pipeline{RESET} on {args.source_file}")
    try:
        res = OR.run_agentic(args.source_file, opt)
    except P.ProjectError as e:
        print(f"{RED}Cannot open project: {e}{RESET}")
        return 1
    with res.proj:
        written = RP.write_outputs(res, args.out, args.in_place)
        if args.json or args.format == "json":
            d = RP.to_dict(res)
            d["written"] = written
            print(json.dumps(d, indent=2, default=str))
        else:
            sm = RP.summary(res)
            col = GREEN if res.verdict in ("VERIFIED", "UNCHANGED") else YELLOW if res.verdict == "PARTIAL" else RED
            print(f"\n{col}{BOLD}{res.verdict}{RESET}  sentinel={sm['sentinel']}  "
                  f"files changed={len(sm['files_changed'])}")
            if sm["before"] and sm["after"]:
                b, a = sm["before"], sm["after"]
                print(f"  errors {b['errors']} -> {a['errors']} | link errors {b['link_errors']} -> {a['link_errors']} | "
                      f"security findings {b['security_findings']} -> {a['security_findings']} | "
                      f"builds {b['built']} -> {a['built']}")
            for k, v in written.items():
                print(f"  {k:<7} {v}")
    return 0 if res.verdict in ("VERIFIED", "UNCHANGED") else 1


def main(argv=None):
    args = parse_arguments(argv)
    if args.no_cache:
        os.environ["GSC_NO_CACHE"] = "1"
    if args.clear_cache:
        import build_cache
        print(f"Removed {build_cache.clear()} cached build result(s).")
        return 0
    if _wants_universal(args):
        return _run_universal(args)
    if args.agentic:
        return run_agentic_cli(args)
    if _is_project_input(args):
        return run_project(args)
    if args.harden:
        return run_harden(args)

    fmt = "json" if args.json else args.format
    res = analyze_file(args.source_file, optimize=not args.no_optimize)
    visible = res.visible(show_all=args.all)
    hidden = len(res.errors) - len(visible)
    code = 1 if res.error_count > 0 else 0
    if code == 0:
        code = _fail_code(res, args.fail_on)

    if fmt == "sarif":
        import sarif
        print(sarif.dumps(res.security_findings, res.optimization_findings))
        return code
    if fmt == "json":
        print(json.dumps(_result_dict(res, visible), indent=2))
        return code

    # ---- human readable ----
    if res.blocked:
        for e in visible:
            print_error(e, verbose=args.verbose)
        return 1
    if not visible:
        print("Compilation successful")
        print()
    else:
        print(f"\n{len(visible)} issue(s) found:\n")
        error_count = warning_count = 0
        for e in visible:
            if e.error_type == "error":
                error_count += 1
            elif e.error_type == "warning":
                warning_count += 1
            print_error(e, verbose=args.verbose)
        print(f"{error_count} error(s), {warning_count} warning(s)")
        if hidden > 0:
            print(f"({hidden} style/quality/follow-on diagnostic(s) hidden; use --all to show)")
        print()
    if res.preflight and args.verbose:
        for p in res.preflight[:5]:
            print(f"{YELLOW}Pre-flight:{RESET} line {p['line']}: {p['message']}")
        print()
    print(format_security_report(res.security_findings), end="")
    if res.optimization_findings:
        print(f"\n{BOLD}Optimization advice{RESET}")
        print(format_optimization_report(res.optimization_findings), end="")
    if args.verbose:
        t = res.timings
        print(f"\n[timing] total {t['total']:.2f}s | build {t['build']:.2f}s"
              f"{' (cached)' if res.cached else ''} | classify {t['classify']:.2f}s | "
              f"security {t['security']:.3f}s | optimize {t['optimize']:.3f}s")
    return code


if __name__ == "__main__":
    try:
        sys.exit(main())
    except BrokenPipeError:                       # e.g. `main.py f.cpp | head` - exit quietly
        try:
            os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        except OSError:
            pass
        sys.exit(0)
