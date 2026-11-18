"""
agents.py - the cooperating agents.  Each agent reads/writes a shared Context and logs to the audit Trace.

    IntakeAgent   safe extraction (zip-slip / zip-bomb / symlink guards from project.py), triage, language detection
    MalwareAgent  heuristic + optional ClamAV triage; malicious files are physically quarantined
    AnalystAgent  per-language analysis in parallel: real parsers, rules, AST, secrets, config checks; syntax self-healing
    CppAgent      wraps the original compiler-backed C++ engine (compile + link + classify + security + perf, heal, harden)
    RiskAgent     transparent 0-100 risk scoring
(repair.py: Fix / LLM-Fix / Verifier agents,  engine.py: Integration agent + orchestration)
"""
from __future__ import annotations

import hashlib
import os
import re
import shutil
import tempfile
import threading
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from . import langdetect as LD
from . import malware as MW
from . import pyanalyzer as PA
from . import risk as RK
from . import toolcheck as TC
from .core import FileInfo, Finding, Fix, Trace, TIER_PROPOSED
from .llm import NullProvider, Provider
from .rules import scan_text as rule_scan
from .secrets import scan_secrets

MAX_ANALYZE_BYTES = 2 * 1024 * 1024
_EXPOSED = re.compile(r"\b(flask|django|fastapi|aiohttp|tornado|bottle|express|koa|fastify|http\.createServer|net/http|"
                      r"ListenAndServe|@RestController|@Controller|Spring|Rails|Sinatra|\$_(GET|POST|REQUEST)|"
                      r"socket\.(bind|listen)|\.listen\s*\(|accept\s*\()", re.I)


@dataclass
class Options:
    out: Optional[str] = None
    fix: bool = True
    apply_proposed: bool = False          # also apply behaviour-changing ("proposed") fixes
    apply_llm: bool = False               # also apply verified LLM-authored fixes (default: write them to proposed.patch)
    llm: Provider = field(default_factory=NullProvider)
    llm_budget: int = 20
    exclude: List[str] = field(default_factory=list)
    cxxflags: List[str] = field(default_factory=list)
    link_flags: List[str] = field(default_factory=list)
    jobs: int = 4
    min_conf: float = 0.5
    max_rounds: int = 4
    max_heal_attempts: int = 30
    keep_quarantined: bool = False
    cpp: bool = True
    fail_on: Optional[str] = None
    cpp_optimize: bool = True             # C++ files: let the Optimizer agent apply verified source-to-source optimisations
    run: bool = False                     # C++ files: also build with sanitizers and EXECUTE in the sandbox (opt-in)
    stdin: bytes = b""
    run_args: List[str] = field(default_factory=list)


@dataclass
class Context:
    src: str
    opts: Options
    proj: object = None
    root: str = ""
    name: str = "project"
    files: Dict[str, FileInfo] = field(default_factory=dict)
    texts: Dict[str, str] = field(default_factory=dict)             # current text (changes as fixes land)
    orig: Dict[str, str] = field(default_factory=dict)              # text as uploaded
    findings: List[Finding] = field(default_factory=list)
    heal: Dict[str, List[dict]] = field(default_factory=dict)       # syntax-heal history per file
    applied: List[dict] = field(default_factory=list)
    rejected: List[dict] = field(default_factory=list)
    proposed_text: Dict[str, str] = field(default_factory=dict)     # rel -> text with verified behaviour-changing fixes
    llm_proposals: List[dict] = field(default_factory=list)
    quarantined: Dict[str, dict] = field(default_factory=dict)
    qdir: str = ""
    cpp: dict = field(default_factory=dict)
    findings_after_cpp: List[Finding] = field(default_factory=list)
    risk_before: float = 0.0
    risk_after: float = 0.0
    risk_if_proposed: float = 0.0
    counts: dict = field(default_factory=dict)
    findings_after: List[Finding] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    skipped: List[str] = field(default_factory=list)
    integrity: List[str] = field(default_factory=list)
    out_path: str = ""
    trace: Trace = field(default_factory=Trace)
    lock: threading.Lock = field(default_factory=threading.Lock)
    llm_calls: int = 0

    def add(self, fs: List[Finding]) -> None:
        with self.lock:
            self.findings.extend(fs)


class Agent:
    name = "agent"

    def run(self, ctx: Context) -> None:            # pragma: no cover - interface
        raise NotImplementedError


def _read(path: str) -> str:
    with open(path, "r", encoding="utf-8", errors="surrogateescape", newline="") as f:
        return f.read()


def write_text(path: str, text: str) -> None:
    with open(path, "w", encoding="utf-8", errors="surrogateescape", newline="") as f:
        f.write(text)


# ─────────────────────────────────────────────────────────────────────────────
class IntakeAgent(Agent):
    name = "intake"

    def run(self, ctx: Context) -> None:
        import project as P
        proj = P.open_project(ctx.src, exclude=ctx.opts.exclude)           # zip-slip / bomb / symlink / size limits
        ctx.proj, ctx.root, ctx.name = proj, proj.root, proj.name
        ctx.notes += list(proj.notes)
        n_vendor = 0
        for dirpath, dirnames, filenames in os.walk(proj.root):
            keep = []
            for d in dirnames:
                if d in LD.VENDOR_DIRS or d.startswith("gsc_objs_") or d.startswith("cmake-build-"):
                    n_vendor += 1
                else:
                    keep.append(d)
            dirnames[:] = keep
            for fn in sorted(filenames):
                full = os.path.join(dirpath, fn)
                rel = os.path.relpath(full, proj.root).replace(os.sep, "/")
                if os.path.islink(full):
                    continue
                size = os.path.getsize(full)
                with open(full, "rb") as f:
                    head = f.read(8192)
                sha = hashlib.sha256()
                with open(full, "rb") as f:
                    for chunk in iter(lambda: f.read(1 << 20), b""):
                        sha.update(chunk)
                exe = LD.executable_kind(head)
                binary = LD.is_binary(head) or os.path.splitext(fn)[1].lower() in LD.BINARY_EXT
                lang = "" if binary else LD.detect(rel, head)
                fi = FileInfo(rel=rel, language=lang, size=size, sha256=sha.hexdigest(), is_binary=binary,
                              is_test=bool(LD.TEST_RE.search(rel)))
                if exe:
                    fi.notes.append(exe)
                ctx.files[rel] = fi
                if lang and not binary:
                    if size > MAX_ANALYZE_BYTES:
                        ctx.skipped.append(f"{rel}: {size // 1024} KB exceeds the {MAX_ANALYZE_BYTES // 1024} KB analysis limit")
                        continue
                    t = _read(full)
                    ctx.texts[rel] = t
                    ctx.orig[rel] = t
                    fi.exposed = bool(_EXPOSED.search(t[:200000]))
        if n_vendor:
            ctx.notes.append(f"{n_vendor} vendor/build folder(s) (node_modules, .git, venv, build ...) were not analysed")
        langs = Counter(f.language for f in ctx.files.values() if f.language)
        ctx.trace.log(self.name, "inventory", files=len(ctx.files), analysed=len(ctx.texts), languages=dict(langs))


# ─────────────────────────────────────────────────────────────────────────────
class MalwareAgent(Agent):
    name = "malware"

    def run(self, ctx: Context) -> None:
        ctx.qdir = tempfile.mkdtemp(prefix="cd1_quarantine_")
        clam = MW.clamav_scan(ctx.root) if MW.clamav_available() else {}
        if clam:
            ctx.trace.log(self.name, "clamav", hits=len(clam))
        elif not MW.clamav_available():
            ctx.notes.append("ClamAV (clamscan) not installed: malware triage used heuristics only")
        results = {}
        for rel, text in list(ctx.texts.items()):
            fi = ctx.files[rel]
            if fi.language in ("markdown", ""):
                continue
            results[rel] = MW.scan_text(text, rel, fi.language, is_test=fi.is_test)
        for rel, fi in ctx.files.items():
            if fi.notes and fi.is_binary:
                ctx.add([MW.binary_finding(rel, fi.notes[0])])
        to_quarantine = {}
        for rel, rep in results.items():
            ctx.add(rep.findings)
            if rep.verdict == "malicious":
                if not ctx.opts.keep_quarantined and self._neutralize_manifest(ctx, rel, rep):
                    continue
                to_quarantine[rel] = f"heuristic score {rep.score}: " + ", ".join(h[0] for h in rep.hits)
        for rel, sig in clam.items():
            if rel in ctx.files:
                to_quarantine[rel] = f"ClamAV signature {sig}"
                ctx.add([Finding(file=rel, line=1, language=ctx.files[rel].language, category="malware", rule_id="M-CLAMAV",
                                 title=f"ClamAV detection: {sig}", severity="Critical", confidence=0.99, cwe=(506,), agent="malware",
                                 message="Antivirus signature match.", recommendation="Delete the file and investigate how it got there.")])
        if not ctx.opts.keep_quarantined:
            for rel, why in to_quarantine.items():
                self._quarantine(ctx, rel, why, results.get(rel))
        else:
            for rel, why in to_quarantine.items():
                ctx.notes.append(f"{rel}: flagged malicious but kept (--keep-quarantined): {why}")
        sus = [r for r, rep in results.items() if rep.verdict == "suspicious"]
        ctx.trace.log(self.name, "triage", malicious=len(to_quarantine), suspicious=len(sus))

    @staticmethod
    def _neutralize_manifest(ctx: Context, rel: str, rep) -> bool:
        """package.json whose ONLY problem is a malicious install-time script: delete just that script, keep the manifest."""
        if os.path.basename(rel).lower() != "package.json":
            return False
        if not {h[0] for h in rep.hits} <= {"M-INSTALL-HOOK", "M-DOWNLOAD-IP", "M-DOWNLOAD-RUN", "M-CURL-SH", "M-CURL-SH-HTTP"}:
            return False
        import json
        hook = next(rx for (i, rx, *_r) in MW._IND if i == "M-INSTALL-HOOK")
        text = ctx.texts[rel]
        fixed_text, _h = TC.heal_json(text)
        try:
            obj = json.loads(fixed_text)
        except ValueError:
            return False
        scripts = obj.get("scripts") if isinstance(obj, dict) else None
        if not isinstance(scripts, dict):
            return False
        bad = [k for k, v in scripts.items() if isinstance(v, str) and hook.search(f'"{k}": "{v}"')]
        if not bad:
            return False
        for k in bad:
            del scripts[k]
        m = re.search(r"\n([ \t]+)\"", text)
        new = json.dumps(obj, indent=(m.group(1) if m else 2), ensure_ascii=False) + "\n"
        if MW.scan_text(new, rel, "json").score >= MW.SUSPICIOUS_AT:
            return False
        ctx.texts[rel] = new
        for f in ctx.findings:
            if f.file == rel and f.category == "malware":
                f.status, f.verified_by = "fixed", "malicious script entry deleted; manifest still valid JSON and re-scans clean"
                f.fix_note = "Investigate who added this hook and rotate any credentials available to CI/dev machines that ran `npm install`."
        ctx.applied.append({"file": rel, "ids": [f.id for f in ctx.findings if f.file == rel], "source": "rule",
                            "what": "removed malicious install-time script(s) " + ", ".join(bad) + " from the manifest", "verified_by": "json.loads + malware re-scan"})
        ctx.trace.log("malware", "neutralize", file=rel)
        return True

    @staticmethod
    def _quarantine(ctx: Context, rel: str, why: str, rep) -> None:
        MalwareAgent._quarantine_impl(ctx, rel, why, rep)

    @staticmethod
    def _quarantine_impl(ctx: Context, rel: str, why: str, rep) -> None:
        src = os.path.join(ctx.root, *rel.split("/"))
        dst = os.path.join(ctx.qdir, *rel.split("/"))
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        if os.path.exists(src):
            shutil.move(src, dst)
        fi = ctx.files[rel]
        fi.quarantined, fi.quarantine_reason = True, why
        ctx.quarantined[rel] = {"reason": why, "sha256": fi.sha256, "size": fi.size,
                                "indicators": [h[0] for h in rep.hits] if rep else []}
        ctx.texts.pop(rel, None)
        for f in ctx.findings:
            if f.file == rel:
                f.status = "quarantined"
        ctx.trace.log("malware", "quarantine", file=rel, reason=why)


# ─────────────────────────────────────────────────────────────────────────────
class AnalystAgent(Agent):
    """Per-language analysis.  A file that does not parse is first self-healed (verified by the same parser)."""
    name = "analyst"

    def run(self, ctx: Context) -> None:
        todo = [r for r in sorted(ctx.texts) if not ctx.files[r].quarantined and ctx.files[r].language]
        with ThreadPoolExecutor(max_workers=max(1, ctx.opts.jobs)) as ex:
            list(ex.map(lambda r: self.analyze_one(ctx, r), todo))
        ctx.trace.log(self.name, "done", files=len(todo), findings=len(ctx.findings))

    # shared by the verifier for re-scans (no healing, no side effects)
    @staticmethod
    def scan(ctx_files: Dict[str, FileInfo], rel: str, lang: str, text: str) -> List[Finding]:
        out: List[Finding] = []
        if lang == "cpp":
            return scan_secrets(text, rel, lang)
        out += rule_scan(text, rel, lang, agent=lang)
        if lang == "python":
            out += PA.analyze_ast(text, rel)
        out += scan_secrets(text, rel, lang)
        out += _special_files(rel, lang, text)
        return out

    def analyze_one(self, ctx: Context, rel: str) -> None:
        fi, lang = ctx.files[rel], ctx.files[rel].language
        text = ctx.texts[rel]
        found: List[Finding] = []
        lines = text.splitlines()
        syn: List[Finding] = []
        healed = text
        hist: List[dict] = []
        includes = [os.path.dirname(os.path.join(ctx.root, *rel.split("/"))), ctx.root] + \
                   [os.path.join(ctx.root, d) for d in ("include", "inc", "src") if os.path.isdir(os.path.join(ctx.root, d))]
        if lang == "python":
            try:
                text.encode("utf-8")
            except UnicodeEncodeError:                               # undecodable bytes: Python 3 needs a coding declaration
                if not re.search(r"coding[:=]\s*[-\w.]+", "\n".join(lines[:2])):
                    found.append(Finding(file=rel, line=1, language="python", category="error", rule_id="PY-ENCODING",
                                         title="File is not valid UTF-8 and declares no encoding", severity="High", confidence=0.95, agent="python",
                                         message="`python file.py` refuses to run source that is not UTF-8 unless a coding line (PEP 263) says otherwise.",
                                         recommendation="Re-save the file as UTF-8, or add the correct '# -*- coding: <encoding> -*-' line. "
                                                        "The bytes were left exactly as they were: the tool does not guess encodings."))
            e = PA.syntax_error(text, rel)
            if e:
                syn = [PA.syntax_finding(e, rel, lines)]
                if ctx.opts.fix:
                    healed, hist = PA.heal_syntax(text, rel, ctx.opts.max_heal_attempts)
                    ok = PA.syntax_error(healed, rel) is None
        elif lang == "javascript":
            syn = TC.check_js(text, rel)
            if syn and ctx.opts.fix:
                healed, hist = TC.heal_js(text, rel)
        elif lang == "c":
            errs = [f for f in TC.check_c(text, rel, includes) if f.category == "error"]
            syn = errs
            if errs and ctx.opts.fix:
                healed, hist = TC.heal_c(text, includes)
        elif lang == "json":
            syn = TC.check_json(text, rel)
            if syn and ctx.opts.fix:
                healed, hist = TC.heal_json(text)
        elif lang == "yaml":
            syn = TC.check_yaml(text, rel)
        elif lang == "shell":
            syn = TC.check_shell(text, rel)
        elif lang in ("php", "ruby", "go", "rust", "java"):
            syn = TC.check_syntax_tool(text, rel, lang)
        if syn:
            if healed != text:
                still = self._still_broken(lang, healed, rel, includes)
                steps = "; ".join(f"line {h['line']}: {h['result']}" for h in hist if "no safe" not in h["result"])
                if still is False:                                   # healed text parses cleanly -> accept
                    for s in syn:
                        s.status, s.verified_by = "fixed", f"{lang} parser accepts the repaired file"
                        s.fix_note = steps
                    ctx.texts[rel] = healed
                    ctx.heal[rel] = hist
                    ctx.applied.append({"file": rel, "ids": [s.id for s in syn], "what": f"syntax self-heal: {steps}",
                                        "source": "rule", "verified_by": f"{lang} parser"})
                    text, lines = healed, healed.splitlines()
                else:                                               # partial progress is not kept: all-or-nothing
                    for s in syn:
                        s.fix_note = "automatic repair could not fully fix the file; left unchanged"
            found += syn
        if syn and any(s.status == "open" for s in syn) and lang in ("python", "javascript", "c", "json"):
            ctx.add(found)                                           # cannot trust deeper analysis of unparsable code
            ctx.add(scan_secrets(text, rel, lang))
            return
        found += self.scan(ctx.files, rel, lang, text)
        if lang == "c":                                              # the compiler's own security / quality warnings
            found += [f for f in TC.check_c(text, rel, includes) if f.category != "error"]
        ctx.add(found)

    @staticmethod
    def _still_broken(lang: str, text: str, rel: str, includes) -> bool:
        if lang == "python":
            return PA.syntax_error(text, rel) is not None
        if lang == "javascript":
            return bool(TC.check_js(text, rel))
        if lang == "c":
            return any(f.category == "error" for f in TC.check_c(text, rel, includes))
        if lang == "json":
            return bool(TC.check_json(text, rel))
        return True


def _special_files(rel: str, lang: str, text: str) -> List[Finding]:
    out: List[Finding] = []
    base = os.path.basename(rel).lower()
    lines = text.splitlines()
    if base == "requirements.txt" or (lang == "requirements"):
        for i, ln in enumerate(lines):
            s = ln.strip()
            if not s or s.startswith("#"):
                continue
            if re.search(r"--(extra-)?index-url\s+http://|--trusted-host", s):
                out.append(Finding(file=rel, line=i + 1, language="requirements", category="security", rule_id="REQ-INSECURE-INDEX",
                                   title="Package index over plain HTTP / trusted-host", severity="High", confidence=0.9, cwe=(494, 319),
                                   message="Dependencies can be replaced in transit.", recommendation="Use an https:// index and drop --trusted-host.",
                                   snippet=s[:120], agent="deps"))
            elif not s.startswith("-") and not re.search(r"(==|~=|>=|<=|@|===)", s):
                out.append(Finding(file=rel, line=i + 1, language="requirements", category="quality", rule_id="REQ-UNPINNED",
                                   title=f"Unpinned dependency: {s.split('[')[0]}", severity="Low", confidence=0.8, cwe=(1104,),
                                   message="Any future (possibly compromised or breaking) release is installed automatically.",
                                   recommendation="Pin versions (pkg==1.2.3) and use a lock file with hashes (pip-compile --generate-hashes).",
                                   snippet=s[:120], agent="deps"))
    if base == "package.json":
        for i, ln in enumerate(lines):
            if re.search(r"\"[^\"]+\"\s*:\s*\"(\*|latest|x)\"", ln):
                out.append(Finding(file=rel, line=i + 1, language="json", category="quality", rule_id="NPM-UNPINNED",
                                   title="Dependency on '*' / latest", severity="Low", confidence=0.8, cwe=(1104,),
                                   message="Every install can pull a different (or hijacked) version.",
                                   recommendation="Use a semver range with a lockfile (package-lock.json) and `npm ci`.", snippet=ln.strip()[:120], agent="deps"))
    if lang == "shell" and lines and lines[0].startswith("#!") and "bash" in lines[0] and not re.search(r"^\s*set\s+-[a-z]*e", text, re.M):
        from .core import Edit
        out.append(Finding(file=rel, line=1, language="shell", category="quality", rule_id="SH-NO-STRICT",
                           title="Script does not stop on errors", severity="Info", confidence=0.6,
                           message="Without 'set -euo pipefail' a failed command is ignored and later commands run on bad state.",
                           recommendation="Add 'set -euo pipefail' after the shebang.", snippet=lines[0][:80], agent="shell",
                           fix=Fix("Add 'set -euo pipefail'", [Edit(2, 1, ["set -euo pipefail"])], TIER_PROPOSED,
                                   behavior_note="Scripts that relied on ignoring failures or unset variables will now exit.")))
    return out


# ─────────────────────────────────────────────────────────────────────────────
_IMPACT_SEV = {"high": "Medium", "medium": "Low", "low": "Low"}


class CppAgent(Agent):
    """Wraps the original compiler-backed C++ pipeline.  Every claimed fix is a g++ recompile + relink verified one."""
    name = "cpp"

    def run(self, ctx: Context) -> None:
        proj = ctx.proj
        if not ctx.opts.cpp:
            return
        proj.rescan()
        if not proj.sources:
            return
        import project as P
        o = ctx.opts
        try:
            res = P.analyze_project(proj, optimize=True, jobs=o.jobs, cxxflags=o.cxxflags, link_flags=o.link_flags)
        except Exception as e:                                          # never let one engine take the whole audit down
            ctx.notes.append(f"C++ engine failed: {e}")
            ctx.trace.log(self.name, "error", error=str(e))
            return
        before = self._convert(res)
        ctx.cpp = {"sources": len(proj.sources), "headers": len(proj.headers), "compile_ok": res.compile_ok,
                   "link_ok": res.link_ok, "blocked": res.blocked, "blocked_files": dict(res.blocked_files),
                   "errors": res.error_count, "link_errors": len(res.link_errors)}
        cpp_set = set(proj.all_code)                    # the C++ Sentinel judges ONLY the C++ part (scripts are the Malware agent's job)
        from agents import sentinel as SN
        try:
            srep = SN.scan_project(proj, None)
            inds = [i for i in srep.indicators if i.file in cpp_set and i.file in ctx.files]
            cpp_score = sum(i.weight for i in inds if not i.rule.startswith("SEN-GATE"))
        except Exception:                               # noqa: BLE001
            srep, inds, cpp_score = None, [], 0
        if cpp_score >= SN.THRESHOLD_MALICIOUS:
            for rel in sorted({i.file for i in inds}):
                if not ctx.files[rel].quarantined:
                    MalwareAgent._quarantine(ctx, rel, "C++ Sentinel verdict MALICIOUS: " + ", ".join(
                        sorted({i.rule for i in inds if i.file == rel})), None)
            ctx.notes.append("C++ Sentinel judged part of the C++ sources malicious; those files were quarantined.")
            if hasattr(proj, "rescan"):
                proj.rescan()
            cpp_set = set(proj.all_code)
        if o.fix and not res.blocked:
            try:
                from agents import orchestrator as OR
                ao = OR.Options(heal=True, harden=True, optimize=o.cpp_optimize, run=o.run, stdin=o.stdin,
                                run_args=list(o.run_args), jobs=o.jobs, cxxflags=list(o.cxxflags),
                                link_flags=list(o.link_flags), max_attempts=o.max_heal_attempts,
                                exclude=tuple(o.exclude), permissions=None, detect_build=True)
                stage = tempfile.mkdtemp(prefix="cd1_cpp_")          # C++ + build files only: scripts must not influence the C++ verdict
                try:
                    for rel in list(proj.all_code) + [r for r in ctx.files if os.path.basename(r) in ("CMakeLists.txt", "Makefile", "GNUmakefile")
                                                      and not ctx.files[r].quarantined]:
                        src_p = os.path.join(proj.root, *rel.split("/"))
                        if os.path.isfile(src_p):
                            dst_p = os.path.join(stage, *rel.split("/"))
                            os.makedirs(os.path.dirname(dst_p), exist_ok=True)
                            shutil.copyfile(src_p, dst_p)
                    ar = OR.run_agentic(stage, ao)               # Sentinel, Repairer, Integrator, Auditor, Optimizer, Verifier (+Tester)
                finally:
                    shutil.rmtree(stage, ignore_errors=True)
                try:
                    for rel in proj.all_code:
                        try:
                            nt = ar.proj.read(rel)
                        except OSError:
                            continue
                        if nt != proj.read(rel):
                            proj.write(rel, nt)
                    ch = list(ar.board.changes)
                    ctx.cpp["agentic"] = {"verdict": ar.verdict, "changes": len(ch),
                                          "rejected": len(ar.board.rejected), "run": bool(o.run)}
                    ctx.cpp["agentic_changes"] = [{"agent": c.agent, "file": c.file, "line": c.line, "rule": c.rule,
                                                   "title": c.title, "why": c.why, "impact": c.impact} for c in ch][:200]
                    ctx.cpp["heal"] = {"clean": ar.verdict in ("VERIFIED", "UNCHANGED"), "link_ok": None,
                                       "reason": ar.verdict, "steps": len(ch)}
                    dyn = ar.board.facts.get("dynamic")
                    if dyn and dyn.get("ran"):
                        r1 = dyn.get("final")
                        ctx.cpp["dynamic"] = {"exit": getattr(r1, "rc", None), "sanitizer_reports": len(getattr(r1, "sanitizer", []) or []),
                                              "same_behaviour": dyn.get("same"), "confined": getattr(r1, "confined", False)}
                    if ar.verdict == "BLOCKED":
                        ctx.notes.append("C++ agentic pipeline halted: the Sentinel judged the C++ sources malicious.")
                        srep = ar.board.facts.get("sentinel0")
                        bad = set(getattr(srep, "gate_blocked", {}) or {}) | {i.file for i in getattr(srep, "indicators", [])}
                        bad = {b for b in bad if b in ctx.files and b in set(proj.all_code)}
                        for rel in sorted(bad):
                            if ctx.files[rel].quarantined:
                                continue
                            why = "C++ Sentinel/safety-gate verdict: " + (
                                ", ".join(sorted({i.rule for i in srep.indicators if i.file == rel})) or (srep.gate_blocked.get(rel) if srep else "") or "malicious")
                            MalwareAgent._quarantine(ctx, rel, why, None)
                        if hasattr(proj, "rescan"):
                            proj.rescan()
                finally:
                    ar.proj.close()
            except Exception as e:
                ctx.notes.append(f"C++ heal/harden failed and was skipped: {e}")
            res2 = P.analyze_project(proj, optimize=True, jobs=o.jobs, cxxflags=o.cxxflags, link_flags=o.link_flags)
            after = self._convert(res2)
            ctx.cpp.update({"compile_ok_after": res2.compile_ok, "link_ok_after": res2.link_ok, "errors_after": res2.error_count})
            remaining = Counter(self._key(f) for f in after)
            for f in before:
                k = self._key(f)
                if remaining.get(k, 0) > 0:
                    remaining[k] -= 1
                else:
                    f.status = "fixed"
                    f.verified_by = "g++ recompile + relink + re-analysis (original engine)"
            ctx.findings_after_cpp = after
            for rel in proj.all_code:                                   # pull healed/hardened text back into the context
                try:
                    t = proj.read(rel)
                except OSError:
                    continue
                if ctx.orig.get(rel) is None:
                    ctx.orig[rel] = t
                if t != ctx.orig.get(rel):
                    ctx.texts[rel] = t
                    ctx.applied.append({"file": rel, "ids": [f.id for f in before if f.file == rel and f.status == "fixed"],
                                        "what": "C++ agentic pipeline: repair, harden, optimise (independently verified by rebuild + relink)", "source": "rule",
                                        "verified_by": "independent Verifier: from-scratch rebuild + relink + re-audit"})
                else:
                    ctx.texts.setdefault(rel, t)
        else:
            ctx.findings_after_cpp = list(before)
        for rel in proj.all_code:
            if rel in ctx.files and rel not in ctx.texts:
                try:
                    ctx.texts[rel] = ctx.orig[rel] = proj.read(rel)
                except OSError:
                    pass
        ctx.add(before)
        ctx.trace.log(self.name, "done", findings=len(before), cpp=ctx.cpp)

    @staticmethod
    def _key(f: Finding):
        return (f.file, f.rule_id, (f.title or "")[:50])

    @staticmethod
    def _convert(res) -> List[Finding]:
        out: List[Finding] = []
        conf = {"High": 0.9, "Medium": 0.6, "Low": 0.3}
        for rel, why in res.blocked_files.items():
            out.append(Finding(file=rel, line=1, language="cpp", category="security", rule_id="CPP-BLOCKED",
                               title="Safety gate blocked this file", severity="Critical", confidence=0.9, cwe=(78,), agent="cpp",
                               message=f"The pre-compile safety gate found a forbidden construct: {why}. Nothing was compiled or run.",
                               recommendation="Remove the shell/process-execution call or review it manually."))
        for e in res.unique_errors(show_all=True):
            is_err = e.error_type == "error"
            sev = "High" if is_err else {"critical": "High", "high": "Medium"}.get((e.severity or "").lower(), "Low")
            out.append(Finding(file=e.file or "", line=e.line or 1, column=e.column or 0, language="cpp",
                               category="error" if is_err else ("security" if e.group == "security" else "quality"),
                               rule_id=f"CPP-{(e.category or 'diag').upper()}", title=(e.message or "")[:140], severity=sev,
                               confidence=max(0.5, float(e.confidence or 0.8)), cwe=tuple(int(c) for c in (e.cwe or [])),
                               message=(e.explanation or e.message or "")[:900], recommendation=(e.suggestion or "See the explanation.")[:500],
                               snippet=(e.message or "")[:120], agent="cpp"))
        for e in res.link_errors:
            out.append(Finding(file=getattr(e, "file", "") or "(link)", line=getattr(e, "line", 1) or 1, language="cpp", category="error",
                               rule_id="CPP-LINK", title=(e.message or "link error")[:140], severity="High", confidence=1.0, agent="cpp",
                               message=(e.explanation or "The program cannot be linked.")[:900],
                               recommendation=(e.suggestion or "Define the missing symbol exactly once.")[:500]))
        for s in res.security_findings:
            out.append(Finding(file=s.file or "", line=s.line or 1, column=s.column or 0, language="cpp", category="security",
                               rule_id=s.rule_id or "CPP-SEC", title=s.vulnerability_type, severity=s.severity.capitalize(),
                               confidence=conf.get(s.confidence, 0.6), cwe=tuple(s.cwe), message=s.description, recommendation=s.recommendation,
                               snippet=(s.snippet or "")[:160], agent="cpp"))
        for o in res.optimization_findings:
            out.append(Finding(file=o.file or "", line=o.line or 1, language="cpp", category="performance", rule_id=o.rule_id or "CPP-PERF",
                               title=o.kind, severity=_IMPACT_SEV.get((o.impact or "").lower(), "Low"), confidence=0.6,
                               message=o.description, recommendation=o.suggestion, agent="cpp"))
        seen, uniq = set(), []
        for f in out:
            k = (f.file, f.line, f.rule_id, f.title)
            if k not in seen:
                seen.add(k)
                uniq.append(f)
        return uniq


class RiskAgent(Agent):
    name = "risk"

    def run(self, ctx: Context) -> None:
        RK.score_all(ctx.findings, ctx.files)
        ctx.risk_before = RK.project_score([f for f in ctx.findings if f.status != "quarantined" or f.category == "malware"])
        ctx.trace.log(self.name, "scored", risk_before=ctx.risk_before, grade=RK.grade(ctx.risk_before))
