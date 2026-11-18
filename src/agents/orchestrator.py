"""Orchestrator + specialist agents.

  Sentinel      -> is it safe to touch at all?  (malware / supply-chain indicators, quarantine of binaries)
  Diagnostician -> compile + link everything, classify + explain every error, security audit, perf advice
  Repairer      -> fix compile errors (rule-based healer; optional LLM proposer behind guardrails)
  Integrator    -> whole-project consistency (include guards, link plan, unresolved includes)
  Auditor       -> verified security hardening
  Optimizer     -> verified source-to-source optimisations
  Verifier      -> INDEPENDENT final check from scratch; rolls back to the last good checkpoint on failure
  Tester        -> (opt-in) sandboxed run, sanitizers, original-vs-final behaviour comparison
  Reporter      -> final file / zip / folder + patch + report

Makers (Repairer, Integrator, Auditor, Optimizer) never decide whether their own change is acceptable.
"""
import difflib
import os
import re
import shutil
import time
from collections import Counter
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Sequence, Tuple

import project as P
from compiler_runner import scan_source, _default_permissions
from secure_fixer import unified_diff
from security_analyzer import analyze_source, risk_score

from agents.core import Agent, Blackboard, Change, TraceEvent
from agents import sentinel as S
from agents import optimizer as O
from agents import dynamic as DYN

STAGES = ["original", "integrate", "repair", "audit", "optimize"]


@dataclass
class Options:
    heal: bool = True
    harden: bool = True
    optimize: bool = True
    run: bool = False                       # opt-in sandboxed execution
    llm: object = None                      # agents.llm.Provider or None
    stdin: bytes = b""
    run_args: Sequence[str] = ()
    jobs: Optional[int] = None
    cxxflags: Sequence[str] = ()
    link_flags: Sequence[str] = ()
    max_attempts: int = 30
    exclude: Sequence[str] = ()
    permissions: Optional[dict] = None
    llm_attempts: int = 2
    detect_build: bool = True               # read -std / -D / -l from CMakeLists.txt or Makefile
    progress: Optional[Callable[[TraceEvent], None]] = None


@dataclass
class Status:
    compile_ok: bool
    link_ok: bool
    errors: int
    per_file_errors: Dict[str, int]
    targets: list

    @property
    def built(self) -> bool:
        return self.compile_ok and self.link_ok


def build_status(proj, opt, use_builder=None) -> Status:
    """from-scratch compile + link of the current tree (fresh Builder, no memo, unless one is supplied)"""
    b = use_builder or P.Builder(proj, "heal", opt.jobs, opt.cxxflags, opt.link_flags)
    try:
        tus = b.compile_all(proj.sources, use_memo=use_builder is not None)
        per = {r: sum(1 for d in t.diags if d["type"] == "error" and not d.get("cascade")) for r, t in tus.items()}
        compile_ok = all(t.ok for t in tus.values()) and bool(tus)
        link_ok, targets = True, []
        if compile_ok:
            targets = b.link(tus)
            link_ok = all(t.ok for t in targets)
        return Status(compile_ok, link_ok, sum(per.values()), per, targets)
    finally:
        if use_builder is None:
            shutil.rmtree(b.objdir, ignore_errors=True)


def _finding_counter(proj) -> Counter:
    c: Counter = Counter()
    for rel in proj.all_code:
        for f in analyze_source(proj.read(rel), proj.abspath(rel), []):
            c[(rel, f.rule_id or f.vulnerability_type)] += 1
    return c


def _fcount(text: str, path: str) -> Counter:
    return Counter((f.rule_id or f.vulnerability_type) for f in analyze_source(text, path, []))


def _indicator_weight(rel: str, text: str) -> int:
    ind: List[S.Indicator] = []
    S._scan_code(rel, text, ind)
    best: Dict[str, int] = {}
    for i in ind:
        best[i.rule] = max(best.get(i.rule, 0), i.weight)
    return sum(best.values())


def _diff_changes(board, agent, rel, before, after, rule, title, why):
    board.changes.append(Change(agent, rel, None, rule, title, why, before, after, verified=True))


# ════════════════════════════════════════════════════════════════════════
class SentinelAgent(Agent):
    name, role = "Sentinel", "malware / supply-chain indicator scan and quarantine"

    def run(self, board):
        proj = board.proj
        rep = S.scan_project(proj, board.opt.permissions)
        board.facts["sentinel0"] = rep
        for rel, why in rep.quarantined:                      # only ever the WORK COPY is touched
            try:
                os.remove(proj.abspath(rel))
            except OSError:
                pass
        if rep.quarantined:
            proj.rescan()
        board.log(self.name, "scan", f"{rep.verdict} (score {rep.score}, {rep.scanned} files, "
                  f"{len(rep.indicators)} indicators, {len(rep.quarantined)} quarantined)", rep.verdict == "CLEAN")
        if rep.verdict == "MALICIOUS":
            board.facts["halt"] = "Sentinel verdict MALICIOUS: nothing is compiled, repaired or run."
        elif rep.gate_blocked:
            board.facts["halt"] = ("safety gate blocked " + ", ".join(sorted(rep.gate_blocked)) +
                                   ": the project is not compiled, repaired or run until those constructs are removed.")


class DiagnosticianAgent(Agent):
    name, role = "Diagnostician", "compile, link, classify, explain, security audit, performance advice"

    def run(self, board):
        res = P.analyze_project(board.proj, optimize=True, jobs=board.opt.jobs, permissions=board.opt.permissions,
                                cxxflags=board.opt.cxxflags, link_flags=board.opt.link_flags)
        board.facts["baseline"] = res
        board.facts["baseline_findings"] = _finding_counter(board.proj)
        board.facts["baseline_risk"] = res.risk
        board.log(self.name, "analyse", f"{res.error_count} error(s), {res.warning_count} warning(s), "
                  f"{len(res.security_findings)} security finding(s), {len(res.link_errors)} link error(s), "
                  f"build {'OK' if res.built else 'FAILED'}", res.built)
        board.facts["status0"] = build_status(board.proj, board.opt, use_builder=board.builder())


class RepairerAgent(Agent):
    name, role = "Repairer", "fix compile errors (rules first, optional LLM behind guardrails)"

    def run(self, board):
        opt, proj = board.opt, board.proj
        base = board.facts["baseline"]
        if base.compile_ok:
            board.log(self.name, "skip", "every file already compiles")
            return
        h = P.heal_project(proj, max_attempts=opt.max_attempts, jobs=opt.jobs, cxxflags=opt.cxxflags,
                           link_flags=opt.link_flags,
                           progress=lambda e: board.log(self.name, "fix", f"{e['file']}:{e['line']} [{e['category']}] "
                                                        f"{e['message']}", True))
        reverted = {(e["file"], e["line"]) for e in h.history if e["status"] == "reverted"}
        for e in h.history:
            if e["status"] == "fixed" and (e["file"], e.get("line")) not in reverted:
                before_after = h.changed.get(e["file"], ("", ""))
                board.changes.append(Change(self.name, e["file"], e.get("line"), "REPAIR-" + str(e.get("category")),
                                            f"fixed: {e['message']}",
                                            "the compiler error was classified and a rule-based fix was applied; the "
                                            "compiler re-verified the file after the edit", verified=True))
        board.facts["heal"] = h
        remaining = h.remaining
        if remaining and opt.llm:
            self._llm(board, remaining)
        board.log(self.name, "done", "clean" if (h.clean) else f"{len(remaining)} error(s) need a human or LLM", h.clean)

    # ---- LLM proposer, guarded ----
    def _llm(self, board, remaining):
        opt, proj = board.opt, board.proj
        by_file: Dict[str, List[dict]] = {}
        for d in remaining:
            by_file.setdefault(d.get("file") or "", []).append(d)
        for rel, diags in by_file.items():
            if rel not in proj.sources and rel not in proj.headers:
                continue
            for attempt in range(opt.llm_attempts):
                old = proj.read(rel)
                try:
                    cand = opt.llm.fix(rel, old, diags)
                except Exception as e:            # provider failures never abort the run
                    board.log(self.name, "llm", f"{rel}: provider error {type(e).__name__}", False)
                    break
                ok, why = self._guard(board, rel, old, cand)
                board.log(self.name, "llm", f"{rel}: attempt {attempt + 1} {'accepted' if ok else 'rejected - ' + why}", ok)
                if ok:
                    board.changes.append(Change(self.name, rel, None, "REPAIR-LLM",
                                                "model-proposed fix accepted by guardrails",
                                                "the rule-based healer could not fix this; the proposal passed the "
                                                "safety gate, did not raise sentinel indicators, changed < 50% of the "
                                                "file, reduced compiler errors and kept the project linking",
                                                verified=True))
                    break
                board.rejected.append(Change(self.name, rel, None, "REPAIR-LLM", "model proposal rejected", why))

    def _guard(self, board, rel, old, cand) -> Tuple[bool, str]:
        proj, opt = board.proj, board.opt
        if not cand or cand == old:
            return False, "no change proposed"
        viol = scan_source(cand, opt.permissions, include_dir=os.path.dirname(proj.abspath(rel)),
                           confine_root=proj.root)
        if viol:
            return False, "safety gate: " + str(viol[0])
        if _indicator_weight(rel, cand) > _indicator_weight(rel, old):
            return False, "raises sentinel indicators"
        a, b = old.splitlines(), cand.splitlines()
        if difflib.SequenceMatcher(None, a, b, autojunk=False).ratio() < 0.5:
            return False, "changes more than half of the file"
        before = build_status(proj, opt)
        proj.write(rel, cand)
        after = build_status(proj, opt)
        if after.per_file_errors.get(rel, 0) >= before.per_file_errors.get(rel, 0) and not after.compile_ok:
            proj.write(rel, old)
            return False, "does not reduce compiler errors"
        if after.errors > before.errors or (before.compile_ok and not after.built):
            proj.write(rel, old)
            return False, "makes the project build worse"
        return True, ""


class IntegratorAgent(Agent):
    name, role = "Integrator", "whole-project consistency: include guards, includes, link plan"

    _GUARD = re.compile(r"^\s*#\s*(?:pragma\s+once|ifndef\s+\w+\s*\n\s*#\s*define\s+\w+)", re.M)

    def run(self, board):
        proj = board.proj
        info = {"unguarded": [], "unresolved_includes": [], "orphan_headers": []}
        included: Counter = Counter()
        for rel in proj.all_code:
            text = proj.read(rel)
            for m in re.finditer(r'^\s*#\s*include\s*"([^"]+)"', text, re.M):
                tgt = m.group(1)
                base = os.path.dirname(proj.abspath(rel))
                found = None
                for d in [base] + list(proj.include_dirs):
                    cand = os.path.normpath(os.path.join(d, tgt))
                    if os.path.isfile(cand):
                        found = os.path.relpath(cand, proj.root).replace(os.sep, "/")
                        break
                if found:
                    included[found] += 1
                else:
                    info["unresolved_includes"].append((rel, tgt))
        for h in proj.headers:
            text = proj.read(h)
            head = "\n".join(l for l in text.splitlines()[:40])
            if not self._GUARD.search(head):
                info["unguarded"].append(h)
            if included[h] == 0:
                info["orphan_headers"].append(h)
        # fix: unguarded header included from 2+ places = latent redefinition errors (one batch, bisect on failure)
        todo = [h for h in info["unguarded"] if included[h] >= 2]
        if todo:
            sb = board.builder()
            before = build_status(proj, board.opt, use_builder=sb)
            olds = {h: proj.read(h) for h in todo}

            def guarded(h):
                nl = "\r\n" if "\r\n" in olds[h] else "\n"
                return "#pragma once" + nl + olds[h]

            def worse():
                after = build_status(proj, board.opt, use_builder=sb)
                return after.errors > before.errors or (before.built and not after.built)

            for h in todo:
                proj.write(h, guarded(h))
            keep = list(todo)
            if worse():
                for h in todo:
                    proj.write(h, olds[h])
                keep = []
                for h in todo:                                    # slow path: one at a time
                    proj.write(h, guarded(h))
                    if worse():
                        proj.write(h, olds[h])
                        board.rejected.append(Change(self.name, h, 1, "INT-GUARD", "include guard rejected",
                                                     "made the build worse"))
                    else:
                        keep.append(h)
            for h in keep:
                board.changes.append(Change(self.name, h, 1, "INT-GUARD", "added `#pragma once`",
                                            f"{h} is included from {included[h]} places and had no include guard; a "
                                            "second inclusion in one translation unit would be a redefinition error",
                                            "", "#pragma once", "no redefinition when included twice", True))
        board.facts["integration"] = info
        board.log(self.name, "integrate", f"{len(info['unguarded'])} unguarded header(s), "
                  f"{len(info['unresolved_includes'])} unresolved include(s), {len(info['orphan_headers'])} orphan header(s)")


class AuditorAgent(Agent):
    name, role = "Auditor", "verified security hardening"

    def run(self, board):
        proj = board.proj
        before = _finding_counter(proj)
        if not before:
            board.log(self.name, "skip", "no findings that need hardening")
            return
        hp = P.harden_project(proj, jobs=board.opt.jobs, cxxflags=board.opt.cxxflags, link_flags=board.opt.link_flags)
        for rel in hp.changed:
            for fx in hp.files[rel].applied:
                board.changes.append(Change(self.name, rel, fx.line, fx.rule, fx.description,
                                            "automatic secure-coding fix; the whole project was rebuilt and relinked "
                                            "after the edit and the file is rolled back otherwise",
                                            fx.before, fx.after, "removes the vulnerability class", True))
        for rel, why in hp.rolled_back.items():
            board.rejected.append(Change(self.name, rel, None, "HARDEN", "hardening rolled back", why))
        board.facts["harden"] = hp
        board.log(self.name, "harden", f"{sum(len(hp.files[r].applied) for r in hp.changed)} fix(es) in "
                  f"{len(hp.changed)} file(s), {len(hp.rolled_back)} rolled back, {len(hp.remaining)} finding(s) remain", True)


class OptimizerAgent(Agent):
    name, role = "Optimizer", "verified source-to-source optimisation with explanations"

    def run(self, board):
        proj, opt = board.proj, board.opt
        builder = board.builder()
        st = build_status(proj, opt, use_builder=builder)
        if not st.built:
            board.log(self.name, "skip", "the project does not build, so optimisations cannot be verified")
            return
        header_names = set()
        for h in proj.headers:
            header_names |= set(re.findall(r"\b([A-Za-z_]\w*)\s*\(", proj.read(h)))
        plan = {}                                   # rel -> (source, new source, candidates)
        for rel in proj.sources:
            src = proj.read(rel)
            cands = O.propose(src, rel, header_names)
            if cands:
                new = self._precheck(board, rel, src, cands)
                if new is not None:
                    plan[rel] = (src, new, cands)
        accepted = 0
        # fast path: everything at once, one build + one link; bisect on failure
        pending = dict(plan)
        for rel, (src, new, cands) in plan.items():
            proj.write(rel, new)
        if plan:
            st = build_status(proj, opt, use_builder=builder)
            if not st.built:
                bad = [r for r in plan if st.per_file_errors.get(r, 0) > 0]
                for rel in (bad or list(plan)):
                    proj.write(rel, plan[rel][0])
                if bad:
                    st = build_status(proj, opt, use_builder=builder)
                if bad and st.built:
                    pending = {r: v for r, v in plan.items() if r not in bad}
                    retry = bad
                else:                                  # link problem or unattributable: do it file by file
                    for rel in plan:
                        proj.write(rel, plan[rel][0])
                    build_status(proj, opt, use_builder=builder)
                    pending = {}
                    retry = list(plan)
                for rel in retry:
                    accepted += self._file_by_file(board, builder, rel, plan[rel][0], plan[rel][2])
            for rel, (src, new, cands) in pending.items():
                accepted += len(cands)
                self._record(board, rel, cands)
        board.log(self.name, "optimise", f"{accepted} verified transformation(s) in "
                  f"{len({c.file for c in board.changes if c.agent == self.name})} file(s)", True)

    def _precheck(self, board, rel, src, cands):
        proj, opt = board.proj, board.opt
        new = O.apply(src, cands)
        if new == src:
            return None
        if scan_source(new, opt.permissions, include_dir=os.path.dirname(proj.abspath(rel)), confine_root=proj.root):
            return None
        if _indicator_weight(rel, new) > _indicator_weight(rel, src):
            return None
        if sum(_fcount(new, rel).values()) > sum(_fcount(src, rel).values()):
            return None
        return new

    def _record(self, board, rel, cands):
        for c in cands:
            board.changes.append(Change(self.name, rel, c.line, c.rule, c.title,
                                        c.why + (f" Caveat: {c.caveat}." if c.caveat else ""),
                                        c.before, c.after, c.impact, True))

    def _file_by_file(self, board, builder, rel, src, cands) -> int:
        """slow path: all candidates of one file together, else each alone, else none"""
        if self._try(board, builder, rel, src, cands):
            return len(cands)
        keep = []
        for c in cands:
            if self._try(board, builder, rel, src, [c], record=False, restore=True):
                keep.append(c)
            else:
                board.rejected.append(Change(self.name, rel, c.line, c.rule, c.title,
                                             "failed verification (compile / link / safety)"))
        if keep and self._try(board, builder, rel, src, keep):
            return len(keep)
        return 0

    def _try(self, board, builder, rel, src, cands, record=True, restore=False) -> bool:
        proj, opt = board.proj, board.opt
        new = self._precheck(board, rel, src, cands)
        if new is None:
            return False
        proj.write(rel, new)
        st = build_status(proj, opt, use_builder=builder)
        ok = st.built
        if not ok or restore:
            proj.write(rel, src)
            if restore:
                build_status(proj, opt, use_builder=builder)   # keep the memo consistent
        if ok and record:
            self._record(board, rel, cands)
        return ok


# ════════════════════════════════════════════════════════════════════════
@dataclass
class VerifyReport:
    ok: bool
    reasons: List[str]
    status: Optional[Status] = None
    sentinel: Optional[S.SentinelReport] = None
    risk: int = 0
    findings: int = 0


class VerifierAgent(Agent):
    name, role = "Verifier", "independent from-scratch check; rolls back to the last good checkpoint"

    def check(self, board) -> VerifyReport:
        proj, opt = board.proj, board.opt
        reasons: List[str] = []
        st = build_status(proj, opt)                                   # fresh Builder, no memo
        base: Status = board.facts["status0"]
        if st.errors > base.errors:
            reasons.append(f"more compile errors than the original ({st.errors} > {base.errors})")
        if base.built and not st.built:
            reasons.append("the original built and linked; the result does not")
        sen = S.scan_project(proj, opt.permissions)
        s0 = board.facts["sentinel0"]
        new_ind = {(i.rule, i.file) for i in sen.indicators} - {(i.rule, i.file) for i in s0.indicators}
        if new_ind:
            reasons.append("new sentinel indicators: " + ", ".join(sorted(f"{r}@{f}" for r, f in new_ind)[:3]))
        if sen.verdict == "MALICIOUS":
            reasons.append("sentinel verdict MALICIOUS after changes")
        cnt = _finding_counter(proj)
        worse = [k for k, v in cnt.items() if v > board.facts["baseline_findings"].get(k, 0)]
        if worse:
            reasons.append("new security findings: " + ", ".join(f"{r}@{f}" for f, r in worse[:3]))
        risk = risk_score([f for rel in proj.all_code for f in analyze_source(proj.read(rel), proj.abspath(rel), [])])
        return VerifyReport(not reasons, reasons, st, sen, risk, sum(cnt.values()))

    def run(self, board):
        # choose the latest checkpoint that passes; the original always passes by definition
        order = [s for s in reversed(STAGES) if s in board.checkpoints]
        board.facts["verified_stage"] = None
        for stage in order:
            board.restore(stage)
            if stage == "original":
                vr = VerifyReport(True, [], build_status(board.proj, board.opt), board.facts["sentinel0"],
                                  board.facts["baseline_risk"], sum(board.facts["baseline_findings"].values()))
            else:
                vr = self.check(board)
            board.log(self.name, "verify", f"stage '{stage}': {'PASS' if vr.ok else 'FAIL - ' + '; '.join(vr.reasons)}", vr.ok)
            if vr.ok:
                board.facts["verified_stage"] = stage
                board.facts["verify"] = vr
                return
        board.facts["verify"] = vr


class TesterAgent(Agent):
    name, role = "Tester", "opt-in sandboxed execution, sanitizers, original-vs-final comparison"

    def run(self, board):
        opt, proj = board.opt, board.proj
        sen = board.facts["verify"].sentinel if board.facts.get("verify") else board.facts["sentinel0"]
        info = {"ran": False, "note": ""}
        board.facts["dynamic"] = info
        if sen.verdict != "CLEAN":
            info["note"] = f"refused to execute: sentinel verdict is {sen.verdict}"
            board.log(self.name, "refuse", info["note"], False)
            return
        if not DYN.sandbox_available():
            info["note"] = "no sandbox available on this machine (needs Linux `unshare -rn`); nothing was executed"
            board.log(self.name, "refuse", info["note"], False)
            return
        base_built = board.facts["status0"].built
        orig = None
        try:
            if base_built:
                orig = P.open_project(proj.origin, exclude=opt.exclude)
        except P.ProjectError:
            orig = None
        try:
            order = [s for s in reversed(STAGES) if s in board.checkpoints]
            start = order.index(board.facts.get("verified_stage") or "original")
            r0 = DYN.run_project(orig, opt.stdin, list(opt.run_args), jobs=opt.jobs, cxxflags=opt.cxxflags, link_flags=opt.link_flags) if orig else None
            if r0 is not None and not r0.built:
                r0 = None                      # the original cannot be built for execution: nothing to compare with
            r0_bad = bool(r0 and (r0.sanitizer or (r0.rc is not None and r0.rc < 0)))
            runs: Dict[str, object] = {}

            def run_stage(st):
                if st not in runs:
                    board.restore(st)
                    runs[st] = DYN.run_project(proj, opt.stdin, list(opt.run_args), jobs=opt.jobs, cxxflags=opt.cxxflags, link_flags=opt.link_flags)
                return runs[st]

            def ok_vs_original(r1):
                if r0 is None or not r1.built or DYN.same_behaviour(r0, r1):
                    return True
                # the original crashed / tripped a sanitizer: a repair or hardening SHOULD change that
                return r0_bad and len(r1.sanitizer) < len(r0.sanitizer)

            chosen = None
            for stage in order[start:]:
                r1 = run_stage(stage)
                ok = ok_vs_original(r1)
                if ok and stage == "optimize" and "audit" in board.checkpoints:
                    ok = DYN.same_behaviour(run_stage("audit"), r1)      # optimisations must preserve behaviour exactly
                if ok:
                    chosen = (stage, r1)
                    break
                board.log(self.name, "differs", f"stage '{stage}' behaves differently from what is acceptable "
                          f"(exit {r0.rc if r0 else '-'}->{r1.rc}); rolling back one stage", False)
            if chosen is None:                      # nothing matched; the original is the safe answer
                chosen = ("original", r0 or run_stage("original"))
            stage, r1 = chosen
            board.restore(stage)
            board.facts["verified_stage"] = stage
            info.update(ran=True, stage=stage, original=r0, final=r1, compared=r0 is not None,
                        same=(r0 is None or DYN.same_behaviour(r0, r1)), original_bad=r0_bad)
            if r0 is not None and stage != "original" and board.changes and any(c.agent == "Optimizer" for c in board.changes):
                t0, t1 = DYN.time_project(orig, opt.stdin, list(opt.run_args), cxxflags=opt.cxxflags, link_flags=opt.link_flags), DYN.time_project(proj, opt.stdin, list(opt.run_args), cxxflags=opt.cxxflags, link_flags=opt.link_flags)
                if t0 and t1:
                    info["time_before"], info["time_after"] = t0, t1
            board.log(self.name, "run", f"final exit {r1.rc if r1 else '-'}; sanitizer reports: "
                      f"{len(r1.sanitizer) if r1 else 0}; behaviour {'identical' if info['same'] else 'changed (original had sanitizer errors)' if info['original_bad'] else 'DIFFERENT'}"
                      + ("" if r0 else " (no baseline to compare)"), info["same"])
        finally:
            if orig:
                orig.close()


# ════════════════════════════════════════════════════════════════════════
@dataclass
class AgenticResult:
    proj: object
    board: Blackboard
    verdict: str
    final_changed: Dict[str, Tuple[str, str]] = field(default_factory=dict)
    baseline: object = None
    final_status: Optional[Status] = None
    final_findings: list = field(default_factory=list)
    final_risk: int = 0

    after: object = None                    # ProjectResult of the final tree


def run_agentic(path: str, options: Optional[Options] = None) -> AgenticResult:
    opt = options or Options()
    proj = P.open_project(path, exclude=opt.exclude)
    detected = None
    if opt.detect_build:
        import buildinfo
        detected = buildinfo.detect(proj.root)
        if detected.cxxflags or detected.link_flags:
            import dataclasses
            opt = dataclasses.replace(opt, cxxflags=detected.cxxflags + list(opt.cxxflags),
                                      link_flags=detected.link_flags + list(opt.link_flags))
    board = Blackboard(proj, opt)
    board.progress = opt.progress
    if detected and (detected.cxxflags or detected.link_flags):
        board.log("Orchestrator", "flags", f"from {', '.join(detected.sources)}: "
                  f"{' '.join(detected.cxxflags + detected.link_flags)}")
    board.facts["detected_flags"] = detected
    board.progress = opt.progress
    originals = board.snapshot()
    board.log("Orchestrator", "start", f"{proj.name}: {len(proj.sources)} source(s), {len(proj.headers)} header(s)")
    SentinelAgent().run(board)
    if "halt" in board.facts:
        board.facts["baseline"] = P.analyze_project(proj, optimize=False, permissions=opt.permissions, link=False)
        board.log("Orchestrator", "halt", board.facts["halt"], False)
        return AgenticResult(proj, board, "BLOCKED", baseline=board.facts["baseline"])
    DiagnosticianAgent().run(board)
    board.checkpoint("original")
    IntegratorAgent().run(board)            # first: a missing include guard looks like an error the healer cannot fix
    board.checkpoint("integrate")
    if opt.heal:
        RepairerAgent().run(board)
    board.checkpoint("repair")
    if opt.harden:
        AuditorAgent().run(board)
    board.checkpoint("audit")
    if opt.optimize:
        OptimizerAgent().run(board)
    board.checkpoint("optimize")
    VerifierAgent().run(board)
    if opt.run:
        TesterAgent().run(board)
    stage = board.facts.get("verified_stage") or "original"
    # drop changes that were rolled back
    keep_upto = STAGES.index(stage)
    agent_stage = {"Integrator": 1, "Repairer": 2, "Auditor": 3, "Optimizer": 4}
    for c in list(board.changes):
        if agent_stage.get(c.agent, 0) > keep_upto:
            board.changes.remove(c)
            board.rejected.append(Change(c.agent, c.file, c.line, c.rule, c.title,
                                         "rolled back by the Verifier / Tester", c.before, c.after))
    final_changed = {}
    for rel in proj.all_code:
        now = proj.read(rel)
        if rel in originals and originals[rel] != now:
            final_changed[rel] = (originals[rel], now)
    vr = board.facts.get("verify")
    final = AgenticResult(proj, board, "", final_changed, board.facts["baseline"],
                          vr.status if vr else None, [], vr.risk if vr else 0)
    final.after = P.analyze_project(proj, optimize=True, jobs=opt.jobs, permissions=opt.permissions,
                                    cxxflags=opt.cxxflags, link_flags=opt.link_flags)
    final.final_findings = [f for rel in proj.all_code
                            for f in analyze_source(proj.read(rel), proj.abspath(rel), [])]
    st = final.final_status
    if final_changed and st and st.built:
        final.verdict = "VERIFIED"
    elif final_changed:
        final.verdict = "PARTIAL"
    else:
        final.verdict = "UNCHANGED"
    board.close()
    board.log("Orchestrator", "finish", f"{final.verdict}: {len(final_changed)} file(s) changed, verified stage '{stage}'",
              final.verdict in ("VERIFIED", "UNCHANGED"))
    return final
