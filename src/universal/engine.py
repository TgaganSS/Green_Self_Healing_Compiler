"""engine.py - IntegrationAgent + the orchestrator `run_audit`."""
from __future__ import annotations

import hashlib
import os
import shutil
import time
import zipfile
from typing import Dict, List

from . import integrity as IN
from . import report as RP
from . import risk as RK
from .agents import (Agent, AnalystAgent, Context, CppAgent, IntakeAgent, MalwareAgent, Options, RiskAgent, write_text)
from .core import SEV_RANK
from .repair import FixAgent, LLMFixAgent, ProposedAgent


class IntegrationAgent(Agent):
    """Final cross-file check, re-scan of the result (risk after), and writing the secured output + reports."""
    name = "integrator"

    def run(self, ctx: Context) -> None:
        import project as P
        changed = [r for r in ctx.texts if ctx.texts[r] != ctx.orig.get(r)]
        # 1. cross-file integrity: anything we changed must not break another file
        for _ in range(3):
            before = {r: t for r, t in ctx.orig.items()}
            after = dict(ctx.texts)
            problems = IN.new_breakage(before, after)
            bad_files = {p.split(":")[0] for p in problems if p.split(":")[0] in changed}
            qmods = [p for p in problems if p.split(":")[0] not in changed]
            if not bad_files:
                ctx.integrity = qmods
                break
            for rel in bad_files:
                ctx.texts[rel] = ctx.orig[rel]
                ctx.rejected.append({"file": rel, "rule": "integration", "line": 1, "why": "; ".join(p for p in problems if p.startswith(rel)), "source": "integrator"})
                for f in ctx.findings:
                    if f.file == rel and f.status == "fixed":
                        f.status, f.fix_note = "open", "fix rolled back: it broke cross-file integration"
                changed = [r for r in ctx.texts if ctx.texts[r] != ctx.orig.get(r)]
        else:
            ctx.integrity = IN.new_breakage(ctx.orig, ctx.texts)
        # 2. write final texts into the work tree
        for rel in changed:
            write_text(os.path.join(ctx.root, *rel.split("/")), ctx.texts[rel])
        # 3. fresh re-scan of the result => risk after
        fresh: List = []
        for rel, text in ctx.texts.items():
            fi = ctx.files.get(rel)
            if fi and fi.language and not fi.quarantined:
                fresh += AnalystAgent.scan(ctx.files, rel, fi.language, text)
        fresh += [f for f in ctx.findings if f.status == "open" and f.category in ("error", "malware") and f.language != "cpp"]
        fresh += ctx.findings_after_cpp
        seen, uniq = set(), []
        for f in fresh:
            k = (f.file, f.line, f.rule_id, f.title)
            if k not in seen:
                seen.add(k)
                uniq.append(f)
        RK.score_all(uniq, ctx.files)
        ctx.findings_after = uniq
        ctx.risk_after = RK.project_score(uniq)
        alt: List = []
        for rel, text in ctx.texts.items():
            fi = ctx.files.get(rel)
            if fi and fi.language and fi.language != "cpp" and not fi.quarantined:
                alt += AnalystAgent.scan(ctx.files, rel, fi.language, ctx.proposed_text.get(rel, text))
        alt += [f for f in uniq if f.language == "cpp" or f.category in ("error", "malware")]
        RK.score_all(alt, ctx.files)
        ctx.risk_if_proposed = RK.project_score(alt)
        hi = lambda fs: sum(1 for f in fs if f.severity in ("Critical", "High") and f.category != "quality")
        ctx.counts = {"high_before": hi([f for f in ctx.findings if f.status != "quarantined" or f.category == "malware"]),
                      "high_after": hi(uniq), "high_if_proposed": hi(alt)}
        # 4. output
        self._write(ctx, P)

    def _write(self, ctx: Context, P) -> None:
        proj = ctx.proj
        dest = ctx.opts.out or P.default_output(proj, "secured")
        ctx.out_path = dest
        files = {
            "REPORT.md": RP.render_markdown(ctx), "report.json": RP.render_json(ctx), "report.sarif": RP.render_sarif(ctx),
            "changes.patch": RP.changes_patch(ctx), "proposed.patch": RP.proposed_patch(ctx), "trace.jsonl": ctx.trace.jsonl(),
        }
        if ctx.quarantined:
            files["QUARANTINE.md"] = RP.render_quarantine(ctx)
        files = {k: _clean(v) for k, v in files.items()}               # source text may hold undecodable bytes
        stale = os.path.join(ctx.root, "_cd1_report")                  # a previous audit's report must not be duplicated
        if os.path.isdir(stale):
            shutil.rmtree(stale, ignore_errors=True)
        if not ctx.opts.out and os.path.exists(dest) and proj.kind == "dir":
            n = 2                                                      # never delete an earlier result: pick a fresh name
            while os.path.exists(f"{dest}.{n}"):
                n += 1
            dest = f"{dest}.{n}"
            ctx.out_path = dest
            ctx.notes.append(f"the default output folder already existed, so this run wrote to {os.path.basename(dest)}")
        if proj.kind == "file":
            main = os.path.basename(ctx.src)
            if main in ctx.quarantined:
                ctx.out_path = ""
                sidecar = os.path.splitext(dest)[0]
            else:
                write_text(dest, ctx.texts.get(main, ctx.orig.get(main, "")))
                sidecar = os.path.splitext(dest)[0]
            for name, content in files.items():
                if content:
                    write_text(f"{sidecar}.{name}", content)
            return
        if dest.lower().endswith(".zip"):
            P.write_output(proj, dest)
            manifest = []
            with zipfile.ZipFile(dest, "a", zipfile.ZIP_DEFLATED) as zf:
                for n in zf.namelist():
                    manifest.append(f"{hashlib.sha256(zf.read(n)).hexdigest()}  {n}")
                files["MANIFEST.sha256"] = "\n".join(manifest) + "\n"
                for name, content in files.items():
                    if content:
                        zf.writestr(f"{proj.name}/_cd1_report/{name}", content)
        else:
            P.write_output(proj, dest)
            rd = os.path.join(dest, "_cd1_report")
            os.makedirs(rd, exist_ok=True)
            for name, content in files.items():
                if content:
                    write_text(os.path.join(rd, name), content)


def _clean(s: str) -> str:
    """Replace lone surrogates (bytes that were not valid UTF-8) so reports can always be encoded."""
    return s.encode("utf-8", "replace").decode("utf-8") if s else s


def run_audit(path: str, opts: Options = None) -> Context:
    opts = opts or Options()
    ctx = Context(src=os.path.abspath(path), opts=opts)
    pipeline = [IntakeAgent(), MalwareAgent(), AnalystAgent(), CppAgent(), RiskAgent(), FixAgent(), ProposedAgent(), LLMFixAgent(), IntegrationAgent()]
    try:
        for ag in pipeline:
            t = time.time()
            try:
                ag.run(ctx)
            except Exception as e:
                if ag.name in ("intake", "integrator"):
                    raise
                ctx.notes.append(f"agent '{ag.name}' failed and was skipped: {type(e).__name__}: {e}")
                ctx.trace.log(ag.name, "failed", error=f"{type(e).__name__}: {e}")
            ctx.trace.log(ag.name, "finished", seconds=round(time.time() - t, 2))
    finally:
        if ctx.qdir:
            shutil.rmtree(ctx.qdir, ignore_errors=True)
        if ctx.proj is not None:
            ctx.proj.close()
    return ctx
