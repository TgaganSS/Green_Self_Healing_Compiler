"""
repair.py - VerifierAgent (the gate), FixAgent (rule fixes, iterated to a fixpoint) and LLMFixAgent (untrusted proposer).

A change is kept ONLY if the Verifier says so:
  1 syntax      the file still parses/compiles (or, if it was already broken, is no worse)
  2 findings    each fixed rule has fewer hits, NO rule has more hits (nothing new introduced)
  3 malware     the malware score did not rise (LLM text must score < 0.30)
  4 integration public API of the file unchanged; names other files import from it still exist
  5 size        LLM edits are limited to 40 changed lines
"""
from __future__ import annotations

import difflib
import json
import re
from collections import Counter
from typing import Dict, List, Optional, Tuple

from . import integrity as IN
from . import malware as MW
from . import pyanalyzer as PA
from . import toolcheck as TC
from .agents import Agent, AnalystAgent, Context
from .core import Edit, Finding, Fix, SEV_RANK, TIER_AUTO, TIER_PROPOSED, apply_edits, edits_overlap
from .llm import LLMError, build_user_prompt, parse_reply, SYSTEM


# ─────────────────────────────────────────────────────────────────────────────
class Verifier:
    def __init__(self, ctx: Context):
        self.ctx = ctx

    def _syntax(self, lang: str, rel: str, old: str, new: str) -> Tuple[bool, str, str]:
        if lang == "python":
            eo, en = PA.syntax_error(old, rel), PA.syntax_error(new, rel)
            if en and not eo:
                return False, f"change makes the file unparsable (line {en.lineno}: {en.msg})", ""
            if en and eo and (en.lineno or 0) < (eo.lineno or 0):
                return False, "change moves the syntax error earlier", ""
            return True, "", "python compile()" if not en else "python (file was already broken: no regression)"
        if lang == "javascript":
            po, pn = TC._js_parse(old), TC._js_parse(new)
            if pn and not po:
                return False, f"change makes the file unparsable ({pn[1]})", ""
            return True, "", "node --check"
        if lang == "c":
            inc = [self.ctx.root]
            eo = sum(d["kind"] != "warning" for d in TC._gcc_diags(old, inc))
            en = sum(d["kind"] != "warning" for d in TC._gcc_diags(new, inc))
            return (en <= eo), ("change adds compiler errors" if en > eo else ""), "gcc -fsyntax-only"
        if lang == "json":
            return (not TC.check_json(new, "x")) or bool(TC.check_json(old, "x")), "change breaks the JSON", "json.loads"
        if lang == "yaml":
            return (not TC.check_yaml(new, "x")) or bool(TC.check_yaml(old, "x")), "change breaks the YAML", "yaml.safe_load"
        if lang == "shell":
            return (not TC.check_shell(new, "x")) or bool(TC.check_shell(old, "x")), "change breaks the script syntax", "bash -n"
        so, sn = TC._js_delims(old), TC._js_delims(new)             # no parser available: structural balance only
        bo, bn = len(so[0]) + len(so[1]), len(sn[0]) + len(sn[1])
        return (bn <= bo), ("change unbalances brackets" if bn > bo else ""), "bracket balance only (no parser for this language here)"

    def check(self, rel: str, old: str, new: str, fixed: Counter, llm: bool = False) -> Tuple[bool, str, str]:
        lang = self.ctx.files[rel].language
        fi = self.ctx.files[rel]
        ok, why, how = self._syntax(lang, rel, old, new)
        if not ok:
            return False, why, ""
        rep_old, rep_new = MW.scan_text(old, rel, lang, fi.is_test), MW.scan_text(new, rel, lang, fi.is_test)
        if rep_new.score > rep_old.score + 0.02 or (llm and rep_new.score >= 0.30):
            return False, f"malware score would rise to {rep_new.score} (indicators: {[h[0] for h in rep_new.hits]})", ""
        so = Counter(f.rule_id for f in AnalystAgent.scan(self.ctx.files, rel, lang, old))
        sn = Counter(f.rule_id for f in AnalystAgent.scan(self.ctx.files, rel, lang, new))
        for rid, n in sn.items():
            if n > so.get(rid, 0) - fixed.get(rid, 0):
                if fixed.get(rid):
                    return False, f"{rid} still present {n}x after the fix (expected <= {so.get(rid, 0) - fixed[rid]})", ""
                return False, f"change introduces a new finding: {rid}", ""
        if lang == "python":
            ao, an = IN.py_api_surface(old), IN.py_api_surface(new)
            if ao is not None and an is not None and ao != an:
                gone = sorted(set(ao) ^ set(an)) or sorted(k for k in ao if ao[k] != an.get(k))
                return False, f"public API of the module changed: {gone[:3]}", ""
            do, dn = IN.py_defined_names(old), IN.py_defined_names(new)
            if do is not None and dn is not None:
                files = dict(self.ctx.texts)
                for name in sorted(do - dn):
                    if IN.imported_from_elsewhere(files, rel, name):
                        return False, f"'{name}' would disappear but another file imports it from this module", ""
        if llm:
            changed = sum(1 for l in difflib.ndiff(old.splitlines(), new.splitlines()) if l[:1] in "+-")
            if changed > 80:
                return False, f"edit touches {changed} lines (limit 40 changed lines)", ""
            gained = sorted(k for k, rx in _CAPABILITIES.items() if rx.search(new) and not rx.search(old))
            if gained:                                   # a security fix must not give the file new reach (network, processes, environment)
                return False, "LLM edit adds new capabilities (" + ", ".join(gained) + "); a fix must only remove risk", ""
        return True, "", how


_CAPABILITIES = {k: re.compile(v) for k, v in {
    "network": r"\b(requests|urllib|httpx|aiohttp|http\.client|socket|ftplib|smtplib|telnetlib|paramiko|websocket)\b|\b(fetch|XMLHttpRequest|WebSocket|axios)\b|"
               r"net/http|java\.net|HttpClient|curl_init|file_get_contents\s*\(\s*[\"']https?:|\b(curl|wget|nc)\s",
    "process": r"\b(subprocess|os\.system|os\.popen|os\.exec\w*|pty\.spawn|child_process|Runtime\.getRuntime|ProcessBuilder|exec\.Command|shell_exec|proc_open|passthru)\b",
    "dynamic-code": r"\b(eval|exec|compile|__import__|importlib|Function)\s*\(",
    "environment": r"\bos\.environ\b|\bos\.getenv\b|\bprocess\.env\b|\bSystem\.getenv\b|\bgetenv\s*\(|\bENV\[",
    "credential-files": r"\.ssh\b|id_rsa|/etc/shadow|\.aws/credentials|\.netrc",
}.items()}


def _merge(fixes: List[Tuple[Finding, Fix]]) -> List[Tuple[Finding, Fix]]:
    """Greedy, severity-first selection of fixes whose edits do not overlap (identical insertions are shared)."""
    order = sorted(fixes, key=lambda p: (SEV_RANK.get(p[0].severity, 9), -p[0].confidence, p[0].line))
    chosen: List[Tuple[Finding, Fix]] = []
    used: List[Edit] = []
    for f, fx in order:
        clash = False
        for e in fx.edits:
            for u in used:
                same_ins = e.end < e.start and u.end < u.start and e.start == u.start and e.new_lines == u.new_lines
                if edits_overlap(e, u) and not same_ins:
                    clash = True
                    break
            if clash:
                break
        if not clash:
            chosen.append((f, fx))
            used += fx.edits
    return chosen


def _edits_of(chosen: List[Tuple[Finding, Fix]]) -> List[Edit]:
    seen, out = set(), []
    for _f, fx in chosen:
        for e in fx.edits:
            k = (e.start, e.end, tuple(e.new_lines))
            if e.end < e.start and k in seen:
                continue
            seen.add(k)
            out.append(e)
    return out


class FixAgent(Agent):
    name = "fixer"

    def run(self, ctx: Context) -> None:
        if not ctx.opts.fix:
            return
        v = Verifier(ctx)
        targets = sorted({f.file for f in ctx.findings if f.fix and f.status == "open"})
        for rel in targets:
            if rel not in ctx.texts or ctx.files[rel].quarantined:
                continue
            self._file(ctx, v, rel)
        ctx.trace.log(self.name, "done", applied=len(ctx.applied), rejected=len(ctx.rejected))

    def _wanted(self, ctx: Context, f: Finding, fx: Fix) -> bool:
        if f.confidence < ctx.opts.min_conf:
            return False
        if fx.tier == TIER_AUTO:
            return True
        return fx.tier == TIER_PROPOSED and ctx.opts.apply_proposed

    def _mark(self, ctx: Context, rel: str, rule: str, n: int, how: str, fx: Fix) -> List[str]:
        ids = []
        for f in ctx.findings:
            if n <= 0:
                break
            if f.file == rel and f.rule_id == rule and f.status in ("open", "proposed"):
                f.status, f.verified_by = "fixed", how
                f.fix = f.fix or fx
                ids.append(f.id)
                n -= 1
        return ids

    def _file(self, ctx: Context, v: Verifier, rel: str) -> None:
        lang = ctx.files[rel].language
        for rnd in range(ctx.opts.max_rounds):
            text = ctx.texts[rel]
            fresh = AnalystAgent.scan(ctx.files, rel, lang, text) if rnd else [f for f in ctx.findings if f.file == rel and f.status == "open"]
            cands = [(f, f.fix) for f in fresh if f.fix and self._wanted(ctx, f, f.fix)]
            if not cands:
                return
            chosen = _merge(cands)
            new = apply_edits(text, _edits_of(chosen))
            counts = Counter(f.rule_id for f, _ in chosen)
            ok, why, how = v.check(rel, text, new, counts)
            accepted: List[Tuple[Finding, Fix]] = []
            if ok:
                accepted, cur = chosen, new
            else:                                                       # bisect: keep the fixes that pass one by one
                cur = text
                for f, fx in chosen:
                    cand = apply_edits(cur, fx.edits)
                    ok1, why1, how1 = v.check(rel, cur, cand, Counter({f.rule_id: 1}))
                    if ok1:
                        accepted.append((f, fx))
                        cur, how = cand, how1
                    else:
                        f.fix_note = f"rejected by verifier: {why1}"
                        ctx.rejected.append({"file": rel, "rule": f.rule_id, "line": f.line, "why": why1, "source": fx.source})
            if not accepted or cur == text:
                return
            ctx.texts[rel] = cur
            for rule, n in Counter(f.rule_id for f, _ in accepted).items():
                fx0 = next(fx for f, fx in accepted if f.rule_id == rule)
                ids = self._mark(ctx, rel, rule, n, f"{how}; rescan: fewer '{rule}', nothing new; API preserved", fx0)
                ctx.applied.append({"file": rel, "ids": ids, "what": fx0.description + (f" (x{n})" if n > 1 else ""),
                                    "source": fx0.source, "verified_by": how, "tier": fx0.tier})
        return


class ProposedAgent(Agent):
    """Verified behaviour-changing fixes that were NOT applied: collected as proposed.patch for a human to accept."""
    name = "proposals"

    def run(self, ctx: Context) -> None:
        if ctx.opts.apply_proposed:
            return
        v = Verifier(ctx)
        for rel in sorted(ctx.texts):
            fi = ctx.files[rel]
            if fi.quarantined:
                continue
            lang, text = fi.language, ctx.texts[rel]
            fresh = AnalystAgent.scan(ctx.files, rel, lang, text)
            cands = [(f, f.fix) for f in fresh if f.fix and f.fix.tier == TIER_PROPOSED and f.confidence >= ctx.opts.min_conf]
            if not cands:
                continue
            cur = text
            done: List[Finding] = []
            for f, fx in _merge(cands):
                cand = apply_edits(cur, fx.edits)
                ok, why, how = v.check(rel, cur, cand, Counter({f.rule_id: 1}))
                if ok:
                    cur = cand
                    done.append(f)
            if cur != text:
                ctx.proposed_text[rel] = cur
                for rule, n in Counter(f.rule_id for f in done).items():
                    for f in ctx.findings:
                        if n <= 0:
                            break
                        if f.file == rel and f.rule_id == rule and f.status == "open":
                            f.status = "proposed"
                            f.verified_by = "verified (parses, nothing new) but changes behaviour: review proposed.patch"
                            f.fix = f.fix or next(fx for ff, fx in cands if ff.rule_id == rule)
                            n -= 1


class LLMFixAgent(Agent):
    """Optional.  For HIGH/CRITICAL findings that have no mechanical fix the model proposes a window replacement; the
    Verifier must accept it.  Rejections are fed back (max 3 attempts).  Default: result goes to proposed.patch."""
    name = "llm"

    def run(self, ctx: Context) -> None:
        o = ctx.opts
        if not (o.fix and o.llm.available()):
            return
        v = Verifier(ctx)
        todo = [f for f in ctx.findings if f.status == "open" and f.severity in ("Critical", "High") and f.category in ("security", "secret", "error")
                and not f.fix and f.file in ctx.texts and f.language and f.language != "cpp"]
        todo.sort(key=lambda f: -f.risk)
        for f in todo:
            if ctx.llm_calls >= o.llm_budget:
                ctx.notes.append(f"LLM budget of {o.llm_budget} requests exhausted; remaining findings left as advice")
                break
            self._one(ctx, v, f)

    def _one(self, ctx: Context, v: Verifier, f: Finding) -> None:
        o, rel = ctx.opts, f.file
        text = ctx.texts[rel]
        lines = text.splitlines()
        fresh = [g for g in AnalystAgent.scan(ctx.files, rel, f.language, text) if g.rule_id == f.rule_id]
        if not fresh and f.category != "error":
            return                                              # already gone (fixed by another change)
        line = min(fresh, key=lambda g: abs(g.line - f.line)).line if fresh else f.line
        lo, hi = max(1, line - 12), min(len(lines), line + 12)
        feedback = ""
        for attempt in range(3):
            if ctx.llm_calls >= o.llm_budget:
                return
            ctx.llm_calls += 1
            prompt, _ = build_user_prompt(rel, f.language, lines, lo, hi, f, feedback)
            try:
                raw = o.llm.complete(SYSTEM, prompt, 1500)
                obj = parse_reply(raw)
            except LLMError as e:
                ctx.trace.log(self.name, "bad-reply", file=rel, rule=f.rule_id, error=str(e), attempt=attempt + 1)
                feedback = f"Your previous reply was unusable ({e}). Reply with the JSON object only."
                continue
            s, e_, rep = obj["start"], obj["end"], obj["replacement"]
            if s == 0 and e_ == 0:
                ctx.trace.log(self.name, "declined", file=rel, rule=f.rule_id, why=str(obj.get("explanation", ""))[:200])
                return
            if not (lo <= s <= e_ <= hi):
                feedback = f"Rejected: lines must stay inside {lo}-{hi} (got {s}-{e_})."
                continue
            new = apply_edits(text, [Edit(s, e_, rep.split("\n"))])
            ok, why, how = v.check(rel, text, new, Counter({f.rule_id: 1}), llm=True)
            if not ok:
                feedback = f"Rejected by the verifier: {why}. Produce a different minimal fix."
                ctx.trace.log(self.name, "rejected", file=rel, rule=f.rule_id, why=why, attempt=attempt + 1)
                ctx.rejected.append({"file": rel, "rule": f.rule_id, "line": f.line, "why": why, "source": "llm"})
                continue
            expl = str(obj.get("explanation", ""))[:400]
            how = f"{how}; LLM {o.llm.name}/{o.llm.model}, verified gate passed (attempt {attempt + 1})"
            if o.apply_llm:
                ctx.texts[rel] = new
                f.status, f.verified_by, f.fix_note = "fixed", how, "LLM-authored: " + expl
                ctx.applied.append({"file": rel, "ids": [f.id], "what": f"LLM fix: {expl}", "source": "llm", "verified_by": how, "tier": "llm"})
            else:
                f.status, f.verified_by, f.fix_note = "proposed", how, "LLM-authored: " + expl
                ctx.llm_proposals.append({"file": rel, "id": f.id, "rule": f.rule_id, "before": text, "after": new, "explanation": expl, "verified_by": how})
            ctx.trace.log(self.name, "accepted", file=rel, rule=f.rule_id, applied=o.apply_llm)
            return
