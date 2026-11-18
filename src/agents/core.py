"""Agent infrastructure: shared blackboard, trace, checkpoints.

Design rules
  * Agents never talk to each other directly; they read/write the Blackboard and the Orchestrator decides order.
  * Maker / Checker separation: agents that CHANGE code (repairer, auditor, optimizer, integrator) never decide
    whether their change is acceptable - the Verifier does, from scratch.
  * Every change is a Change record (what, why, evidence) so the final report can justify it.
"""
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional


@dataclass
class Change:
    agent: str
    file: str
    line: Optional[int]
    rule: str
    title: str
    why: str
    before: str = ""
    after: str = ""
    impact: str = ""                    # e.g. "O(n^2) -> O(n)", "avoids a copy per call"
    verified: bool = False


@dataclass
class TraceEvent:
    t: float
    agent: str
    action: str
    detail: str = ""
    ok: Optional[bool] = None


class Blackboard:
    """Shared state for one run."""

    def __init__(self, proj, options):
        self.proj = proj
        self.opt = options
        self.facts: Dict[str, object] = {}
        self.changes: List[Change] = []
        self.rejected: List[Change] = []        # proposed but failed verification
        self.trace: List[TraceEvent] = []
        self.warnings: List[str] = []
        self.checkpoints: Dict[str, Dict[str, str]] = {}
        self._t0 = time.time()
        self._builder = None
        self.progress: Optional[Callable[[TraceEvent], None]] = None

    # -- one memoising Builder shared by the MAKERS' internal checks (the Verifier never uses it) --
    def builder(self):
        if self._builder is None:
            import project as P
            self._builder = P.Builder(self.proj, "heal", self.opt.jobs, self.opt.cxxflags, self.opt.link_flags)
        return self._builder

    def close(self) -> None:
        if self._builder is not None:
            import shutil
            shutil.rmtree(self._builder.objdir, ignore_errors=True)
            self._builder = None

    # -- tracing --
    def log(self, agent: str, action: str, detail: str = "", ok: Optional[bool] = None) -> None:
        ev = TraceEvent(round(time.time() - self._t0, 2), agent, action, detail, ok)
        self.trace.append(ev)
        if self.progress:
            self.progress(ev)

    # -- snapshots of the work tree (code files only) --
    def snapshot(self) -> Dict[str, str]:
        return {rel: self.proj.read(rel) for rel in self.proj.all_code}

    def checkpoint(self, name: str) -> None:
        self.checkpoints[name] = self.snapshot()

    def restore(self, name: str) -> None:
        snap = self.checkpoints[name]
        for rel, text in snap.items():
            if self.proj.read(rel) != text:
                self.proj.write(rel, text)


class Agent:
    """Base class. Subclasses implement run(board)."""
    name = "agent"
    role = ""

    def run(self, board: Blackboard) -> None:        # pragma: no cover - interface
        raise NotImplementedError
