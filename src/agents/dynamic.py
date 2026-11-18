"""Dynamic tester - OPT-IN (--run).  Builds the project and executes it in a restricted sandbox.

Isolation (all best-effort, Linux): no network (`unshare -rn`), a private mount namespace whose root is an empty
tmpfs (only /usr, /bin, /lib* read-only, a minimal /dev and /proc are visible, so the program cannot read or write
the host's files), empty environment, private temp working dir,
CPU / file-size / open-file / process-count rlimits, wall-clock timeout, output cap, ASan hard RSS limit.
It is still *executing code*: it is refused unless the Sentinel verdict is CLEAN, and it is not a substitute
for a container or VM when the input is untrusted.
"""
import os
import re
import resource
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from typing import List, Optional

import diagnostics as D
from project import Builder, open_project

OUTPUT_CAP = 64 * 1024
_SAN_RE = re.compile(r"(ERROR: (?:Address|Leak|Thread|Memory)Sanitizer[^\n]*|[^\n]*runtime error:[^\n]*)")


@dataclass
class RunResult:
    built: bool = False
    build_error: str = ""
    rc: Optional[int] = None
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False
    sanitizer: List[str] = field(default_factory=list)
    seconds: Optional[float] = None
    skipped: str = ""
    confined: bool = False   # True: ran with a private filesystem root (host files not visible)


def sandbox_available() -> bool:
    if os.name != "posix" or not shutil.which("unshare"):
        return False
    try:
        r = subprocess.run(["unshare", "-rn", "true"], capture_output=True, timeout=10)
        return r.returncode == 0
    except Exception:
        return False


_CONFINE = r"""set -e
PATH=/usr/sbin:/sbin:/usr/bin:/bin
R=$(mktemp -d)
mount -t tmpfs -o size=64m tmpfs "$R"
mkdir -p "$R/usr" "$R/work" "$R/proc" "$R/dev" "$R/old"
mount --rbind /usr "$R/usr"
mount -o remount,bind,ro "$R/usr" 2>/dev/null || true
for d in bin lib lib64 sbin; do
  if [ -L "/$d" ]; then ln -s "$(readlink "/$d")" "$R/$d"
  elif [ -d "/$d" ]; then mkdir -p "$R/$d"; mount --rbind "/$d" "$R/$d"; mount -o remount,bind,ro "$R/$d" 2>/dev/null || true; fi
done
mount -t proc proc "$R/proc"
for n in null zero urandom; do touch "$R/dev/$n"; mount --bind "/dev/$n" "$R/dev/$n"; done
cp "$1" "$R/work/prog"
shift
cd "$R"
pivot_root . old
umount -l /old
cd /work
exec ./prog "$@"
"""
_CONFINE_PATH = None


def _confine_script() -> str:
    global _CONFINE_PATH
    if not _CONFINE_PATH or not os.path.exists(_CONFINE_PATH):
        fd, _CONFINE_PATH = tempfile.mkstemp(prefix="gsc_confine_", suffix=".sh")
        with os.fdopen(fd, "w") as f:
            f.write(_CONFINE)
    return _CONFINE_PATH


def _confine_cmd(exe: str, args: List[str]) -> List[str]:
    return ["unshare", "-rn", "--mount", "--pid", "--fork", "sh", _confine_script(), exe, *args]


_CONFINED: Optional[bool] = None


def confinement_available() -> bool:
    """True when the program can be run with a private filesystem root (probe: it must not see /etc/hostname-like host files)."""
    global _CONFINED
    if _CONFINED is None:
        try:
            probe = shutil.which("true") or "/bin/true"
            r = subprocess.run(_confine_cmd(probe, []), capture_output=True, timeout=15)
            _CONFINED = r.returncode == 0
        except Exception:
            _CONFINED = False
    return _CONFINED


def _limits(cpu: int):
    def f():
        resource.setrlimit(resource.RLIMIT_CPU, (cpu, cpu))
        resource.setrlimit(resource.RLIMIT_FSIZE, (10 * 1024 * 1024,) * 2)
        resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        try:
            resource.setrlimit(resource.RLIMIT_NPROC, (256, 256))
        except (ValueError, OSError):
            pass
        os.setsid()
    return f


def _build_exe(proj, flags: List[str], link_flags: List[str], jobs=None, include_dirs=None):
    b = Builder(proj, "heal", jobs, flags, link_flags)
    tus = b.compile_all(proj.sources)
    bad = [r for r in tus.values() if not r.ok]
    if bad:
        return None, b, "does not compile: " + (next((d["message"] for d in bad[0].diags if d["type"] == "error"), "")[:120])
    targets = [t for t in b.plan_targets(tus) if not t.stub and t.entry]
    if not targets:
        return None, b, "no entry point (main) to run"
    t = targets[0]
    exe = os.path.join(b.objdir, "gsc_run.out")
    rc, _o, err, to = D._run_limited([D._COMPILER, *[tus[r].obj for r in t.files], "-o", exe,
                                      *b.auto_link_flags(), *link_flags], 120)
    if rc != 0:
        return None, b, "link failed: " + err.strip().splitlines()[-1][:120] if err.strip() else "link failed"
    return exe, b, ""


def _execute(exe: str, stdin: bytes, args: List[str], timeout: int, sanitized: bool) -> RunResult:
    r = RunResult(built=True)
    wd = tempfile.mkdtemp(prefix="gsc_run_")
    env = {"PATH": "/usr/bin:/bin", "LANG": "C", "HOME": wd, "TMPDIR": wd}
    if sanitized:
        env["ASAN_OPTIONS"] = "hard_rss_limit_mb=1024:detect_leaks=1:abort_on_error=0:color=0"
        env["UBSAN_OPTIONS"] = "print_stacktrace=0:halt_on_error=0:color=0"
    t0 = time.time()
    try:
        r.confined = confinement_available()
        cmd = _confine_cmd(exe, args) if r.confined else ["unshare", "-rn", "--", exe, *args]
        p = subprocess.run(cmd, input=stdin, capture_output=True,
                           cwd=wd, env=env, timeout=timeout, preexec_fn=_limits(max(2, timeout)))
        r.rc = p.returncode
        r.stdout = p.stdout[:OUTPUT_CAP].decode("utf-8", "replace")
        r.stderr = p.stderr[:OUTPUT_CAP].decode("utf-8", "replace")
    except subprocess.TimeoutExpired as e:
        r.timed_out = True
        r.rc = 124
        r.stdout = (e.stdout or b"")[:OUTPUT_CAP].decode("utf-8", "replace")
        r.stderr = (e.stderr or b"")[:OUTPUT_CAP].decode("utf-8", "replace")
    finally:
        r.seconds = round(time.time() - t0, 3)
        shutil.rmtree(wd, ignore_errors=True)
    r.sanitizer = sorted(set(m.group(1).strip() for m in _SAN_RE.finditer(r.stderr)))[:10]
    return r


def run_project(proj, stdin: bytes = b"", args: Optional[List[str]] = None, timeout: int = 10,
                sanitize: bool = True, optimize_level: str = "-O0", jobs=None, cxxflags=(), link_flags=()) -> RunResult:
    """Build (with ASan+UBSan when ``sanitize``) and run once inside the sandbox."""
    if not sandbox_available():
        return RunResult(skipped="no sandbox available (needs Linux `unshare -rn`); refusing to run code")
    flags = [*cxxflags, optimize_level, "-g"]
    lf: List[str] = list(link_flags)
    if sanitize:
        flags += ["-fsanitize=address,undefined", "-fno-omit-frame-pointer"]
        lf += ["-fsanitize=address,undefined"]
    exe, b, why = _build_exe(proj, flags, lf, jobs)
    try:
        if not exe:
            return RunResult(built=False, build_error=why)
        return _execute(exe, stdin, args or [], timeout, sanitize)
    finally:
        shutil.rmtree(b.objdir, ignore_errors=True)


def time_project(proj, stdin: bytes = b"", args=None, timeout: int = 10, repeats: int = 3, jobs=None,
                 cxxflags=(), link_flags=()) -> Optional[float]:
    """best-of-N wall time of an -O2 build (no sanitizers) - used only to report measured speed-ups"""
    if not sandbox_available():
        return None
    exe, b, why = _build_exe(proj, [*cxxflags, "-O2"], list(link_flags), jobs)
    try:
        if not exe:
            return None
        best = None
        for _ in range(repeats):
            r = _execute(exe, stdin, args or [], timeout, False)
            if r.timed_out:
                return None
            best = r.seconds if best is None else min(best, r.seconds)
            if r.seconds > 2:
                break
        return best
    finally:
        shutil.rmtree(b.objdir, ignore_errors=True)


def same_behaviour(a: RunResult, b: RunResult) -> bool:
    return (a.built and b.built and a.rc == b.rc and a.stdout == b.stdout and a.timed_out == b.timed_out)
