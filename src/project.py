"""
project.py
----------
Whole-project (multi-file) support: give the tool a folder, a .zip or a .tar.gz of C++ files
and it compiles every translation unit, LINKS them together, and runs the same explanation,
classification, security, optimisation, hardening and self-healing logic as the single-file tool.

    open_project(path)          safe intake (zip-slip, symlink, zip-bomb and size guards)
      -> discover sources / headers / include directories
      -> safety gate on EVERY file before any compiler runs
      -> compile each .cpp once, in parallel, with project include paths  (-c, object per file)
      -> link:   exactly one main()      -> one program
                 several main()s         -> one program per main (+ all non-main files)
                 no main()               -> link check with a stub main (library code)
      -> per-file analysis (errors, security, optimisation) via pipeline.analyze_file
      -> heal_project / harden_project: verified fixes across all files, then a whole-project rebuild

The original upload is never modified; everything happens in a private work copy.
"""

from __future__ import annotations

import fnmatch
import hashlib
import os
import posixpath
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field, replace, is_dataclass
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

import diagnostics as D
from compiler_runner import _default_permissions, forbidden_symbols_in, scan_source, security_violation_diag
from error_explainer import enrich_error
from error_parser import parse_errors
from pipeline import AnalysisResult, analyze_file
from security_analyzer import SecurityFinding, analyze_source, risk_score

# ─────────────────────────────────────────────────────────────────────────────
# configuration
# ─────────────────────────────────────────────────────────────────────────────
SOURCE_EXTS = {".cpp", ".cc", ".cxx", ".c++", ".cp"}          # ".C" (upper case) is handled below
HEADER_EXTS = {".h", ".hpp", ".hh", ".hxx", ".h++", ".inl", ".ipp", ".tpp", ".tcc"}
C_EXTS = {".c"}
SKIP_DIRS = {".git", ".svn", ".hg", "__MACOSX", "CMakeFiles", "node_modules", ".vscode", ".idea",
             "__pycache__"}
_SKIP_DIR_GLOBS = ("cmake-build-*",)
_GENERATED_RE = re.compile(r"\.(hardened|healed|fixed)\.[A-Za-z+]+$")   # outputs of earlier runs

MAX_FILES = int(os.environ.get("GSC_MAX_PROJECT_FILES", "5000"))
MAX_TOTAL_BYTES = int(os.environ.get("GSC_MAX_PROJECT_MB", "200")) * 1024 * 1024
MAX_FILE_BYTES = int(os.environ.get("GSC_MAX_PROJECT_FILE_MB", "20")) * 1024 * 1024
MAX_TARGETS = 50
MAX_INCLUDE_DIRS = 64
TU_TIMEOUT = int(os.environ.get("GSC_TU_TIMEOUT_S", "120"))

_INCLUDE_RE = re.compile(r'^\s*#\s*include\s*([<"])([^>"\n]+)[>"]', re.M)
_THREAD_HDRS = ("<thread>", "<pthread.h>", "<future>", "<condition_variable>", "<semaphore>",
                "<shared_mutex>", "<stop_token>")
_MAIN_RE = re.compile(r"\bmain\s*\(")


class ProjectError(Exception):
    """The upload cannot be opened safely (unsafe path, too large, unreadable, ...)."""


# ─────────────────────────────────────────────────────────────────────────────
# safe intake
# ─────────────────────────────────────────────────────────────────────────────
def _safe_rel(name: str) -> str:
    """Normalise an archive member name; raise ProjectError if it could escape the work dir."""
    raw = name.replace("\\", "/")
    if raw.startswith("/") or re.match(r"^[A-Za-z]:", raw):
        raise ProjectError(f"unsafe absolute path in archive: {name!r}")
    norm = posixpath.normpath(raw)
    if norm == ".." or norm.startswith("../") or "/../" in "/" + norm + "/" or "\x00" in norm:
        raise ProjectError(f"unsafe path traversal in archive: {name!r}")
    return norm


class _Budget:
    def __init__(self):
        self.files = 0
        self.bytes = 0

    def add(self, size: int, what: str) -> None:
        self.files += 1
        self.bytes += size
        if self.files > MAX_FILES:
            raise ProjectError(f"too many files (limit {MAX_FILES})")
        if size > MAX_FILE_BYTES:
            raise ProjectError(f"{what} is larger than {MAX_FILE_BYTES // (1 << 20)} MB")
        if self.bytes > MAX_TOTAL_BYTES:
            raise ProjectError(f"project is larger than {MAX_TOTAL_BYTES // (1 << 20)} MB "
                               f"(possible zip bomb)")


def _copy_capped(src, dst_path: str, budget: _Budget, what: str) -> None:
    """Stream ``src`` to ``dst_path`` counting the REAL bytes (a header can lie about its size)."""
    try:
        os.makedirs(os.path.dirname(dst_path), exist_ok=True)
        out_f = open(dst_path, "wb")
    except (FileExistsError, NotADirectoryError, IsADirectoryError):
        raise ProjectError(f"archive has a file/directory name conflict at {what!r}")
    written = 0
    with out_f as out:
        while True:
            chunk = src.read(1 << 16)
            if not chunk:
                break
            written += len(chunk)
            if written > MAX_FILE_BYTES or budget.bytes + written > MAX_TOTAL_BYTES:
                raise ProjectError(f"{what} expands beyond the size limit (possible zip bomb)")
            out.write(chunk)
    budget.bytes += written


def _extract_zip(path: str, dest: str) -> List[str]:
    notes: List[str] = []
    budget = _Budget()
    try:
        zf = zipfile.ZipFile(path)
    except zipfile.BadZipFile as e:
        raise ProjectError(f"not a valid zip file: {e}")
    with zf:
        for info in zf.infolist():
            rel = _safe_rel(info.filename)
            mode = (info.external_attr >> 16) & 0o170000
            if info.is_dir() or rel in (".", ""):
                continue
            if mode == stat.S_IFLNK:
                notes.append(f"skipped symlink {rel}")
                continue
            if info.flag_bits & 0x1:
                raise ProjectError("the zip is password protected")
            budget.add(0, rel)                                  # counts the file; real size checked while streaming
            with zf.open(info) as src:
                _copy_capped(src, os.path.join(dest, *rel.split("/")), budget, rel)
    return notes


def _extract_tar(path: str, dest: str) -> List[str]:
    notes: List[str] = []
    budget = _Budget()
    try:
        tf = tarfile.open(path)
    except tarfile.TarError as e:
        raise ProjectError(f"not a valid tar archive: {e}")
    with tf:
        for m in tf:
            rel = _safe_rel(m.name)
            if m.isdir() or rel in (".", ""):
                continue
            if not m.isreg():                                   # symlinks, devices, fifos, hardlinks
                notes.append(f"skipped non-regular entry {rel}")
                continue
            budget.add(0, rel)
            src = tf.extractfile(m)
            if src is None:
                continue
            with src:
                _copy_capped(src, os.path.join(dest, *rel.split("/")), budget, rel)
    return notes


def _copy_dir(path: str, dest: str) -> List[str]:
    notes: List[str] = []
    budget = _Budget()
    for dirpath, dirnames, filenames in os.walk(path, followlinks=False):
        dirnames[:] = [d for d in dirnames if d != ".git" and not os.path.islink(os.path.join(dirpath, d))]
        for fn in filenames:
            src = os.path.join(dirpath, fn)
            rel = os.path.relpath(src, path).replace(os.sep, "/")
            if os.path.islink(src):
                notes.append(f"skipped symlink {rel}")
                continue
            if _GENERATED_RE.search(fn) and not fn.startswith("."):
                pass                                            # copied; discovery will skip it
            budget.add(os.path.getsize(src), rel)
            tgt = os.path.join(dest, *rel.split("/"))
            os.makedirs(os.path.dirname(tgt), exist_ok=True)
            shutil.copyfile(src, tgt)
    return notes


def _is_archive(path: str) -> Optional[str]:
    low = path.lower()
    if os.path.isfile(path):
        if low.endswith(".zip") or zipfile.is_zipfile(path):
            return "zip"
        if low.endswith((".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tar.xz")) or tarfile.is_tarfile(path):
            return "tar"
    return None


# ─────────────────────────────────────────────────────────────────────────────
# Project object
# ─────────────────────────────────────────────────────────────────────────────
def _excluded(rel: str, patterns: Sequence[str]) -> bool:
    parts = rel.split("/")
    for pat in patterns:
        pat = pat.strip().strip("/")
        if not pat:
            continue
        if fnmatch.fnmatch(rel, pat) or fnmatch.fnmatch(parts[-1], pat) \
                or any(fnmatch.fnmatch(p, pat) for p in parts[:-1]) or rel.startswith(pat + "/"):
            return True
    return False


@dataclass
class Project:
    origin: str                              # what the user gave us
    kind: str                                # zip | tar | dir | file
    work: str                                # private temp dir holding the extracted copy
    root: str                                # project root inside ``work``
    name: str
    sources: List[str] = field(default_factory=list)       # relative posix paths
    headers: List[str] = field(default_factory=list)
    c_files: List[str] = field(default_factory=list)
    skipped: List[Tuple[str, str]] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    include_dirs: List[str] = field(default_factory=list)  # absolute
    exclude: Tuple[str, ...] = ()

    # --- file access ---
    def abspath(self, rel: str) -> str:
        return os.path.join(self.root, *rel.split("/"))

    def read(self, rel: str) -> str:
        with open(self.abspath(rel), "r", encoding="utf-8", errors="ignore", newline="") as f:
            return f.read()

    def write(self, rel: str, text: str) -> None:
        with open(self.abspath(rel), "w", encoding="utf-8", newline="") as f:
            f.write(text)

    def relpath(self, p: Optional[str]) -> Optional[str]:
        if not p or not os.path.isabs(p):
            return p
        try:
            r = os.path.relpath(os.path.realpath(p), os.path.realpath(self.root))
        except ValueError:
            return p
        return p if r.startswith("..") else r.replace(os.sep, "/")

    @property
    def all_code(self) -> List[str]:
        return self.sources + self.headers

    def line_count(self) -> int:
        n = 0
        for rel in self.all_code:
            try:
                n += self.read(rel).count("\n") + 1
            except OSError:
                pass
        return n

    # --- lifecycle ---
    def close(self) -> None:
        shutil.rmtree(self.work, ignore_errors=True)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    # --- discovery ---
    def rescan(self) -> None:
        self.sources, self.headers, self.c_files, self.skipped = [], [], [], []
        for dirpath, dirnames, filenames in os.walk(self.root, followlinks=False):
            keep = []
            for d in sorted(dirnames):
                rel_d = os.path.relpath(os.path.join(dirpath, d), self.root).replace(os.sep, "/")
                if d in SKIP_DIRS or any(fnmatch.fnmatch(d, g) for g in _SKIP_DIR_GLOBS):
                    continue
                if _excluded(rel_d, self.exclude):
                    self.skipped.append((rel_d + "/", "excluded"))
                    continue
                keep.append(d)
            dirnames[:] = keep
            for fn in sorted(filenames):
                rel = os.path.relpath(os.path.join(dirpath, fn), self.root).replace(os.sep, "/")
                ext = os.path.splitext(fn)[1]
                low = ext.lower()
                is_src = low in SOURCE_EXTS or ext == ".C"
                is_hdr = low in HEADER_EXTS
                is_c = low in C_EXTS and not is_src
                if not (is_src or is_hdr or is_c) or fn.startswith("._"):
                    continue
                if _excluded(rel, self.exclude):
                    self.skipped.append((rel, "excluded"))
                    continue
                if _GENERATED_RE.search(fn):
                    self.skipped.append((rel, "output of an earlier hardening/healing run"))
                    continue
                if is_src:
                    self.sources.append(rel)
                elif is_hdr:
                    self.headers.append(rel)
                else:
                    self.c_files.append(rel)
        for rel in self.c_files:
            self.skipped.append((rel, "plain C file (this tool analyses C++ only)"))
        dirs = {self.root}
        for rel in self.sources + self.headers:
            dirs.add(os.path.dirname(self.abspath(rel)))
        ordered = sorted(dirs, key=lambda d: (d.count(os.sep), d))
        self.include_dirs = ordered[:MAX_INCLUDE_DIRS]
        if len(ordered) > MAX_INCLUDE_DIRS:
            self.notes.append(f"{len(ordered)} directories hold code; only the first "
                              f"{MAX_INCLUDE_DIRS} are used as -I paths")


def _collapse_root(work: str) -> str:
    """A zip usually wraps everything in one top-level folder; use it as the project root."""
    cur = work
    for _ in range(3):
        entries = [e for e in os.listdir(cur) if e not in SKIP_DIRS]
        if len(entries) == 1 and os.path.isdir(os.path.join(cur, entries[0])):
            cur = os.path.join(cur, entries[0])
        else:
            break
    return cur


def _local_includes(path: str, seen: Optional[set] = None, depth: int = 0) -> List[str]:
    seen = seen if seen is not None else set()
    found: List[str] = []
    if depth > 4:
        return found
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            text = f.read()
    except OSError:
        return found
    for kind, name in _INCLUDE_RE.findall(text):
        if kind != '"':
            continue
        p = os.path.normpath(os.path.join(os.path.dirname(path), name))
        if p in seen or not os.path.isfile(p):
            continue
        seen.add(p)
        found.append(p)
        found += _local_includes(p, seen, depth + 1)
    return found


def open_project(path: str, exclude: Iterable[str] = ()) -> Project:
    """Open a folder, archive (.zip/.tar.gz) or single .cpp file as a Project (work copy in a temp dir)."""
    path = os.path.abspath(path)
    if not os.path.exists(path):
        raise ProjectError(f"{path} does not exist")
    work = tempfile.mkdtemp(prefix="gsc_proj_")
    try:
        kind = _is_archive(path)
        notes: List[str] = []
        if kind == "zip":
            notes = _extract_zip(path, work)
        elif kind == "tar":
            notes = _extract_tar(path, work)
        elif os.path.isdir(path):
            kind = "dir"
            notes = _copy_dir(path, work)
        elif os.path.isfile(path):
            kind = "file"                                       # the file + the local headers it includes
            shutil.copyfile(path, os.path.join(work, os.path.basename(path)))
            base = os.path.dirname(path)
            for inc in _local_includes(path):
                rel = os.path.relpath(inc, base)
                if not rel.startswith(".."):
                    tgt = os.path.join(work, rel)
                    os.makedirs(os.path.dirname(tgt), exist_ok=True)
                    shutil.copyfile(inc, tgt)
        else:
            raise ProjectError(f"{path} is neither a file, a folder nor a supported archive")
        root = work if kind in ("dir", "file") else _collapse_root(work)
        if kind in ("zip", "tar"):
            name = re.sub(r"(\.tar\.(gz|bz2|xz)|\.tgz|\.zip|\.tar)$", "", os.path.basename(path), flags=re.I)
        else:
            name = os.path.splitext(os.path.basename(path))[0] if kind == "file" else os.path.basename(path.rstrip("/"))
        proj = Project(origin=path, kind=kind, work=work, root=root, name=name or "project",
                       notes=notes, exclude=tuple(exclude))
        proj.rescan()
        return proj
    except BaseException:
        shutil.rmtree(work, ignore_errors=True)
        raise


# ─────────────────────────────────────────────────────────────────────────────
# build engine
# ─────────────────────────────────────────────────────────────────────────────
@dataclass
class TUResult:
    rel: str
    obj: Optional[str] = None
    rc: int = 0
    diags: List[dict] = field(default_factory=list)
    undefined: List[str] = field(default_factory=list)
    defined: List[str] = field(default_factory=list)
    has_main: bool = False
    elapsed: float = 0.0
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        return self.rc == 0 and not any(d["type"] == "error" for d in self.diags)


@dataclass
class LinkTarget:
    name: str                                # "program" | "program: src/a.cpp" | "library (stub main)"
    entry: Optional[str]
    files: List[str]
    ok: bool = False
    stub: bool = False
    errors: list = field(default_factory=list)              # enriched CompilerError objects
    elapsed: float = 0.0
    skipped_reason: Optional[str] = None


def defined_symbols(obj: str) -> Optional[List[str]]:
    nm = shutil.which("nm")
    if not nm:
        return None
    try:
        r = subprocess.run([nm, "-g", "--defined-only", obj], stdout=subprocess.PIPE,
                           stderr=subprocess.DEVNULL, text=True, timeout=15)
    except (OSError, subprocess.TimeoutExpired):
        return None
    out = []
    for line in r.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[-2] in "TtWwDdBbRr":
            out.append(parts[-1])
    return out


def _digest(proj: Project, rels: Iterable[str]) -> str:
    h = hashlib.sha256()
    for rel in sorted(rels):
        h.update(rel.encode() + b"\0")
        try:
            h.update(proj.read(rel).encode("utf-8", "surrogatepass"))
        except OSError:
            pass
    return h.hexdigest()


def _link_explanation(e) -> None:
    """The shared explainer treats every linker error as 'undefined reference'; be precise for duplicates."""
    msg = e.message or ""
    if msg.startswith("multiple definition of"):
        e.explanation = ("What happened:  " + msg + "\n\n"
                         "Why it happened:  The same function or variable is defined in more than one "
                         "source file (or in a header that several files include), so the linker cannot "
                         "decide which definition to use.\n\n"
                         "How to fix it:  Keep exactly one definition. Put the body in a single .cpp and "
                         "leave only a declaration in the header, or mark the function 'inline' / 'static' "
                         "if each file should have its own copy.")
        e.suggestion = ("Remove or rename the duplicate definition, or make the function 'static' or 'inline' "
                        "if the copies are meant to be separate.")


class Builder:
    """Compile translation units in parallel and link them."""

    def __init__(self, proj: Project, profile: str = "analysis", jobs: Optional[int] = None,
                 cxxflags: Sequence[str] = (), link_flags: Sequence[str] = ()):
        self.proj = proj
        self.profile = profile
        self.jobs = max(1, jobs or min(4, os.cpu_count() or 2))
        self.cxxflags = list(cxxflags)
        self.link_flags = list(link_flags)
        self._memo: Dict[str, Tuple[str, TUResult]] = {}
        self.objdir = tempfile.mkdtemp(prefix="gsc_objs_", dir=proj.work)

    # --- flags ---
    def flags(self) -> List[str]:
        if self.profile == "analysis":
            base = list(D.analysis_flags()) + ["-g1"]
        else:                                                    # "heal": focused -Wall, no -O2 noise
            base = list(D.basic_flags()) + ["-Wall", "-g1"]
        for d in self.proj.include_dirs:
            base += ["-I", d]
        return base + self.cxxflags

    def auto_link_flags(self) -> List[str]:
        needs_thread = False
        for rel in self.proj.sources + self.proj.headers:
            try:
                txt = self.proj.read(rel)
            except OSError:
                continue
            if any(h in txt for h in _THREAD_HDRS):
                needs_thread = True
                break
        out = ["-pthread"] if needs_thread and "-pthread" not in self.link_flags else []
        return out + self.link_flags

    # --- compile ---
    def compile_tu(self, rel: str) -> TUResult:
        proj = self.proj
        abs_src = proj.abspath(rel)
        safe = re.sub(r"[^A-Za-z0-9_.-]", "_", rel)
        obj = os.path.join(self.objdir, safe + ".o")
        t0 = time.time()
        rc, _o, err, to = D._run_limited([D._COMPILER, *self.flags(), "-c", abs_src, "-o", obj], TU_TIMEOUT)
        res = TUResult(rel=rel, rc=rc, timed_out=to)
        if to:
            msg = f"Compilation of {rel} timed out after {TU_TIMEOUT}s"
            res.diags = [{"file": abs_src, "line": None, "column": None, "type": "error", "message": msg,
                          "raw": msg, "option": None, "notes": []}]
        else:
            res.diags = D.parse_compiler_stderr(err, abs_src, rc)
        if rc == 0 and os.path.exists(obj):
            res.obj = obj
            u = D.undefined_symbols(obj)
            res.undefined = u or []
            d = defined_symbols(obj)
            res.defined = d or []
            res.has_main = ("main" in res.defined) if d is not None else bool(_MAIN_RE.search(proj.read(rel)))
        res.elapsed = time.time() - t0
        return res

    def compile_all(self, rels: Sequence[str], use_memo: bool = False) -> Dict[str, TUResult]:
        hdr = _digest(self.proj, self.proj.headers) if use_memo else ""
        out: Dict[str, TUResult] = {}
        todo: List[str] = []
        keys: Dict[str, str] = {}
        for rel in rels:
            if use_memo:
                keys[rel] = hdr + _digest(self.proj, [rel])
                hit = self._memo.get(rel)
                if hit and hit[0] == keys[rel]:
                    out[rel] = hit[1]
                    continue
            todo.append(rel)
        if todo:
            with ThreadPoolExecutor(max_workers=self.jobs) as ex:
                for rel, r in zip(todo, ex.map(self.compile_tu, todo)):
                    out[rel] = r
                    if use_memo:
                        self._memo[rel] = (keys[rel], r)
        return {rel: out[rel] for rel in rels}

    # --- link ---
    def plan_targets(self, tus: Dict[str, TUResult]) -> List[LinkTarget]:
        ok = [r for r in tus.values() if r.ok and r.obj]
        mains = [r for r in ok if r.has_main]
        others = [r for r in ok if not r.has_main]
        if len(mains) == 1:
            return [LinkTarget("program", mains[0].rel, [r.rel for r in ok])]
        if not mains:
            return [LinkTarget("library (stub main added for the link check)", None,
                               [r.rel for r in ok], stub=True)]
        targets = [LinkTarget(f"program: {m.rel}", m.rel, [m.rel] + [o.rel for o in others])
                   for m in mains[:MAX_TARGETS]]
        return targets

    def link(self, tus: Dict[str, TUResult], targets: Optional[List[LinkTarget]] = None) -> List[LinkTarget]:
        targets = targets if targets is not None else self.plan_targets(tus)
        flags = self.auto_link_flags()
        stub_obj = None
        if any(t.stub for t in targets):
            stub_src = os.path.join(self.objdir, "gsc_stub_main.cpp")
            with open(stub_src, "w") as f:
                f.write("int main() { return 0; }\n")
            stub_obj = os.path.join(self.objdir, "gsc_stub_main.o")
            D._run_limited([D._COMPILER, "-c", stub_src, "-o", stub_obj], TU_TIMEOUT)

        def one(i_t):
            i, t = i_t
            t0 = time.time()
            objs = [tus[r].obj for r in t.files]
            if t.stub and stub_obj and os.path.exists(stub_obj):
                objs.append(stub_obj)
            out = os.path.join(self.objdir, f"link_{i}.out")
            rc, _o, err, to = D._run_limited([D._COMPILER, *objs, "-o", out, *flags], TU_TIMEOUT)
            t.elapsed = time.time() - t0
            if to:
                err = f"Link timed out after {TU_TIMEOUT}s"
                rc = 124
            t.ok = rc == 0
            if not t.ok:
                diags = D.parse_compiler_stderr(err, None, rc)
                for d in diags:
                    self._attribute(d)
                errs = parse_errors(diags)
                for e in errs:
                    enrich_error(e)
                    _link_explanation(e)
                    e.file = self.proj.relpath(e.file) if e.file else None
                    for n in (e.notes or []):
                        if isinstance(n, dict):
                            n["file"] = self.proj.relpath(n.get("file"))
                t.errors = errs
            try:
                os.remove(out)
            except OSError:
                pass
            return t

        with ThreadPoolExecutor(max_workers=self.jobs) as ex:
            list(ex.map(one, list(enumerate(targets))))
        return targets

    _LOC_RE = re.compile(r"^(?P<file>[^:\s][^:]*?\.[A-Za-z+]+):(?P<line>\d+)(?::\([^)]*\))?:\s*"
                         r"(?:undefined reference to|multiple definition of)")
    _FIRST_RE = re.compile(r";\s*\S+?\.o:(?P<file>[^:]+?):(?P<line>\d+): first defined here")

    def _attribute(self, d: dict) -> None:
        """Give a linker diagnostic a real source location (needs the -g1 line tables)."""
        raw = d.get("raw") or ""
        m = self._LOC_RE.match(raw)
        if m:
            d["file"] = m.group("file")
            d["line"] = int(m.group("line"))
            d["column"] = None
        f = self._FIRST_RE.search(raw)
        msg = d.get("message") or ""
        if f:
            first = f"{self.proj.relpath(f.group('file'))}:{f.group('line')}"
            msg = self._FIRST_RE.sub("", msg).rstrip("; ")
            msg += f" (first defined at {first})"
            d["notes"] = list(d.get("notes") or []) + [
                {"file": f.group("file"), "line": int(f.group("line")), "column": None,
                 "message": "first definition is here"}]
        d["message"] = self._tidy(msg)
        d["raw"] = self._tidy(raw)

    def _tidy(self, text: str) -> str:
        text = text.replace(self.objdir + os.sep, "").replace(self.proj.root + os.sep, "")
        return re.sub(r"\.cpp\.o\b", ".cpp", text)


# ─────────────────────────────────────────────────────────────────────────────
# analysis
# ─────────────────────────────────────────────────────────────────────────────
@dataclass
class ProjectResult:
    name: str
    files: Dict[str, AnalysisResult] = field(default_factory=dict)       # per .cpp
    header_findings: Dict[str, List[SecurityFinding]] = field(default_factory=dict)
    targets: List[LinkTarget] = field(default_factory=list)
    blocked: bool = False
    blocked_files: Dict[str, str] = field(default_factory=dict)          # rel -> reason
    compile_ok: bool = False
    link_skipped: Optional[str] = None
    timings: Dict[str, float] = field(default_factory=dict)
    n_sources: int = 0
    n_headers: int = 0
    n_lines: int = 0
    skipped: List[Tuple[str, str]] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    flags_note: str = ""

    # --- aggregated views (deduplicated: a header error shows up once, not once per includer) ---
    @staticmethod
    def _ekey(e):
        return (e.file, e.line, e.column, e.error_type, e.message)

    def unique_errors(self, show_all: bool = False) -> list:
        seen, out = set(), []
        for res in self.files.values():
            for e in res.visible(show_all):
                k = self._ekey(e)
                if k not in seen:
                    seen.add(k)
                    out.append(e)
        return out

    @property
    def error_count(self) -> int:
        seen = set()
        for res in self.files.values():
            for e in res.errors:
                if e.error_type == "error" and not e.cascade:
                    seen.add(self._ekey(e))
        return len(seen)

    @property
    def warning_count(self) -> int:
        seen = set()
        for res in self.files.values():
            for e in res.visible():
                if e.error_type == "warning":
                    seen.add(self._ekey(e))
        return len(seen)

    @property
    def link_errors(self) -> list:
        seen, out = set(), []
        for t in self.targets:
            for e in t.errors:
                k = (e.message,)
                if k not in seen:
                    seen.add(k)
                    out.append(e)
        return out

    @property
    def link_ok(self) -> bool:
        return bool(self.targets) and all(t.ok for t in self.targets)

    @property
    def security_findings(self) -> List[SecurityFinding]:
        seen, out = set(), []
        pools = [r.security_findings for r in self.files.values()] + list(self.header_findings.values())
        for pool in pools:
            for f in pool:
                k = (f.file, f.line, f.rule_id, f.vulnerability_type)
                if k not in seen:
                    seen.add(k)
                    out.append(f)
        out.sort(key=lambda f: ({"critical": 0, "high": 1, "medium": 2, "low": 3}.get(f.severity.lower(), 4),
                                f.file or "", f.line or 0))
        return out

    @property
    def optimization_findings(self) -> list:
        out = []
        for r in self.files.values():
            out += r.optimization_findings
        return out

    @property
    def risk(self) -> int:
        return risk_score(self.security_findings)

    @property
    def built(self) -> bool:
        return self.compile_ok and self.link_ok


def _relativize(proj: Project, res: AnalysisResult, rel: str) -> None:
    res.file = rel
    for e in res.errors:
        e.file = proj.relpath(e.file)
        for n in (e.notes or []):
            if isinstance(n, dict):
                n["file"] = proj.relpath(n.get("file"))
    res.security_findings = [replace(f, file=proj.relpath(f.file)) for f in res.security_findings]
    for e in res.errors:
        e.security_findings = [replace(f, file=proj.relpath(f.file)) if is_dataclass(f) else f
                               for f in (e.security_findings or [])]
    res.optimization_findings = [replace(o, file=proj.relpath(o.file)) for o in res.optimization_findings]


def _gate(proj: Project, permissions: dict) -> Dict[str, list]:
    """Safety gate on every file BEFORE any compiler runs.  rel -> [Violation]."""
    bad: Dict[str, list] = {}
    for rel in proj.all_code:
        try:
            src = proj.read(rel)
        except OSError:
            continue
        v = scan_source(src, permissions, os.path.dirname(proj.abspath(rel)), semantic=False,
                        confine_root=proj.root)
        if v:
            bad[rel] = v
    return bad


def analyze_project(proj: Project, optimize: bool = True, jobs: Optional[int] = None,
                    permissions: Optional[dict] = None, link: bool = True,
                    cxxflags: Sequence[str] = (), link_flags: Sequence[str] = ()) -> ProjectResult:
    t_all = time.time()
    perms = _default_permissions() if permissions is None else permissions
    out = ProjectResult(name=proj.name, n_sources=len(proj.sources), n_headers=len(proj.headers),
                        n_lines=proj.line_count(), skipped=list(proj.skipped), notes=list(proj.notes))
    if not proj.sources:
        out.notes.append("No C++ source files (.cpp/.cc/.cxx) were found in the project.")
        out.compile_ok = True
        return out

    # 1. safety gate (all files, before any compiler)
    t = time.time()
    bad = _gate(proj, perms)
    out.timings["gate"] = time.time() - t
    if bad:
        out.blocked = True
        for rel, v in bad.items():
            out.blocked_files[rel] = "; ".join(str(x) for x in v[:3])
        for rel in proj.sources:
            if rel in bad:
                diags = [security_violation_diag(proj.abspath(rel), bad[rel])]
                res = analyze_file(proj.abspath(rel), perms, optimize=False, log=False, use_ast=False,
                                   precompiled=(diags, None))
            else:                                                # static analysis is text-only: safe
                res = AnalysisResult(file=rel)
                res.security_findings = analyze_source(proj.read(rel), proj.abspath(rel), [])
            _relativize(proj, res, rel)
            out.files[rel] = res
        for rel in proj.headers:
            out.header_findings[rel] = [replace(f, file=rel)
                                        for f in analyze_source(proj.read(rel), proj.abspath(rel), [])]
        out.notes.append("Safety gate blocked the project: no compiler was run for ANY file, "
                         "because linking would pull the blocked code into the program.")
        out.timings["total"] = time.time() - t_all
        return out

    # 2. compile every translation unit (parallel)
    builder = Builder(proj, "analysis", jobs, cxxflags, link_flags)
    out.flags_note = f"{builder.jobs} parallel job(s); {len(proj.include_dirs)} include dir(s)"
    t = time.time()
    tus = builder.compile_all(proj.sources)
    out.timings["compile"] = time.time() - t

    # 3. semantic gate (forbidden libc symbols in any object)
    for rel, r in tus.items():
        if r.ok and not perms.get("allow_system_calls", False):
            badsyms = forbidden_symbols_in(r.undefined)
            if badsyms:
                out.blocked = True
                out.blocked_files[rel] = f"object imports forbidden libc symbol(s): {', '.join(badsyms)}"
    if out.blocked:
        for rel, reason in out.blocked_files.items():
            from compiler_runner import Violation
            tus[rel].diags = [security_violation_diag(proj.abspath(rel), [Violation("forbidden-symbol", reason)])]
        out.notes.append("Safety gate blocked linking: an object imports a forbidden libc symbol.")

    # 4. per-file analysis (explain / classify / security / optimise) on the project-aware diagnostics
    t = time.time()
    for rel in proj.sources:
        r = tus[rel]
        pre = (r.diags, None)
        res = analyze_file(proj.abspath(rel), perms, optimize=optimize and not out.blocked, log=False,
                           use_ast=False, precompiled=pre)
        res.timings["build"] = r.elapsed
        _relativize(proj, res, rel)
        out.files[rel] = res
    for rel in proj.headers:
        found = analyze_source(proj.read(rel), proj.abspath(rel), [])
        out.header_findings[rel] = [replace(f, file=rel) for f in found]
    out.timings["analysis"] = time.time() - t
    out.compile_ok = all(r.ok for r in tus.values()) and not out.blocked

    # 5. link
    if link and not out.blocked:
        if out.compile_ok:
            t = time.time()
            out.targets = builder.link(tus)
            out.timings["link"] = time.time() - t
            if any(t_.stub for t_ in out.targets):
                out.notes.append("No main() found: linked with a stub main() to check that every "
                                 "symbol the files use is defined somewhere in the project.")
            if len([t_ for t_ in out.targets if t_.entry]) > 1:
                out.notes.append(f"{len(out.targets)} files define main(): each is linked as its own "
                                 f"program together with all the files that do not.")
        else:
            bad_n = sum(1 for r in tus.values() if not r.ok)
            out.link_skipped = f"{bad_n} file(s) have compile errors, so linking was skipped"
    out.timings["total"] = time.time() - t_all
    shutil.rmtree(builder.objdir, ignore_errors=True)
    return out


# ─────────────────────────────────────────────────────────────────────────────
# self-healing across files
# ─────────────────────────────────────────────────────────────────────────────
@dataclass
class HealResult:
    history: List[dict] = field(default_factory=list)
    changed: Dict[str, Tuple[str, str]] = field(default_factory=dict)      # rel -> (original, healed)
    clean: bool = False
    link_ok: Optional[bool] = None
    reason: str = ""
    remaining: List[dict] = field(default_factory=list)
    link_errors: list = field(default_factory=list)


def _unique_remaining(proj: Project, errors) -> List[dict]:
    seen, out = set(), []
    for rel, d in errors:
        f = proj.relpath(d.get("file")) or rel
        k = (f, d.get("line"), d.get("message"))
        if k not in seen:
            seen.add(k)
            out.append(dict(d, file=f))
    return out


def heal_project(proj: Project, max_attempts: int = 30, jobs: Optional[int] = None,
                 cxxflags: Sequence[str] = (), link_flags: Sequence[str] = (),
                 progress=None) -> HealResult:
    """compile all files -> classify -> apply ONE rule-based fix -> recompile the file(s) -> repeat.
    Finishes with a project-wide link check.  Linker/access errors are never auto-fixed."""
    from auto_healer import attempt_fix, UNFIXABLE_CATEGORIES
    from error_classifier import ErrorClassifier

    clf = ErrorClassifier()
    res = HealResult()
    builder = Builder(proj, "heal", jobs, cxxflags, link_flags)
    originals: Dict[str, str] = {}
    rel_by_abs = {os.path.realpath(proj.abspath(r)): r for r in proj.all_code}

    def classify(d: dict) -> dict:
        if not d.get("category"):
            cat, conf = clf.predict(d["message"])
            d["category"] = cat or "other"
            d["confidence"] = round(conf, 3)
        return d

    tus: Dict[str, TUResult] = {}
    banned: set = set()            # (file, line, message) of fixes that made things worse
    last = None                    # (target, source_before, key, error_count_before)
    for attempt in range(1, max_attempts + 1):
        tus = builder.compile_all(proj.sources, use_memo=True)
        errors = []
        for rel in proj.sources:
            for d in tus[rel].diags:
                if d["type"] == "error" and not d.get("cascade"):
                    errors.append((rel, classify(dict(d))))
        if last is not None and len(errors) > last[3]:
            # regression guard: the last fix produced MORE errors than before -> undo it and never retry it
            proj.write(last[0], last[1])
            banned.add(last[2])
            res.history.append({"attempt": attempt, "status": "reverted", "file": last[0], "line": last[2][1],
                                "message": "fix increased the error count (%d -> %d); undone" % (last[3], len(errors))})
            if progress:
                progress(dict(res.history[-1], category="reverted"))
            last = None
            continue
        last = None
        if not errors:
            res.history.append({"attempt": attempt, "status": "clean",
                                "message": "all files compile"})
            break
        fixed = False
        for rel, d in errors:
            if d.get("category") in UNFIXABLE_CATEGORIES:
                continue
            target = rel_by_abs.get(os.path.realpath(d["file"])) if d.get("file") else rel
            target = target or rel
            key = (target, d.get("line"), d["message"][:80])
            if key in banned:
                continue
            src = proj.read(target)
            new = attempt_fix(src, d)
            if new and new != src:
                originals.setdefault(target, src)
                proj.write(target, new)
                last = (target, src, key, len(errors))
                entry = {"attempt": attempt, "status": "fixed", "file": target, "line": d.get("line"),
                         "category": d.get("category"), "message": d["message"][:80]}
                res.history.append(entry)
                if progress:
                    progress(entry)
                fixed = True
                break
        if not fixed:
            res.history.append({"attempt": attempt, "status": "stopped",
                                "message": "no safe automatic fix for: " + "; ".join(
                                    f"{x['file']}:{x.get('line')} {x['message'][:40]}"
                                    for x in _unique_remaining(proj, errors)[:3])})
            res.reason = "a human decision is needed"
            res.remaining = _unique_remaining(proj, errors)
            break
    else:
        res.reason = f"stopped after {max_attempts} attempts"
        res.remaining = _unique_remaining(proj, [(r, d) for r in proj.sources for d in tus[r].diags
                                                  if d["type"] == "error"])

    for rel, orig in originals.items():
        new = proj.read(rel)
        if new != orig:
            res.changed[rel] = (orig, new)

    compile_clean = all(r.ok for r in tus.values()) and bool(tus)
    if compile_clean:
        targets = builder.link(tus)
        res.link_ok = all(t.ok for t in targets)
        res.link_errors = [e for t in targets for e in t.errors]
        res.clean = res.link_ok
        if not res.link_ok:
            res.reason = ("every file compiles, but linking fails; linker errors need a human "
                          "decision (a missing definition, or the same function defined twice)")
    shutil.rmtree(builder.objdir, ignore_errors=True)
    return res


# ─────────────────────────────────────────────────────────────────────────────
# verified hardening across files
# ─────────────────────────────────────────────────────────────────────────────
@dataclass
class HardenProjectResult:
    files: Dict[str, object] = field(default_factory=dict)                  # rel -> HardenResult
    changed: Dict[str, Tuple[str, str]] = field(default_factory=dict)       # rel -> (before, after)
    rolled_back: Dict[str, str] = field(default_factory=dict)               # rel -> why
    remaining: List[SecurityFinding] = field(default_factory=list)
    build_ok_before: Optional[bool] = None
    build_ok_after: Optional[bool] = None


def _status(proj: Project, builder: Builder) -> Tuple[bool, int, bool]:
    tus = builder.compile_all(proj.sources)
    n_err = sum(1 for r in tus.values() for d in r.diags if d["type"] == "error")
    compile_ok = all(r.ok for r in tus.values())
    link_ok = True
    if compile_ok:
        link_ok = all(t.ok for t in builder.link(tus))
    return compile_ok and link_ok, n_err, link_ok


def harden_project(proj: Project, jobs: Optional[int] = None, cxxflags: Sequence[str] = (),
                   link_flags: Sequence[str] = ()) -> HardenProjectResult:
    """Apply verified security fixes to every file, then rebuild+relink the WHOLE project.
    A file whose fixes break the project build (or the link) is rolled back."""
    from secure_fixer import harden_source
    out = HardenProjectResult()
    builder = Builder(proj, "heal", jobs, cxxflags, link_flags)
    out.build_ok_before = _status(proj, builder)[0]
    pending: Dict[str, str] = {}
    for rel in proj.all_code:
        text = proj.read(rel)
        if not analyze_source(text, proj.abspath(rel), []):
            continue
        r = harden_source(text, proj.abspath(rel), include_dirs=proj.include_dirs)
        out.files[rel] = r
        if r.applied and r.hardened != text:
            pending[rel] = r.hardened

    def apply(rels):
        for rel in rels:
            proj.write(rel, pending[rel])

    def revert(rels):
        for rel in rels:
            proj.write(rel, out.files[rel].original)

    apply(pending)
    ok_all, _n, _l = _status(proj, builder)
    keep = set(pending)
    if not ok_all and out.build_ok_before:
        revert(pending)                                         # whole-project check failed: add back one by one
        keep = set()
        for rel in pending:
            apply([rel])
            ok1, _n1, _l1 = _status(proj, builder)
            if ok1:
                keep.add(rel)
            else:
                revert([rel])
                out.rolled_back[rel] = "the fixed file broke the whole-project build or link"
    for rel in keep:
        out.changed[rel] = (out.files[rel].original, pending[rel])
    out.build_ok_after = _status(proj, builder)[0]
    out.remaining = [replace(f, file=rel) for rel in proj.all_code
                     for f in analyze_source(proj.read(rel), proj.abspath(rel), [])]
    shutil.rmtree(builder.objdir, ignore_errors=True)
    return out


# ─────────────────────────────────────────────────────────────────────────────
# output
# ─────────────────────────────────────────────────────────────────────────────
def write_output(proj: Project, dest: str) -> str:
    """Write the (healed / hardened) work tree as a .zip (if dest ends in .zip) or as a folder."""
    dest = os.path.abspath(dest)
    if dest.lower().endswith(".zip"):
        with zipfile.ZipFile(dest, "w", zipfile.ZIP_DEFLATED) as zf:
            for dirpath, dirnames, filenames in os.walk(proj.root):
                dirnames[:] = [d for d in dirnames if not d.startswith("gsc_objs_")]
                for fn in sorted(filenames):
                    full = os.path.join(dirpath, fn)
                    if os.path.islink(full):
                        continue
                    zf.write(full, os.path.join(proj.name, os.path.relpath(full, proj.root)))
        return dest
    if os.path.exists(dest):
        raise ProjectError(f"{dest} already exists; choose another --out or remove it")
    shutil.copytree(proj.root, dest, ignore=shutil.ignore_patterns("gsc_objs_*", "__pycache__"))
    return dest


def default_output(proj: Project, suffix: str) -> str:
    base = proj.origin.rstrip("/")
    if proj.kind in ("zip", "tar"):
        stem = re.sub(r"(\.tar\.(gz|bz2|xz)|\.tgz|\.zip|\.tar)$", "", base, flags=re.I)
        return f"{stem}.{suffix}.zip"
    if proj.kind == "file":
        return os.path.splitext(base)[0] + f".{suffix}" + os.path.splitext(base)[1]
    return f"{base}.{suffix}"


def write_in_place(proj: Project, changed: Iterable[str]) -> List[str]:
    """Copy changed files back over the ORIGINAL folder (directory input only), keeping CRLF files CRLF."""
    if proj.kind not in ("dir", "file"):
        raise ProjectError("--in-place only works for a folder or a single file, not for an archive")
    written = []
    for rel in changed:
        dst = os.path.join(proj.origin, *rel.split("/")) if proj.kind == "dir" else proj.origin
        crlf = False
        try:
            with open(dst, "rb") as f:
                crlf = b"\r\n" in f.read()
        except OSError:
            pass
        text = proj.read(rel)
        with open(dst, "w", encoding="utf-8", newline="\r\n" if crlf and "\r\n" not in text else "") as f:
            f.write(text)
        written.append(dst)
    return written
