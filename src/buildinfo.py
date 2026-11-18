"""Light-weight detection of compiler / linker flags from CMakeLists.txt and Makefile.

This is NOT a CMake or make implementation: it reads simple, literal settings only
(language standard, -D definitions, -O/-W options, linked libraries) and ignores everything it
cannot understand (variables, generator expressions, conditionals).  Only flags matching a strict
allow-list are accepted, so a hostile build file cannot smuggle in -fplugin=, -include, -B, -specs=, -Xlinker ...
"""
import os
import re
import shlex
from dataclasses import dataclass, field
from typing import List

_OK = re.compile(r"^(-std=[A-Za-z0-9+:]+|-D[A-Za-z_]\w*(=[\w.\-+/]*)?|-O[0-3sgz]?|-W[A-Za-z0-9-=]*|-pthread|"
                 r"-f(no-)?(exceptions|rtti|strict-aliasing|omit-frame-pointer|sanitize=[a-z,]+|openmp|"
                 r"permissive|signed-char|unsigned-char)|-fopenmp|-m(32|64|avx2?|sse4\.[12]|arch=[a-z0-9-]+)|-g[0-3]?)$")
_LIB = re.compile(r"^[A-Za-z][A-Za-z0-9_+.-]{0,40}$")
_CMAKE_WORDS = {"PUBLIC", "PRIVATE", "INTERFACE", "STATIC", "SHARED", "debug", "optimized", "general"}
_KNOWN_TARGET_LIBS = {"Threads::Threads": "-pthread", "m": "-lm", "pthread": "-pthread", "dl": "-ldl", "rt": "-lrt",
                      "stdc++fs": "-lstdc++fs"}


@dataclass
class BuildInfo:
    cxxflags: List[str] = field(default_factory=list)
    link_flags: List[str] = field(default_factory=list)
    sources: List[str] = field(default_factory=list)       # which files contributed
    ignored: List[str] = field(default_factory=list)        # rejected flags (for the report)

    def add_cxx(self, f: str) -> None:
        if _OK.match(f):
            if f not in self.cxxflags:
                self.cxxflags.append(f)
        elif f.startswith("-"):
            self.ignored.append(f)

    def add_link(self, f: str) -> None:
        if f in ("-pthread",) or re.match(r"^-l[A-Za-z0-9_+.-]+$", f):
            if f not in self.link_flags:
                self.link_flags.append(f)
        elif f.startswith("-"):
            self.ignored.append(f)


def _read(path: str, limit: int = 256 * 1024) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read(limit)
    except OSError:
        return ""


def _args(body: str) -> List[str]:
    body = re.sub(r"#.*", "", body)
    try:
        return shlex.split(body)
    except ValueError:
        return body.split()


def parse_cmake(text: str, info: BuildInfo) -> None:
    text = re.sub(r"#[^\n]*", "", text)
    m = re.search(r"set\s*\(\s*CMAKE_CXX_STANDARD\s+(\d+)", text, re.I)
    if m:
        info.add_cxx(f"-std=c++{m.group(1)}")
    for m in re.finditer(r"cxx_std_(\d+)", text):
        info.add_cxx(f"-std=c++{m.group(1)}")
    for m in re.finditer(r"set\s*\(\s*CMAKE_CXX_FLAGS[^\s)]*\s+([^)]*)\)", text, re.I):
        for a in _args(m.group(1)):
            if not a.startswith("$"):
                info.add_cxx(a)
    for m in re.finditer(r"add_compile_options\s*\(([^)]*)\)", text, re.I):
        for a in _args(m.group(1)):
            if not a.startswith("$"):
                info.add_cxx(a)
    for m in re.finditer(r"add_definitions\s*\(([^)]*)\)", text, re.I):
        for a in _args(m.group(1)):
            if a.startswith("-D"):
                info.add_cxx(a)
    for m in re.finditer(r"(?:target_)?compile_definitions\s*\(([^)]*)\)", text, re.I):
        parts = [a for a in _args(m.group(1)) if a not in _CMAKE_WORDS and not a.startswith("$")]
        if re.match(r"add_compile_definitions", m.group(0), re.I):
            defs = parts
        else:
            defs = parts[1:]                                   # first is the target name
        for d in defs:
            info.add_cxx("-D" + d if not d.startswith("-D") else d)
    for m in re.finditer(r"target_link_libraries\s*\(([^)]*)\)", text, re.I):
        parts = [a for a in _args(m.group(1)) if a not in _CMAKE_WORDS and not a.startswith("$")]
        for lib in parts[1:]:                                  # first is the target
            if lib in _KNOWN_TARGET_LIBS:
                info.add_link(_KNOWN_TARGET_LIBS[lib])
            elif lib.startswith("-l"):
                info.add_link(lib)
            elif _LIB.match(lib) and "::" not in lib and not lib.endswith((".a", ".so")) and lib == lib.lower():
                info.add_link("-l" + lib)


_MK_VAR = re.compile(r"^\s*(CXXFLAGS|CPPFLAGS|LDFLAGS|LDLIBS|LIBS)\s*[:+?]?=\s*(.*)$", re.M)


def parse_makefile(text: str, info: BuildInfo) -> None:
    text = text.replace("\\\n", " ")
    for m in _MK_VAR.finditer(text):
        var, val = m.group(1), re.sub(r"#.*", "", m.group(2))
        for a in _args(val):
            if "$" in a:
                continue
            if var in ("CXXFLAGS", "CPPFLAGS"):
                info.add_cxx(a)
            else:
                info.add_link(a)


def detect(root: str) -> BuildInfo:
    info = BuildInfo()
    cm = os.path.join(root, "CMakeLists.txt")
    if os.path.isfile(cm):
        parse_cmake(_read(cm), info)
        info.sources.append("CMakeLists.txt")
    for name in ("Makefile", "makefile", "GNUmakefile"):
        mk = os.path.join(root, name)
        if os.path.isfile(mk):
            parse_makefile(_read(mk), info)
            info.sources.append(name)
            break
    return info
