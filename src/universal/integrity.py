"""
integrity.py - cross-file integration checks, so fixing one file cannot silently break another.

  Python : local imports resolve (module exists, imported name is defined); public API surface of a file unchanged
  JS/TS  : relative import/require targets exist
  all    : names removed from a module (unused-import cleanup) are not imported from it elsewhere
"""
from __future__ import annotations

import ast
import os
import posixpath
import re
from .core import pysrc
from typing import Dict, List, Optional, Set, Tuple

_JS_IMPORT = re.compile(r"""(?:import\s[^'"]*?from\s*|import\s*|require\s*\(\s*|import\s*\(\s*)["'](\.{1,2}/[^"']+)["']""")
_JS_EXTS = ("", ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".json", "/index.js", "/index.ts", "/index.mjs")


def py_module_names(files: Dict[str, str]) -> Dict[str, str]:
    """dotted module name -> relative path, for every .py file (packages with or without __init__)."""
    m = {}
    for rel in files:
        if not rel.endswith(".py"):
            continue
        stem = rel[:-3]
        if stem.endswith("/__init__"):
            stem = stem[: -len("/__init__")]
        dotted = stem.replace("/", ".")
        m[dotted] = rel
        parts = dotted.split(".")                              # also reachable from a source root (src/pkg/mod.py -> pkg.mod)
        for k in range(1, len(parts)):
            m.setdefault(".".join(parts[k:]), rel)
    return m


def py_defined_names(text: str) -> Optional[Set[str]]:
    try:
        tree = ast.parse(pysrc(text))
    except (SyntaxError, ValueError, RecursionError):
        return None
    names: Set[str] = set()
    for n in tree.body:
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.add(n.name)
        elif isinstance(n, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
            tg = n.targets if isinstance(n, ast.Assign) else [n.target]
            for t in tg:
                for x in ast.walk(t):
                    if isinstance(x, ast.Name):
                        names.add(x.id)
        elif isinstance(n, (ast.Import, ast.ImportFrom)):
            for a in n.names:
                names.add((a.asname or a.name).split(".")[0])
        elif isinstance(n, (ast.If, ast.Try, ast.With, ast.For)):
            for x in ast.walk(n):
                if isinstance(x, (ast.FunctionDef, ast.ClassDef)):
                    names.add(x.name)
                elif isinstance(x, ast.Name) and isinstance(x.ctx, ast.Store):
                    names.add(x.id)
                elif isinstance(x, (ast.Import, ast.ImportFrom)):
                    for a in x.names:
                        names.add((a.asname or a.name).split(".")[0])
    return names


def py_api_surface(text: str) -> Optional[Dict[str, Tuple]]:
    """Public top-level functions/classes with their parameter names: what other files can depend on."""
    try:
        tree = ast.parse(pysrc(text))
    except (SyntaxError, ValueError, RecursionError):
        return None
    api = {}
    for n in tree.body:
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and not n.name.startswith("_"):
            a = n.args
            api[n.name] = ("def", tuple(x.arg for x in a.posonlyargs + a.args), a.vararg is not None, a.kwarg is not None,
                           tuple(x.arg for x in a.kwonlyargs))
        elif isinstance(n, ast.ClassDef) and not n.name.startswith("_"):
            meths = tuple(sorted(m.name for m in n.body if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef)) and not m.name.startswith("_")))
            api[n.name] = ("class", meths)
    return api


def py_unresolved_imports(files: Dict[str, str]) -> Set[Tuple[str, int, str]]:
    """(file, line, description) for local imports that no longer resolve."""
    mods = py_module_names(files)
    top_pkgs = {m.split(".")[0] for m in mods}
    defined_cache: Dict[str, Optional[Set[str]]] = {}
    bad: Set[Tuple[str, int, str]] = set()
    for rel, text in files.items():
        if not rel.endswith(".py"):
            continue
        try:
            tree = ast.parse(pysrc(text))
        except (SyntaxError, ValueError, RecursionError):
            continue
        for n in ast.walk(tree):
            if isinstance(n, ast.Import):
                for a in n.names:
                    if a.name.split(".")[0] in top_pkgs and a.name not in mods and a.name.split(".")[0] not in {m for m in mods if "." not in m}:
                        bad.add((rel, n.lineno, f"import {a.name}"))
            elif isinstance(n, ast.ImportFrom) and n.module and n.level == 0:
                if n.module.split(".")[0] not in top_pkgs:
                    continue
                if n.module not in mods:
                    bad.add((rel, n.lineno, f"from {n.module} import ..."))
                    continue
                target = mods[n.module]
                if target not in defined_cache:
                    defined_cache[target] = py_defined_names(files[target])
                defs = defined_cache[target]
                if defs is None:
                    continue
                for a in n.names:
                    if a.name != "*" and a.name not in defs and f"{n.module}.{a.name}" not in mods:
                        bad.add((rel, n.lineno, f"from {n.module} import {a.name}"))
    return bad


def js_unresolved_imports(files: Dict[str, str]) -> Set[Tuple[str, int, str]]:
    bad = set()
    names = set(files)
    for rel, text in files.items():
        if not rel.endswith((".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx")):
            continue
        base = posixpath.dirname(rel)
        for m in _JS_IMPORT.finditer(text):
            tgt = posixpath.normpath(posixpath.join(base, m.group(1)))
            if not any((tgt + ext) in names for ext in _JS_EXTS):
                bad.add((rel, text.count("\n", 0, m.start()) + 1, m.group(1)))
    return bad


def new_breakage(before: Dict[str, str], after: Dict[str, str]) -> List[str]:
    """Human-readable list of integration problems present AFTER the changes but not BEFORE."""
    out = []
    for rel, ln, what in sorted((py_unresolved_imports(after) | js_unresolved_imports(after)) -
                                (py_unresolved_imports(before) | js_unresolved_imports(before))):
        out.append(f"{rel}:{ln}: unresolved local import {what}")
    for rel, text in after.items():
        if rel.endswith(".py") and rel in before:
            b, a = py_api_surface(before[rel]), py_api_surface(text)
            if b is not None and a is not None:
                for name in sorted(set(b) - set(a)):
                    out.append(f"{rel}: public name '{name}' disappeared")
                for name in sorted(n for n in set(b) & set(a) if b[n] != a[n]):
                    out.append(f"{rel}: signature/shape of '{name}' changed")
    return out


def imported_from_elsewhere(files: Dict[str, str], rel: str, name: str) -> bool:
    """Is ``name`` imported FROM module ``rel`` by another file (so deleting it there would break that file)?"""
    mods = py_module_names(files)
    dotted = [d for d, p in mods.items() if p == rel]
    if not dotted:
        return False
    for other, text in files.items():
        if other == rel or not other.endswith(".py"):
            continue
        for d in dotted:
            if re.search(rf"^\s*from\s+{re.escape(d)}\s+import\s+[^#\n]*\b{re.escape(name)}\b", text, re.M):
                return True
    return False
