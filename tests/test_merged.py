"""Tests for the merged system: universal multi-language layer + verified C++ agentic pipeline."""
import os
import shutil
import sys
import tempfile
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

from universal.agents import Options          # noqa: E402
from universal.engine import run_audit        # noqa: E402

HAVE_GPP = shutil.which("g++") is not None
PY = "import subprocess, hashlib\ndef run(c):\n    return subprocess.call(c, shell=True)\ndef h(p): return hashlib.md5(p.encode()).hexdigest()\n"
CPP = ('#include <iostream>\n#include <vector>\nint main(){\n    std::vector<int> v;\n'
       '    for (int i = 0; i < 5; i++) { v.push_back(i)\n        std::cout << i << std::endl;\n    }\n    return 0;\n}\n')


def _mk(files):
    d = tempfile.mkdtemp()
    for rel, txt in files.items():
        p = os.path.join(d, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        open(p, "w").write(txt)
    return d


def test_mixed_project_cpp_goes_through_verified_agents():
    if not HAVE_GPP:
        return "skip"
    d = _mk({"src/app.py": PY, "src/main.cpp": CPP})
    out = os.path.join(tempfile.mkdtemp(), "o.zip")
    try:
        ctx = run_audit(d, Options(out=out))
        ag = ctx.cpp.get("agentic")
        assert ag and ag["verdict"] == "VERIFIED" and ag["changes"] >= 2, ctx.cpp
        assert ctx.cpp["compile_ok_after"] and ctx.cpp["link_ok_after"] and not ctx.cpp["compile_ok"]
        with zipfile.ZipFile(out) as z:
            cpp = z.read([n for n in z.namelist() if n.endswith("main.cpp")][0]).decode()
            rep = z.read([n for n in z.namelist() if n.endswith("REPORT.md")][0]).decode()
        assert "push_back(i);" in cpp and "'\\n'" in cpp and "reserve(5)" in cpp
        assert "C++ agent pipeline" in rep and any(f.language == "python" and f.rule_id for f in ctx.findings)
        assert open(os.path.join(d, "src/main.cpp")).read() == CPP          # input never modified
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_healer_uses_compiler_column_for_one_line_bodies():
    from auto_healer import fix_syntax_error
    src = "int main(){\n    for (int i = 0; i < 5; i++) { f(i)\n        g(i);\n    }\n}\n"
    err = {"line": 2, "column": 39, "message": "expected ';' before 'g'", "category": "syntax_error"}
    out = fix_syntax_error(src, err)
    assert out and "{ f(i);" in out, out


def test_c_files_are_gated_before_gcc():
    """The C checker must not feed host-file includes (digraph or literal) to the compiler."""
    from universal import toolcheck as TC
    for text in ('%:include "/etc/passwd"\nint main(){return 0;}\n', '#include "/etc/passwd"\nint main(){return 0;}\n',
                 '#include <sys/socket.h>\nint main(){return 0;}\n'):
        fs = TC.check_c(text, "a.c", [])
        assert any(f.rule_id == "C-GATE-BLOCKED" for f in fs), (text, [f.rule_id for f in fs])
    if shutil.which("gcc"):
        assert not any(f.rule_id == "C-GATE-BLOCKED" for f in TC.check_c('#include <stdio.h>\nint main(){puts("x");return 0;}\n', "ok.c", []))


def test_cpp_in_mixed_project_still_blocked_by_gate():
    d = _mk({"src/app.py": "print(1)\n", "src/evil.cpp": '#include <cstdlib>\nint main(){ std::system("id"); }\n'})
    try:
        ctx = run_audit(d, Options(out=os.path.join(tempfile.mkdtemp(), "o.zip")))
        assert ctx.cpp.get("blocked") or any(f.rule_id == "CPP-BLOCKED" for f in ctx.findings), ctx.cpp
    finally:
        shutil.rmtree(d, ignore_errors=True)


def main():
    tests = [(n, f) for n, f in sorted(globals().items()) if n.startswith("test_") and callable(f)]
    ok = skipped = failed = 0
    for name, fn in tests:
        try:
            r = fn()
            if r == "skip":
                skipped += 1
                print(f"SKIP  {name}")
            else:
                ok += 1
                print(f"ok    {name}")
        except Exception as e:                                   # noqa: BLE001
            failed += 1
            import traceback
            print(f"FAIL  {name}: {type(e).__name__}: {e}")
            traceback.print_exc(limit=3)
    print(f"\n{ok} passed, {skipped} skipped, {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
