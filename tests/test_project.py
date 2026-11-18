"""
Tests for multi-file project support (folder / .zip / .tar.gz): safe intake, safety gate,
per-file compile, linking, analysis, self-healing and hardening across files.

Run:  python tests/test_project.py
Tests that need g++ are reported as SKIPPED (never silently passed) when it is missing.
"""
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))
os.environ.setdefault("GSC_DISABLE_DATASET_LOGGING", "1")
os.environ["GSC_CACHE_DIR"] = tempfile.mkdtemp(prefix="gsc_test_cache_")

import project as P                                # noqa: E402
import secure_fixer as SF                          # noqa: E402

MAIN = os.path.join(ROOT, "src", "main.py")
DEMO = os.path.join(ROOT, "demo")


class Skip(Exception):
    pass


def needs(*tools):
    def deco(fn):
        def wrapper(*a, **k):
            missing = [t for t in tools if not shutil.which(t)]
            if missing:
                raise Skip("needs " + ", ".join(missing))
            return fn(*a, **k)
        wrapper.__name__ = fn.__name__
        return wrapper
    return deco


def make_tree(files: dict) -> str:
    d = tempfile.mkdtemp(prefix="gsc_pt_")
    for rel, text in files.items():
        p = os.path.join(d, *rel.split("/"))
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w", newline="") as f:
            f.write(text)
    return d


def make_zip(files: dict, extra=None) -> str:
    fd, path = tempfile.mkstemp(suffix=".zip", prefix="gsc_pz_")
    os.close(fd)
    with zipfile.ZipFile(path, "w") as zf:
        for rel, text in files.items():
            zf.writestr(rel, text)
        for fn in (extra or []):
            fn(zf)
    return path


def cli(*args):
    env = dict(os.environ, GSC_DISABLE_DATASET_LOGGING="1", PYTHONWARNINGS="ignore")
    r = subprocess.run([sys.executable, MAIN, *args], capture_output=True, text=True, env=env)
    return r.returncode, r.stdout, r.stderr


GOOD = {
    "include/lib.h": "#pragma once\nint twice(int x);\n",
    "src/lib.cpp": '#include "lib.h"\nint twice(int x) { return x * 2; }\n',
    "src/main.cpp": '#include <cstdio>\n#include "lib.h"\nint main() { std::printf("%d\\n", twice(4)); return 0; }\n',
}


# ───────────────────────── safe intake ─────────────────────────
def test_zip_slip_is_rejected():
    z = make_zip({"../evil.cpp": "int x;\n"})
    try:
        P.open_project(z)
    except P.ProjectError as e:
        assert "traversal" in str(e)
        return
    raise AssertionError("zip-slip path was accepted")


def test_absolute_path_in_zip_is_rejected():
    z = make_zip({"/etc/evil.cpp": "int x;\n"})
    try:
        P.open_project(z)
    except P.ProjectError as e:
        assert "absolute" in str(e)
        return
    raise AssertionError("absolute path was accepted")


def test_symlink_in_zip_is_skipped_not_followed():
    def add_link(zf):
        info = zipfile.ZipInfo("link.cpp")
        info.external_attr = (0o120777 << 16)
        zf.writestr(info, "/etc/passwd")
    z = make_zip({"a.cpp": "int a;\n"}, extra=[add_link])
    with P.open_project(z) as pr:
        assert pr.sources == ["a.cpp"], pr.sources
        assert any("symlink" in n for n in pr.notes)


def test_zip_bomb_is_rejected():
    old = P.MAX_TOTAL_BYTES
    P.MAX_TOTAL_BYTES = 10_000
    try:
        z = make_zip({"big.cpp": "// " + "A" * 50_000 + "\n"})
        try:
            P.open_project(z)
        except P.ProjectError as e:
            assert "limit" in str(e) or "bomb" in str(e) or "larger" in str(e)
            return
        raise AssertionError("oversized zip was accepted")
    finally:
        P.MAX_TOTAL_BYTES = old


def test_too_many_files_is_rejected():
    old = P.MAX_FILES
    P.MAX_FILES = 5
    try:
        z = make_zip({f"f{i}.cpp": "int x;\n" for i in range(10)})
        try:
            P.open_project(z)
        except P.ProjectError as e:
            assert "too many" in str(e)
            return
        raise AssertionError("file-count limit not enforced")
    finally:
        P.MAX_FILES = old


def test_not_a_zip_is_a_clean_error():
    fd, path = tempfile.mkstemp(suffix=".zip")
    os.write(fd, b"this is not a zip")
    os.close(fd)
    try:
        P.open_project(path)
    except P.ProjectError:
        return
    raise AssertionError("corrupt zip accepted")


def test_tar_gz_input_and_wrapper_folder_collapse():
    d = make_tree({"proj/" + k: v for k, v in GOOD.items()})
    fd, tgz = tempfile.mkstemp(suffix=".tar.gz")
    os.close(fd)
    with tarfile.open(tgz, "w:gz") as tf:
        tf.add(os.path.join(d, "proj"), arcname="proj")
    with P.open_project(tgz) as pr:
        assert pr.kind == "tar"
        assert sorted(pr.sources) == ["src/lib.cpp", "src/main.cpp"], pr.sources
        assert pr.headers == ["include/lib.h"]


def test_discovery_skips_generated_excluded_and_c_files():
    d = make_tree({**GOOD, "src/lib.hardened.cpp": "int dup;\n", "tests/t.cpp": "int main(){}\n",
                   "legacy/old.cpp": "int old;\n", "src/c_file.c": "int c;\n",
                   "build/CMakeFiles/x.cpp": "int z;\n", ".git/hooks/p.cpp": "int g;\n"})
    with P.open_project(d, exclude=["tests/*", "legacy"]) as pr:
        assert sorted(pr.sources) == ["src/lib.cpp", "src/main.cpp"], pr.sources
        reasons = dict(pr.skipped)
        assert "src/lib.hardened.cpp" in reasons and "src/c_file.c" in reasons
        assert "tests/t.cpp" in reasons and "legacy/" in reasons


def test_single_wrapper_folder_in_zip():
    z = make_zip({"myproj/" + k: v for k, v in GOOD.items()})
    with P.open_project(z) as pr:
        assert pr.sources == ["src/lib.cpp", "src/main.cpp"] and pr.name == os.path.basename(z)[:-4]


# ───────────────────────── build + link ─────────────────────────
@needs("g++", "nm")
def test_multi_file_project_compiles_and_links():
    d = make_tree(GOOD)
    with P.open_project(d) as pr:
        r = P.analyze_project(pr)
        assert r.compile_ok and r.link_ok and r.error_count == 0, (r.error_count, r.link_errors)
        assert [t.name for t in r.targets] == ["program"]


@needs("g++", "nm")
def test_undefined_reference_across_files_is_a_link_error_with_location():
    d = make_tree({"a.h": "int missing();\n", "a.cpp": '#include "a.h"\nint f(){ return 1; }\n',
                   "main.cpp": '#include "a.h"\nint main(){ return missing(); }\n'})
    with P.open_project(d) as pr:
        r = P.analyze_project(pr)
        assert r.compile_ok and not r.link_ok
        e = r.link_errors[0]
        assert "undefined reference" in e.message and "missing" in e.message
        assert e.file == "main.cpp" and e.line == 2, (e.file, e.line)


@needs("g++", "nm")
def test_multiple_definition_is_reported_with_both_locations():
    d = make_tree({"a.cpp": "int h(){return 1;}\n", "b.cpp": "int h(){return 2;}\n",
                   "main.cpp": "int h();\nint main(){return h();}\n"})
    with P.open_project(d) as pr:
        r = P.analyze_project(pr)
        e = [x for x in r.link_errors if "multiple definition" in x.message][0]
        assert "first defined at" in e.message and e.file in ("a.cpp", "b.cpp")
        assert "more than one" in e.explanation            # precise explanation, not 'undefined'


@needs("g++", "nm")
def test_several_mains_link_as_separate_programs():
    d = make_tree({"lib.cpp": "int k(){return 3;}\n",
                   "p1.cpp": "int k();\nint main(){return k();}\n",
                   "p2.cpp": "int k();\nint main(){return k()+1;}\n"})
    with P.open_project(d) as pr:
        r = P.analyze_project(pr)
        assert r.link_ok and len(r.targets) == 2, [(t.name, t.ok) for t in r.targets]
        assert all("lib.cpp" in t.files for t in r.targets)


@needs("g++", "nm")
def test_library_without_main_is_link_checked_with_stub():
    d = make_tree({"a.cpp": "int f();\nint g(){ return f(); }\n", "b.cpp": "int f(){ return 1; }\n"})
    with P.open_project(d) as pr:
        r = P.analyze_project(pr)
        assert r.link_ok and r.targets[0].stub
    d2 = make_tree({"a.cpp": "int f();\nint g(){ return f(); }\n"})        # f never defined
    with P.open_project(d2) as pr:
        r = P.analyze_project(pr)
        assert not r.link_ok and "undefined reference" in r.link_errors[0].message


@needs("g++", "nm")
def test_compile_errors_are_attributed_to_the_right_file_and_header_errors_dedupe():
    d = make_tree({"h.h": "#pragma once\ninline int t(int x){ return x * 2 }\n",
                   "a.cpp": '#include "h.h"\nint a(){ return t(1); }\n',
                   "b.cpp": '#include "h.h"\nint b(){ return t(2); }\n',
                   "main.cpp": "int main(){ return 0; }\n"})
    with P.open_project(d) as pr:
        r = P.analyze_project(pr)
        errs = r.unique_errors()
        assert len([e for e in errs if e.file == "h.h"]) == 1, [(e.file, e.line) for e in errs]
        assert r.link_skipped and not r.targets


@needs("g++", "nm")
def test_include_from_sibling_dir_via_dotdot_is_allowed_inside_project():
    d = make_tree({"include/x.h": "#pragma once\nint x();\n",
                   "src/m.cpp": '#include "../include/x.h"\nint x(){return 1;}\nint main(){return x();}\n'})
    with P.open_project(d) as pr:
        r = P.analyze_project(pr)
        assert not r.blocked and r.link_ok


@needs("g++", "nm")
def test_extra_flags_and_thread_autolink():
    d = make_tree({"main.cpp": '#include <thread>\nvoid f(){}\nint main(){ std::thread t(f); t.join(); return 0; }\n'})
    with P.open_project(d) as pr:
        assert P.analyze_project(pr).link_ok
    d = make_tree({"main.cpp": "#ifndef FLAG\n#error FLAG missing\n#endif\nint main(){return 0;}\n"})
    with P.open_project(d) as pr:
        assert not P.analyze_project(pr).compile_ok
    with P.open_project(d) as pr:
        assert P.analyze_project(pr, cxxflags=["-DFLAG"]).link_ok


# ───────────────────────── safety gate ─────────────────────────
@needs("g++", "nm")
def test_gate_blocks_whole_project_before_any_compiler_runs():
    d = make_tree({"ok.cpp": "int f(){return 1;}\n",
                   "bad.cpp": '#include <cstdlib>\nint g(){ return system("ls"); }\n',
                   "main.cpp": "int main(){return 0;}\n"})
    calls = []
    real = P.Builder.compile_tu
    P.Builder.compile_tu = lambda self, rel: calls.append(rel) or real(self, rel)
    try:
        with P.open_project(d) as pr:
            r = P.analyze_project(pr)
    finally:
        P.Builder.compile_tu = real
    assert r.blocked and "bad.cpp" in r.blocked_files and not calls, (r.blocked_files, calls)
    assert not r.targets


@needs("g++", "nm")
def test_gate_blocks_forbidden_call_hidden_in_a_header():
    d = make_tree({"h.h": '#pragma once\n#include <cstdlib>\ninline void go(){ system("id"); }\n',
                   "main.cpp": '#include "h.h"\nint main(){ go(); return 0; }\n'})
    with P.open_project(d) as pr:
        r = P.analyze_project(pr)
        assert r.blocked and "h.h" in r.blocked_files


@needs("g++", "nm")
def test_gate_blocks_include_that_escapes_the_project():
    d = make_tree({"main.cpp": '#include "../../../../etc/passwd"\nint main(){return 0;}\n'})
    with P.open_project(d) as pr:
        r = P.analyze_project(pr)
        assert r.blocked and "main.cpp" in r.blocked_files


# ───────────────────────── healing and hardening ─────────────────────────
@needs("g++", "nm")
def test_heal_fixes_errors_in_several_files_including_a_header():
    with P.open_project(os.path.join(DEMO, "project_heal")) as pr:
        h = P.heal_project(pr)
        assert h.clean and h.link_ok, (h.reason, h.history)
        assert sorted(h.changed) == ["include/calc.h", "src/calc.cpp", "src/main.cpp"]
        assert P.analyze_project(pr).built


@needs("g++", "nm")
def test_heal_never_touches_the_original_folder():
    src = os.path.join(DEMO, "project_heal")
    before = {p: open(os.path.join(src, p)).read() for p in ("src/calc.cpp", "src/main.cpp", "include/calc.h")}
    with P.open_project(src) as pr:
        P.heal_project(pr)
    after = {p: open(os.path.join(src, p)).read() for p in before}
    assert before == after


@needs("g++", "nm")
def test_heal_refuses_linker_errors_and_says_so():
    with P.open_project(os.path.join(DEMO, "project_link_error")) as pr:
        h = P.heal_project(pr)
        assert not h.clean and h.link_ok is False and not h.changed
        assert "linker" in h.reason and h.link_errors


@needs("g++", "nm")
def test_harden_fixes_multiple_files_and_project_still_links():
    with P.open_project(os.path.join(DEMO, "project_shapes")) as pr:
        hp = P.harden_project(pr)
        assert sorted(hp.changed) == ["src/main.cpp", "src/util.cpp"]
        assert hp.build_ok_before and hp.build_ok_after and not hp.remaining
        assert P.analyze_project(pr).built


@needs("g++", "nm")
def test_harden_rolls_back_a_fix_that_breaks_the_whole_project():
    real = SF.harden_source

    def evil(source, path="<source>", verify=True, include_dirs=()):
        r = real(source, path, verify, include_dirs)
        if path.endswith("main.cpp") and r.applied:
            r.hardened = r.hardened + "\nthis is not valid c++ (\n"          # breaks the whole-project build
        return r
    SF.harden_source = evil
    try:
        with P.open_project(os.path.join(DEMO, "project_shapes")) as pr:
            hp = P.harden_project(pr)
            assert "src/main.cpp" in hp.rolled_back and "src/main.cpp" not in hp.changed
            assert "src/util.cpp" in hp.changed and hp.build_ok_after
    finally:
        SF.harden_source = real


@needs("g++", "nm")
def test_in_place_keeps_crlf_and_refuses_archives():
    d = make_tree({"a.cpp": "int f(){\r\n  return 1\r\n}\r\n", "main.cpp": "int f();\r\nint main(){return f();}\r\n"})
    with P.open_project(d) as pr:
        h = P.heal_project(pr)
        assert h.clean
        P.write_in_place(pr, h.changed)
    raw = open(os.path.join(d, "a.cpp"), "rb").read()
    assert b"\r\n" in raw and b"return 1;" in raw
    z = make_zip(GOOD)
    with P.open_project(z) as pr:
        try:
            P.write_in_place(pr, ["src/lib.cpp"])
        except P.ProjectError:
            return
    raise AssertionError("--in-place on an archive must be refused")


# ───────────────────────── CLI ─────────────────────────
@needs("g++", "nm")
def test_cli_zip_clean_project_exit_zero():
    z = make_zip({"proj/" + k: v for k, v in GOOD.items()})
    code, out, _ = cli(z, "--no-optimize")
    assert code == 0 and "link OK" in out and "3 header" not in out, out[:400]


@needs("g++", "nm")
def test_cli_link_error_exit_one_and_names_file():
    code, out, _ = cli(os.path.join(DEMO, "project_link_error.zip"))
    assert code == 1 and "link FAILED" in out and "src/main.cpp" in out and "cube" in out


@needs("g++", "nm")
def test_cli_fail_on_and_json_and_sarif_cover_all_files():
    shapes = os.path.join(DEMO, "project_shapes")
    assert cli(shapes, "--fail-on", "high", "--no-optimize")[0] == 2
    code, out, _ = cli(shapes, "--format", "json", "--no-optimize")
    doc = json.loads(out)
    assert doc["link_ok"] is True and set(doc["files"]) == {"src/main.cpp", "src/shapes.cpp", "src/util.cpp"}
    assert {f["file"] for f in doc["security_findings"]} == {"src/main.cpp", "src/util.cpp"}
    code, out, _ = cli(shapes, "--format", "sarif", "--no-optimize")
    sarif = json.loads(out)
    uris = {loc["physicalLocation"]["artifactLocation"]["uri"]
            for run in sarif["runs"] for r in run["results"] for loc in r["locations"]}
    assert any(u.endswith("util.cpp") for u in uris) and any(u.endswith("main.cpp") for u in uris), uris


@needs("g++", "nm")
def test_cli_heal_and_harden_write_new_zip_and_leave_input_alone():
    d = tempfile.mkdtemp()
    shutil.copy(os.path.join(DEMO, "project_heal.zip"), d)
    shutil.copy(os.path.join(DEMO, "project_shapes.zip"), d)
    code, out, _ = cli(os.path.join(d, "project_heal.zip"), "--heal")
    assert code == 0 and "BUILDS" in out and os.path.exists(os.path.join(d, "project_heal.healed.zip")), out[-400:]
    code, out, _ = cli(os.path.join(d, "project_shapes.zip"), "--harden")
    assert code == 0 and "BUILDS" in out and os.path.exists(os.path.join(d, "project_shapes.hardened.zip"))
    with zipfile.ZipFile(os.path.join(d, "project_shapes.zip")) as z:
        assert b"strcpy" in z.read("project_shapes/src/util.cpp")
    with zipfile.ZipFile(os.path.join(d, "project_shapes.hardened.zip")) as z:
        assert b"strcpy" not in z.read("project_shapes/src/util.cpp")


@needs("g++", "nm")
def test_cli_single_file_mode_is_unchanged():
    code, out, _ = cli(os.path.join(DEMO, "01_null_deref.cpp"))
    assert "CWE-476" in out and "Project:" not in out


@needs("g++", "nm")
def test_scale_many_files_links_quickly():
    n = 60
    files = {f"src/m{i}.cpp": f"int f{i}(int x){{ return x + {i}; }}\n" for i in range(n)}
    files["include/all.h"] = "#pragma once\n" + "".join(f"int f{i}(int);\n" for i in range(n))
    files["src/main.cpp"] = '#include "all.h"\nint main(){ int s=0;\n' + \
        "".join(f" s += f{i}(1);\n" for i in range(n)) + " return s > 0 ? 0 : 1; }\n"
    d = make_tree(files)
    t = time.time()
    with P.open_project(d) as pr:
        r = P.analyze_project(pr, optimize=False)
        assert r.n_sources == n + 1 and r.compile_ok and r.link_ok, (r.error_count, r.link_errors)
    assert time.time() - t < 120


# ───────────────────────── runner ─────────────────────────
if __name__ == "__main__":
    tests = [(n, f) for n, f in sorted(globals().items()) if n.startswith("test_") and callable(f)]
    passed = failed = skipped = 0
    for name, fn in tests:
        try:
            fn()
            print(f"PASS  {name}")
            passed += 1
        except Skip as s:
            print(f"SKIP  {name}: {s}")
            skipped += 1
        except Exception as e:                          # noqa: BLE001
            print(f"FAIL  {name}: {type(e).__name__}: {e}")
            failed += 1
    print(f"\n{passed}/{len(tests)} passed" + (f", {skipped} skipped" if skipped else "")
          + (f", {failed} FAILED" if failed else ""))
    sys.exit(1 if failed else 0)
