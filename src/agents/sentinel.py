"""Sentinel agent - static malware / supply-chain indicator scan of EVERY file in the project.

This is a heuristic indicator scanner, NOT an antivirus and NOT a sandbox.  It looks for things that
ordinary C++ coursework almost never contains (shellcode blobs, executable-memory tricks, process
injection APIs, Trojan-Source control characters, embedded executables ...).  Verdicts:

  CLEAN       nothing noteworthy                       -> everything allowed
  SUSPICIOUS  some indicators                          -> compile-only; dynamic execution is refused
  MALICIOUS   strong combined indicators               -> nothing is built or run; report only
"""
import os
import re
from dataclasses import dataclass, field
from typing import Dict, List, Tuple

from lexer import tokenize, IDENT, STRING, PUNCT, PREPROC, NUMBER
from compiler_runner import scan_source

THRESHOLD_SUSPICIOUS = 4
THRESHOLD_MALICIOUS = 10

_CALL_INDICATORS: Dict[str, Tuple[str, int, str]] = {
    # name -> (rule, weight, description)
    "mprotect": ("SEN-MEMEXEC", 3, "changes memory protection (can make memory executable)"),
    "VirtualProtect": ("SEN-MEMEXEC", 5, "changes memory protection (can make memory executable)"),
    "VirtualAlloc": ("SEN-MEMEXEC", 2, "allocates raw virtual memory"),
    "VirtualAllocEx": ("SEN-INJECT", 6, "allocates memory in another process (injection API)"),
    "WriteProcessMemory": ("SEN-INJECT", 6, "writes into another process (injection API)"),
    "CreateRemoteThread": ("SEN-INJECT", 6, "starts a thread in another process (injection API)"),
    "SetWindowsHookEx": ("SEN-KEYLOG", 5, "installs a global hook (keylogger technique)"),
    "SetWindowsHookExA": ("SEN-KEYLOG", 5, "installs a global hook (keylogger technique)"),
    "GetAsyncKeyState": ("SEN-KEYLOG", 4, "polls keyboard state (keylogger technique)"),
    "ptrace": ("SEN-ANTIDEBUG", 4, "ptrace (debugger detection / process control)"),
    "IsDebuggerPresent": ("SEN-ANTIDEBUG", 4, "debugger detection"),
    "dlopen": ("SEN-DYNLOAD", 3, "loads a shared library at run time"),
    "dlsym": ("SEN-DYNLOAD", 2, "resolves a symbol at run time"),
    "LoadLibraryA": ("SEN-DYNLOAD", 3, "loads a DLL at run time"),
    "LoadLibraryW": ("SEN-DYNLOAD", 3, "loads a DLL at run time"),
    "GetProcAddress": ("SEN-DYNLOAD", 2, "resolves a function address at run time"),
    "socket": ("SEN-NET", 3, "opens a network socket"),
    "connect": ("SEN-NET", 2, "network connect"),
    "getaddrinfo": ("SEN-NET", 2, "DNS lookup"),
    "gethostbyname": ("SEN-NET", 2, "DNS lookup"),
    "URLDownloadToFileA": ("SEN-DOWNLOAD", 6, "downloads a file from the internet"),
    "URLDownloadToFileW": ("SEN-DOWNLOAD", 6, "downloads a file from the internet"),
    "curl_easy_perform": ("SEN-NET", 3, "HTTP request"),
    "setuid": ("SEN-PRIV", 3, "changes user id"),
    "chroot": ("SEN-PRIV", 3, "changes root directory"),
}
_NET_HEADERS = ("sys/socket.h", "netinet/in.h", "arpa/inet.h", "winsock2.h", "winsock.h", "netdb.h")
_SENSITIVE_PATHS = ("/etc/passwd", "/etc/shadow", ".ssh", "id_rsa", "authorized_keys", "/dev/mem",
                    "/dev/kmem", "/dev/input", "/proc/self/mem", ".bashrc", ".bash_profile", "crontab",
                    "LD_PRELOAD", "CurrentVersion\\\\Run", "CurrentVersion\\Run", "/etc/rc.local",
                    "systemd/system", "Login Data", "wallet.dat")
_BIDI = re.compile("[‪-‮⁦-⁩​-‏  ﻿]")
_B64 = re.compile(r"^[A-Za-z0-9+/=]{80,}$")
_HEX_ESC = re.compile(r"(?:\\x[0-9A-Fa-f]{2}){16,}")
_URL = re.compile(r"https?://[^\s\"']+", re.I)
_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_SCRIPT_EXT = {".sh", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".py", ".pl", ".jar", ".scr", ".com", ".msi"}
_BIN_EXT = {".exe", ".dll", ".so", ".dylib", ".o", ".obj", ".a", ".lib", ".bin", ".class", ".pyc"}
_MAGICS = ((b"\x7fELF", "ELF executable"), (b"MZ", "Windows PE executable"),
           (b"\xcf\xfa\xed\xfe", "Mach-O executable"), (b"\xce\xfa\xed\xfe", "Mach-O executable"),
           (b"\xca\xfe\xba\xbe", "Mach-O / Java class"), (b"#!", "script with a shebang"))
_CODE_EXT = {".cpp", ".cc", ".cxx", ".c++", ".cp", ".h", ".hpp", ".hh", ".hxx", ".h++", ".inl", ".ipp",
             ".tpp", ".tcc", ".c"}


@dataclass
class Indicator:
    rule: str
    file: str
    line: int
    weight: int
    message: str


@dataclass
class SentinelReport:
    verdict: str = "CLEAN"
    score: int = 0
    indicators: List[Indicator] = field(default_factory=list)
    quarantined: List[Tuple[str, str]] = field(default_factory=list)      # (rel, reason): excluded from output
    gate_blocked: Dict[str, str] = field(default_factory=dict)
    scanned: int = 0

    @property
    def allows_execution(self) -> bool:
        return self.verdict == "CLEAN"

    @property
    def allows_build(self) -> bool:
        return self.verdict != "MALICIOUS"


def _scan_code(rel: str, text: str, out: List[Indicator]) -> None:
    m = _BIDI.search(text[1:] if text.startswith("\ufeff") else text)     # a leading BOM is normal on Windows files
    if m:
        m = _BIDI.search(text, 1 if text.startswith("\ufeff") else 0)
        line = text.count("\n", 0, m.start()) + 1
        out.append(Indicator("SEN-TROJAN-SOURCE", rel, line, 6,
                             "invisible / bidirectional Unicode control character (can make code read "
                             "differently from how it executes)"))
    if any(len(l) > 2000 for l in text.split("\n")):
        out.append(Indicator("SEN-MINIFIED", rel, 1, 1, "extremely long line (minified or packed code)"))

    toks = tokenize(text)
    seen_rules = set()

    def add(rule, line, weight, msg):
        key = (rule, line)
        if key not in seen_rules:
            seen_rules.add(key)
            out.append(Indicator(rule, rel, line, weight, msg))

    names_seen = set()
    payload_arrays: List[int] = []
    for i, t in enumerate(toks):
        if t.kind == PREPROC:
            low = t.text.replace(" ", "")
            if any(h in low for h in _NET_HEADERS):
                add("SEN-NET-HDR", t.line, 2, "includes a networking header")
            if "attribute((constructor" in low.replace("_", "") or "attribute((constructor)" in low:
                add("SEN-CTOR", t.line, 2, "constructor attribute (code runs before main)")
            continue
        if t.kind == IDENT and t.text in _CALL_INDICATORS and i + 1 < len(toks) \
                and toks[i + 1].kind == PUNCT and toks[i + 1].text == "(":
            rule, w, msg = _CALL_INDICATORS[t.text]
            add(rule, t.line, w, f"{t.text}(): {msg}")
            names_seen.add(t.text)
        elif t.kind == IDENT and t.text == "__attribute__" and i + 3 < len(toks):
            nxt = "".join(x.text for x in toks[i + 1:i + 6])
            if "constructor" in nxt:
                add("SEN-CTOR", t.line, 2, "constructor attribute (code runs before main)")
        elif t.kind == IDENT and t.text in ("PROT_EXEC", "PAGE_EXECUTE_READWRITE", "PAGE_EXECUTE_READ",
                                            "PAGE_EXECUTE"):
            add("SEN-MEMEXEC", t.line, 5, f"{t.text}: requests executable memory")
        elif t.kind == STRING:
            s = t.text
            body = s[s.find('"') + 1:s.rfind('"')] if '"' in s else s
            if _HEX_ESC.search(body):
                add("SEN-BYTES", t.line, 2, "string made of many \\x escapes (binary blob)")
                payload_arrays.append(t.line)
                if re.search(r"\\x0f\\x05|\\xcd\\x80|(?:\\x90){6}|\\x31\\xc0|\\x48\\x31", body, re.I):
                    add("SEN-SHELLCODE", t.line, 5, "escaped string containing machine-code signatures")
            if _B64.match(body):
                add("SEN-ENCODED", t.line, 2, "long base64-like string literal")
            for p in _SENSITIVE_PATHS:
                if p in body:
                    add("SEN-SENSITIVE-PATH", t.line, 5, f"refers to sensitive location {p!r}")
                    break
            if _URL.search(body) or _IPV4.search(body):
                add("SEN-ENDPOINT", t.line, 2, "hard-coded URL / IP address")
        elif t.kind == PUNCT and t.text == "{":
            # long array of 2-digit hex BYTES: a lookup table (weight 2) unless it carries machine-code signatures
            j, nums = i + 1, []
            while j < len(toks) and (toks[j].kind == NUMBER or (toks[j].kind == PUNCT and toks[j].text == ",")):
                if toks[j].kind == NUMBER:
                    nums.append(toks[j].text.lower())
                j += 1
            if len(nums) >= 32 and j < len(toks) and toks[j].text == "}":
                byte_like = [n for n in nums if re.fullmatch(r"0x[0-9a-f]{2}", n)]
                if len(byte_like) >= 0.9 * len(nums):
                    vals = [int(n, 16) for n in byte_like]
                    blob = bytes(vals)
                    sig = (b"\x0f\x05" in blob or b"\xcd\x80" in blob or b"\x90" * 6 in blob or b"\x31\xc0" in blob
                           or b"\x48\x31" in blob or b"\xff\xe4" in blob or b"\xff\xd0" in blob)
                    payload_arrays.append(t.line)
                    if sig:
                        add("SEN-SHELLCODE", t.line, 5, f"array of {len(nums)} bytes containing machine-code "
                                                        "signatures (syscall / NOP sled / xor-clear)")
                    else:
                        add("SEN-BYTES", t.line, 2, f"array of {len(nums)} hexadecimal bytes (lookup table or payload)")
    # an embedded payload next to code that can execute or load it = loader behaviour
    if payload_arrays and any(r in {o.rule for o in out if o.file == rel} for r in ("SEN-MEMEXEC", "SEN-INJECT", "SEN-DYNLOAD")):
        out.append(Indicator("SEN-LOADER-LIKE", rel, payload_arrays[0], 5,
                             "embedded byte payload combined with executable-memory / injection / dynamic-load APIs"))
    # encryption / wiper-style filesystem sweep: directory walk + destructive file ops + xor
    if {"opendir", "readdir"} <= names_seen | {x.text for x in toks if x.kind == IDENT} and \
            any(x.kind == IDENT and x.text in ("remove", "unlink", "rename") for x in toks) and \
            any(x.kind == PUNCT and x.text == "^=" for x in toks):
        out.append(Indicator("SEN-RANSOM-LIKE", rel, 1, 5,
                             "walks directories, renames/deletes files and XOR-transforms data (ransomware-like)"))
    if {"getenv"} & {x.text for x in toks if x.kind == IDENT} and \
            names_seen & {"socket", "connect", "curl_easy_perform", "getaddrinfo"}:
        out.append(Indicator("SEN-EXFIL-LIKE", rel, 1, 3, "reads environment variables and uses the network"))


def scan_project(proj, permissions=None) -> SentinelReport:
    rep = SentinelReport()
    for dirpath, dirnames, filenames in os.walk(proj.root, followlinks=False):
        dirnames[:] = [d for d in dirnames if not d.startswith("gsc_objs_") and d != ".git"]
        for fn in sorted(filenames):
            full = os.path.join(dirpath, fn)
            rel = os.path.relpath(full, proj.root).replace(os.sep, "/")
            if os.path.islink(full):
                continue
            ext = os.path.splitext(fn)[1].lower()
            rep.scanned += 1
            try:
                with open(full, "rb") as f:
                    head = f.read(8)
            except OSError:
                continue
            is_code = ext in _CODE_EXT
            if not is_code:
                kind = next((d for m, d in _MAGICS if head.startswith(m)), None)
                if kind and kind != "script with a shebang":
                    rep.indicators.append(Indicator("SEN-BINARY", rel, 0, 6, f"{kind} inside the project"))
                    rep.quarantined.append((rel, kind))
                elif ext in _BIN_EXT:
                    rep.indicators.append(Indicator("SEN-BINARY", rel, 0, 4, f"binary artefact ({ext})"))
                    rep.quarantined.append((rel, f"binary artefact ({ext})"))
                elif ext in _SCRIPT_EXT or head.startswith(b"#!"):
                    rep.indicators.append(Indicator("SEN-SCRIPT", rel, 0, 2,
                                                    "script file in a C++ project (kept, never executed)"))
                continue
            try:
                text = open(full, "r", encoding="utf-8", errors="ignore", newline="").read()
            except OSError:
                continue
            _scan_code(rel, text, rep.indicators)
            if ext not in (".c",):
                viol = scan_source(text, permissions, include_dir=os.path.dirname(full), confine_root=proj.root)
                if viol:
                    rep.gate_blocked[rel] = "; ".join(str(v) for v in viol[:3])
                    rep.indicators.append(Indicator("SEN-GATE", rel, viol[0].line or 0, 3,
                                                    "safety gate: " + str(viol[0])))
    # a rule repeated many times in one file counts once per (rule,file) pair, so noisy files don't explode
    best: Dict[Tuple[str, str], int] = {}
    for ind in rep.indicators:
        k = (ind.rule, ind.file)
        best[k] = max(best.get(k, 0), ind.weight)
    rep.score = sum(best.values())
    non_gate = sum(v for (rule, _f), v in best.items() if rule != "SEN-GATE")
    # gate hits alone (e.g. system("pause") in coursework) never make a project MALICIOUS
    rep.verdict = ("MALICIOUS" if non_gate >= THRESHOLD_MALICIOUS else
                   "SUSPICIOUS" if rep.score >= THRESHOLD_SUSPICIOUS else "CLEAN")
    # gate violations alone never reach MALICIOUS (e.g. system("pause") in coursework); they still stop execution
    if rep.gate_blocked and rep.verdict == "CLEAN":
        rep.verdict = "SUSPICIOUS"
    return rep
