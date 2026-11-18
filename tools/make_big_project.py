#!/usr/bin/env python3
"""Generate a large multi-file C++ project for scale-testing --agentic:  make_big_project.py OUT_DIR [N=150]"""
import os, sys
out = sys.argv[1]
n = int(sys.argv[2]) if len(sys.argv) > 2 else 150
os.makedirs(os.path.join(out, "src"), exist_ok=True)
os.makedirs(os.path.join(out, "include"), exist_ok=True)
for i in range(n):
    guard = "#pragma once\n" if i % 7 else ""             # every 7th header is unguarded (included twice below)
    open(f"{out}/include/mod{i}.h", "w").write(f"{guard}#include <string>\n#include <vector>\nint f{i}(int x);\nstd::string name{i}(std::string s);\nint total{i}(std::vector<int> v);\n")
    body = [f'#include "mod{i}.h"', f'#include "mod{i-1}.h"' if i else "", f'#include "mod{i}.h"' if i % 7 == 0 else "", "#include <cstring>", "#include <iostream>"]
    prev = f"+ f{i-1}(x - 1)" if i else ""
    body.append(f'int f{i}(int x) {{ if (x <= 0) return {i}; return x * 2 {prev}; }}'.replace("\n", " "))
    body.append(f"std::string name{i}(std::string s) {{ return s + \"{i}\"; }}")
    body.append(f"int total{i}(std::vector<int> v) {{ int t = 0; for (size_t k = 0; k < v.size(); k++) t += v[k]; return t; }}")
    if i % 10 == 3:
        body.append(f"void log{i}() {{ char b[8]; strcpy(b, \"overflowing-name-{i}\"); std::cout << b << std::endl; }}")
    if i % 10 == 5:
        body.append(f"void spam{i}() {{ for (int k = 0; k < 3; k++) {{ std::cout << k << std::endl; }} }}")
    if i % 50 == 17:
        body.append(f"int broken{i}() {{ int a = 1\n    return a; }}")                 # missing semicolon
    open(f"{out}/src/mod{i}.cpp", "w").write("\n".join(l for l in body if l) + "\n")
calls = "\n".join(f"    sum += f{i}(3);" for i in range(0, n, 5))
decl = "\n".join(f'#include "mod{i}.h"' for i in range(0, n, 5))
open(f"{out}/src/main.cpp", "w").write(f"{decl}\n#include <iostream>\nint main() {{\n    long sum = 0;\n{calls}\n    std::cout << sum << \"\\n\";\n}}\n")
print(f"generated {n + 1} sources in {out}")
