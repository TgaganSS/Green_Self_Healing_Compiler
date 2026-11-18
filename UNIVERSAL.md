# Universal multi-agent audit (v2)

Give it **one file, a folder, a `.zip` or a `.tar.gz`** in any mix of languages. You get back a **secured copy** (zip / folder / file)
plus a report. Your upload is never modified and **nothing in it is ever executed**.

```bash
./cppcheck project.zip                    # auto-routes to the universal engine when non-C++ code is present
python3 src/audit.py project.zip          # -> project.secured.zip   (reports in _cd1_report/ inside)
python3 src/audit.py app.py               # -> app.secured.py + app.secured.REPORT.md/.json/.sarif/.patch
python3 src/audit.py repo/ --apply-proposed          # also apply verified behaviour-changing fixes
python3 src/audit.py repo.zip --report-only          # analyse only
python3 src/audit.py repo.zip --fail-on high         # CI gate (exit 2)
python3 src/audit.py repo.zip --llm anthropic        # optional LLM proposals (see below)
```

## The agents

| Agent | Job |
|---|---|
| **Intake** | Reuses the zip-slip / zip-bomb / symlink / size guards of `project.py`; inventories files, detects language (extension, shebang, content), spots binaries/executables, marks tests and network-facing files |
| **Malware** | Behaviour indicators (decode→exec, reverse shells, droppers, miners, persistence, credential theft + exfiltration, wipers, ransomware, install-hooks, injection) + entropy/compressibility features, combined by noisy-OR with co-occurrence rules. ClamAV used as a 2nd opinion if installed. Malicious files are **quarantined** (removed from the output); a `package.json` with only a bad install hook is surgically cleaned instead |
| **Analyst** (parallel) | Per-language: real parsers (`compile`/`ast`, `node --check`, `gcc -fsyntax-only`, `bash -n`, JSON, YAML) + 112 rules + 32 malware indicators + 12 secret patterns (Python, JS/TS, C, Java/Kotlin/Scala, Go, Rust, PHP, Ruby, C#, shell, PowerShell, Docker, K8s/CI YAML, Terraform, requirements/package.json) + AST checks + secrets. **Syntax errors are self-healed**, each repair verified by the same parser |
| **C++ agents** | C++ files go through the full verified agentic pipeline (Sentinel, Repairer, Integrator, Auditor, Optimizer, independent Verifier, and with `--run` the sandboxed Tester). Every change is rebuilt, relinked and re-audited from scratch; see the README "Agentic mode" section |
| **Risk** | 0-100 per finding (severity × confidence × context), noisy-OR per file/project, grade A-F, *fix-first* ranking |
| **Fixer** | Applies **auto-tier** fixes (strictly safer), iterated to a fixpoint so overlapping fixes converge |
| **Proposals** | Behaviour-changing fixes (e.g. `md5→sha256`, `var→let`, secret→env var) are verified but **not applied** → `proposed.patch` |
| **LLM** (optional) | Proposes fixes for High/Critical findings that have no mechanical fix |
| **Verifier** | The gate every change must pass (below) |
| **Integrator** | Cross-file import / API checks, rollback on breakage, re-scan of the result ("risk after"), writes output + reports + SHA-256 manifest |

### The verification gate (every change, rule-based or LLM)
1. file still parses / compiles (or is no worse if it was already broken)
2. each fixed rule has fewer hits; **no rule has more** (nothing new introduced)
3. malware score did not rise (LLM text must score < 0.30)
4. public API of the module unchanged; names other files import from it still exist
5. LLM edits limited to 40 changed lines
Then, after all fixes: Python/JS local imports still resolve, else the offending file is rolled back.

## LLM mode (optional, off by default)
`--llm anthropic` (needs `ANTHROPIC_API_KEY`), `--llm openai` (any OpenAI-compatible endpoint incl. local Ollama via `CD1_LLM_BASE_URL`), `--llm auto`.
Model: `CD1_LLM_MODEL`. Code only leaves the machine with this flag; **secrets are redacted** first; code is fenced as untrusted data
(prompt-injection defence); the reply must be strict JSON; rejections are fed back (3 tries, budget `--llm-budget`).
LLM fixes go to `proposed.patch` unless you also pass `--apply-llm`; either way they must pass the same gate.

## Outputs (`_cd1_report/`)
`REPORT.md` (human) · `report.json` · `report.sarif` (GitHub code-scanning) · `changes.patch` (applied) · `proposed.patch` (needs review) ·
`QUARANTINE.md` · `trace.jsonl` (what each agent did) · `MANIFEST.sha256`. Credentials are redacted in all of them.

## Honest limits
- Non-C++ code is never executed (static analysis only). C++ is executed only with `--run`, in a sandbox with no network and a private filesystem root, and only when the Sentinel verdict is CLEAN.
- Static analysis only; logic bugs and runtime behaviour are out of reach. Run your own tests on the output.
- Java/Go/Rust/PHP/Ruby/C#: pattern rules + bracket balance (no parser invoked). Their fixes are limited accordingly.
- Malware detection is **heuristic triage**, not antivirus (weights are expert priors, evadable by a determined author).
- No offline CVE database: run `pip-audit` / `npm audit` / `osv-scanner` on the output.
- Python undefined-name and type errors are not detected (use `ruff`/`mypy`).
- The LLM path was verified with a scripted mock model (retry, rejection, injection, redaction, budget), not a live API.
- The only trained ML model remains the original C++ diagnostic classifier. Risk scoring and malware weights are transparent formulas, not learned.

## Tests
`python3 tests/test_universal.py` (35), `tests/test_merged.py` (4), `tests/test_review3.py` (11), `tests/test_agents.py` (35) plus the original three suites (80) = 165 tests. Includes false-positive controls, deliberately bad fixes that must be rejected,
malicious LLM replies, zip-slip/bomb, CRLF + non-UTF-8 fidelity, idempotence (re-auditing the output changes nothing), and 250-file scale.

## Merged edition
This edition combines the multi-language layer with the verified C++ agentic pipeline. The C safety gate (include confinement incl. digraph/macro includes, spawn primitives such as `wordexp`/`fexecve`) now also guards the C syntax check, and the C++ healer uses the compiler's exact error column for one-line bodies such as `for (...) { call(x)`.

## Second independent review (merged edition)
A fresh reviewer attacked the merged tree. All high/medium findings were fixed and have regression tests (`tests/test_review3.py`):
- include gate bypass by line splices (`#in\<newline>clude`) and `__has_include("/etc/passwd")` (now blocked; also in the C check);
- malicious C++ was reported but still shipped: now quarantined (the C++ Sentinel judges only the C++ part, so scripts cannot inflate its score);
- malware heuristics widened (reverse/bind shells, decode-then-exec through a variable, web shells, PowerShell download-and-run, wipers, ransomware loop, credential stealers, curl|sh) and hardened against padding / `tests/` path discounts; measured on 20,000 clean files from system Python, Node, Go and Rust trees: 1 false "malicious" (a test file that is only "suspicious" under the real pipeline's test-path rule);
- report injection through file names (newlines, ANSI, bidi, markdown links) neutralised;
- behaviour-changing Python rewrites (`== None`, bare `except`) are now proposals, not automatic fixes;
- non-UTF-8 files no longer stop the analysis; UTF-8 BOM Python is not a syntax error;
- an LLM-suggested fix that adds network, process, environment or credential-file access is rejected by the verifier;
- archive name conflicts give a clean error; an existing default output folder is never deleted.
