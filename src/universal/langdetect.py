"""Language / file-kind detection: extension -> shebang -> content sniffing.  Binary & executable magic numbers."""
from __future__ import annotations

import os
import re
from typing import Optional

EXT = {
    ".py": "python", ".pyw": "python", ".pyi": "python",
    ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript", ".jsx": "javascript",
    ".ts": "typescript", ".tsx": "typescript",
    ".c": "c", ".h": "cpp",
    ".cpp": "cpp", ".cc": "cpp", ".cxx": "cpp", ".c++": "cpp", ".hpp": "cpp", ".hh": "cpp", ".hxx": "cpp",
    ".java": "java", ".kt": "kotlin", ".kts": "kotlin", ".scala": "scala",
    ".go": "go", ".rs": "rust", ".php": "php", ".phtml": "php", ".rb": "ruby",
    ".cs": "csharp", ".swift": "swift",
    ".sh": "shell", ".bash": "shell", ".zsh": "shell", ".ksh": "shell",
    ".ps1": "powershell", ".psm1": "powershell", ".bat": "batch", ".cmd": "batch",
    ".sql": "sql", ".yml": "yaml", ".yaml": "yaml", ".json": "json", ".toml": "toml", ".ini": "ini",
    ".env": "env", ".tf": "terraform", ".dockerfile": "dockerfile",
    ".html": "html", ".htm": "html", ".vue": "javascript",
}
NAMES = {"dockerfile": "dockerfile", "makefile": "makefile", "jenkinsfile": "groovy", ".env": "env",
         "requirements.txt": "requirements", "package.json": "json", "pom.xml": "xml", "build.gradle": "groovy"}
SHEBANG = (("python", "python"), ("node", "javascript"), ("bash", "shell"), ("sh", "shell"), ("zsh", "shell"),
           ("ruby", "ruby"), ("php", "php"), ("perl", "perl"))

# languages that have real code analyzers (rest are config/data: secrets + config rules only)
CODE_LANGS = {"python", "javascript", "typescript", "c", "cpp", "java", "kotlin", "scala", "go", "rust", "php",
              "ruby", "csharp", "swift", "shell", "powershell", "batch", "perl", "groovy"}

MAGIC = ((b"\x7fELF", "ELF executable"), (b"MZ", "Windows PE executable"),
         (b"\xca\xfe\xba\xbe", "Mach-O/Java class"), (b"\xcf\xfa\xed\xfe", "Mach-O executable"),
         (b"\xfe\xed\xfa\xce", "Mach-O executable"), (b"#!", None))
BINARY_EXT = {".png", ".jpg", ".jpeg", ".gif", ".ico", ".webp", ".pdf", ".zip", ".gz", ".tar", ".woff", ".woff2",
              ".ttf", ".otf", ".npz", ".pyc", ".class", ".jar", ".so", ".dll", ".exe", ".o", ".a", ".bin", ".mp3",
              ".mp4", ".svg"}
VENDOR_DIRS = {"_cd1_report", "node_modules", ".git", ".svn", ".hg", "__pycache__", "venv", ".venv", "env", "dist", "build",
               "target", "vendor", ".idea", ".vscode", "__MACOSX", ".tox", ".mypy_cache", ".pytest_cache",
               "site-packages", "CMakeFiles"}
TEST_RE = re.compile(r"(^|/)(tests?|__tests__|spec|specs|examples?|samples?|demo|fixtures?|benchmarks?|docs?)(/|$)"
                     r"|(^|/)(test_[^/]*|[^/]*_test\.[a-z]+|[^/]*\.(test|spec)\.[a-z]+|conftest\.py)$", re.I)


def executable_kind(head: bytes) -> Optional[str]:
    for magic, label in MAGIC:
        if label and head.startswith(magic):
            return label
    return None


def is_binary(head: bytes) -> bool:
    if b"\x00" in head:
        return True
    if not head:
        return False
    text_like = sum(1 for b in head if b in (9, 10, 13) or 32 <= b < 127 or b >= 128)
    return text_like / len(head) < 0.90


def detect(rel: str, head: bytes) -> str:
    """Return a language/kind string, or "" when unknown."""
    base = os.path.basename(rel)
    low = base.lower()
    if low in NAMES:
        return NAMES[low]
    if low.startswith("dockerfile"):
        return "dockerfile"
    if low.startswith(".env"):
        return "env"
    ext = os.path.splitext(low)[1]
    if ext in EXT:
        return EXT[ext]
    if head.startswith(b"#!"):
        first = head.split(b"\n", 1)[0].decode("utf-8", "ignore").lower()
        for key, lang in SHEBANG:
            if re.search(r"[/ ]" + key + r"\d*(\s|$)", first):
                return lang
    sample = head[:2048].decode("utf-8", "ignore")
    if re.search(r"^\s*(import|from)\s+\w+|^\s*def\s+\w+\(.*\):", sample, re.M):
        return "python" if ext in ("", ".txt") else ""
    return ""
