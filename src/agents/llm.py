"""Optional LLM repair provider (OFF by default).

When enabled (--llm anthropic) the Repairer may ask a model for a corrected version of a file the rule-based
healer could not fix.  The model is treated as an UNTRUSTED proposer: its output is only kept if the
orchestrator's guardrails accept it (safety gate, sentinel indicators not increased, size of change bounded,
fewer compiler errors, whole project still links).  Privacy: enabling it sends the file's source text and its
compiler messages to the provider - nothing else is sent, and it never happens unless you pass --llm.
"""
import json
import os
import re
import urllib.request
import urllib.error
from typing import Callable, List, Optional

SYSTEM = ("You repair C++ compile errors. Make the SMALLEST possible change that fixes the listed errors. "
          "Do not add network, process, file-system, inline-assembly or dynamic-loading code. Do not rename "
          "public functions or change their signatures. Reply with the complete corrected file in ONE ```cpp "
          "fenced block and nothing else.")


class Provider:
    name = "none"

    def fix(self, rel: str, source: str, diagnostics: List[dict]) -> Optional[str]:   # pragma: no cover
        raise NotImplementedError


class CallableProvider(Provider):
    """wrap any function(rel, source, diagnostics) -> new source (used by tests and custom back-ends)"""
    name = "callable"

    def __init__(self, fn: Callable[[str, str, List[dict]], Optional[str]]):
        self.fn = fn

    def fix(self, rel, source, diagnostics):
        return self.fn(rel, source, diagnostics)


def extract_code(reply: str) -> Optional[str]:
    m = re.search(r"```(?:cpp|c\+\+|cc)?\s*\n(.*?)```", reply, re.S)
    return m.group(1) if m else None


class AnthropicProvider(Provider):
    name = "anthropic"

    def __init__(self, model: Optional[str] = None, api_key: Optional[str] = None, timeout: int = 90):
        self.model = model or os.environ.get("GSC_LLM_MODEL", "claude-sonnet-5-5")
        self.key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        self.timeout = timeout
        if not self.key:
            raise RuntimeError("--llm anthropic needs the ANTHROPIC_API_KEY environment variable")

    def fix(self, rel, source, diagnostics):
        errs = "\n".join(f"line {d.get('line')}: {d.get('message')}" for d in diagnostics[:12])
        body = {"model": self.model, "max_tokens": 8192, "system": SYSTEM,
                "messages": [{"role": "user",
                              "content": f"File: {rel}\n\nCompiler errors:\n{errs}\n\n```cpp\n{source}\n```"}]}
        req = urllib.request.Request("https://api.anthropic.com/v1/messages", data=json.dumps(body).encode(),
                                     headers={"x-api-key": self.key, "anthropic-version": "2023-06-01",
                                              "content-type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                data = json.load(r)
        except (urllib.error.URLError, TimeoutError, ValueError):
            return None
        text = "".join(b.get("text", "") for b in data.get("content", []) if b.get("type") == "text")
        return extract_code(text)


def make_provider(spec: Optional[str]) -> Optional[Provider]:
    if not spec or spec == "none":
        return None
    if spec == "anthropic":
        return AnthropicProvider()
    raise ValueError(f"unknown --llm provider {spec!r} (supported: anthropic)")
