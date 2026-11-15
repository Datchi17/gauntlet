#!/usr/bin/env python3
"""
LLM providers for the Gauntlet benchmark (M4). Stdlib only (urllib).

  - dry-run : no model; returns "" (lets the harness run in CI without an LLM).
  - ollama  : local model via the Ollama HTTP API. Nothing leaves the box.
  - replay  : returns a saved response from a file (deterministic re-scoring).

Frontier models (Claude/OpenAI) plug in the same way behind an API key; left as a
one-method subclass to keep the default fully local.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from pathlib import Path


def _post_json(req: urllib.request.Request, timeout: int) -> dict:
    """Open a request, returning parsed JSON — and on an HTTP error, surface the
    server's response body (APIs explain *why* there, not in the status line)."""
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", "replace")[:1000]
        raise SystemExit(f"HTTP {e.code} from {req.full_url}\n{body}") from None


class DryRun:
    name = "dry-run"

    def generate(self, prompt: str) -> str:
        return ""


class Replay:
    """Return a canned response (for tests / re-scoring a saved run)."""
    name = "replay"

    def __init__(self, text: str):
        self._text = text

    def generate(self, prompt: str) -> str:
        return self._text


class Ollama:
    name = "ollama"

    def __init__(self, url: str | None = None, model: str | None = None):
        self.url = (url or os.environ.get("GAUNTLET_OLLAMA_URL", "http://localhost:11434")).rstrip("/")
        self.model = model or os.environ.get("GAUNTLET_OLLAMA_MODEL", "qwen2.5-coder:3b")

    def generate(self, prompt: str) -> str:
        body = json.dumps({
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "options": {"temperature": 0.2},
        }).encode()
        req = urllib.request.Request(
            self.url + "/api/generate", data=body,
            headers={"Content-Type": "application/json"},
        )
        return _post_json(req, timeout=300)["response"]


class OpenAICompatible:
    """Any OpenAI-compatible chat endpoint — works with free, no-card providers:
      Groq:   GAUNTLET_API_BASE=https://api.groq.com/openai/v1              MODEL=llama-3.3-70b-versatile
      Gemini: GAUNTLET_API_BASE=https://generativelanguage.googleapis.com/v1beta/openai  MODEL=gemini-2.5-flash
    Set GAUNTLET_API_BASE, GAUNTLET_API_MODEL, GAUNTLET_API_KEY (your own free key)."""
    name = "api"

    def __init__(self):
        self.base = os.environ.get("GAUNTLET_API_BASE", "").rstrip("/")
        self.model = os.environ.get("GAUNTLET_API_MODEL", "")
        self.key = os.environ.get("GAUNTLET_API_KEY", "")
        if not (self.base and self.model and self.key):
            raise SystemExit("set GAUNTLET_API_BASE, GAUNTLET_API_MODEL and GAUNTLET_API_KEY "
                             "(see ai/README.md for free Groq/Gemini setup)")

    def generate(self, prompt: str) -> str:
        body = json.dumps({
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.2,
        }).encode()
        req = urllib.request.Request(
            self.base + "/chat/completions", data=body,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.key}",
                # Some providers (Groq) front their API with Cloudflare, which bans
                # the default "Python-urllib/x" signature with a 403 (error 1010).
                # A generic client UA passes; we send no personal/identifying info.
                "User-Agent": "gauntlet-bench/1.0",
            },
        )
        return _post_json(req, timeout=120)["choices"][0]["message"]["content"]


def get(provider: str, **kw):
    if provider == "dry-run":
        return DryRun()
    if provider == "ollama":
        return Ollama(**{k: v for k, v in kw.items() if k in ("url", "model")})
    if provider == "api":
        return OpenAICompatible()
    if provider == "replay":
        return Replay(Path(kw["file"]).read_text())
    raise SystemExit(f"unknown provider: {provider}")
