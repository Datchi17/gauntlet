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
import urllib.request
from pathlib import Path


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
        with urllib.request.urlopen(req, timeout=300) as r:
            return json.loads(r.read())["response"]


def get(provider: str, **kw):
    if provider == "dry-run":
        return DryRun()
    if provider == "ollama":
        return Ollama(**{k: v for k, v in kw.items() if k in ("url", "model")})
    if provider == "replay":
        return Replay(Path(kw["file"]).read_text())
    raise SystemExit(f"unknown provider: {provider}")
