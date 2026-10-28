"""Persistent disk cache for LLM results (Plane 7 / W0.3).

The cache key is bundle_hash + prompt_version + model + agent.
When a bundle has already been evaluated with a given model and prompt version,
subsequent requests hit the cache and make zero model calls.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any

from .. import PROMPT_VERSION
from ..util import PROJECT_ROOT, digest
from .llm import LLMResult


class AICache:
    """Persistent on-disk cache for AI agent completions."""

    def __init__(self, cache_dir: str | Path | None = None, enabled: bool = True):
        self.cache_dir = Path(cache_dir or os.environ.get("TAPM_AI_CACHE_DIR", PROJECT_ROOT / ".cache" / "ai"))
        self.enabled = enabled
        self.hits = 0
        self.misses = 0

    def key(self, bundle_hash: str, prompt_version: str, model: str | None, agent: str) -> str:
        parts = [bundle_hash, prompt_version, model or "none", agent]
        return digest(parts, 24)

    def get(self, bundle_hash: str, prompt_version: str, model: str | None, agent: str) -> LLMResult | None:
        if not self.enabled:
            return None
        k = self.key(bundle_hash, prompt_version, model, agent)
        p = self.cache_dir / f"{k}.json"
        if not p.exists():
            self.misses += 1
            return None
        try:
            doc = json.loads(p.read_text(encoding="utf-8"))
            r_doc = doc.get("result", {})
            self.hits += 1
            res = LLMResult(
                text=r_doc["text"],
                backend=r_doc.get("backend", "cached"),
                model=r_doc.get("model", model),
                input_tokens=r_doc.get("input_tokens"),
                output_tokens=r_doc.get("output_tokens"),
                latency_ms=0,
                stop_reason=r_doc.get("stop_reason"),
            )
            setattr(res, "_from_cache", True)
            return res
        except Exception:
            self.misses += 1
            return None

    def put(self, bundle_hash: str, prompt_version: str, model: str | None, agent: str, result: LLMResult) -> None:
        if not self.enabled:
            return
        k = self.key(bundle_hash, prompt_version, model, agent)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        p = self.cache_dir / f"{k}.json"
        doc = {
            "key": k,
            "bundle_hash": bundle_hash,
            "prompt_version": prompt_version,
            "model": model,
            "agent": agent,
            "result": {
                "text": result.text,
                "backend": result.backend,
                "model": result.model,
                "input_tokens": result.input_tokens,
                "output_tokens": result.output_tokens,
                "latency_ms": result.latency_ms,
                "stop_reason": result.stop_reason,
            },
            "cached_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        p.write_text(json.dumps(doc, indent=2, sort_keys=True), encoding="utf-8")

    def clear(self) -> int:
        count = 0
        if self.cache_dir.exists():
            for f in self.cache_dir.glob("*.json"):
                f.unlink()
                count += 1
        return count

    @property
    def size(self) -> int:
        if not self.cache_dir.exists():
            return 0
        return len(list(self.cache_dir.glob("*.json")))


class CachedLLM:
    """Wraps an LLM instance with an AICache.

    Intercepts calls where bundle_hash is present; if cached, returns the
    cached result without invoking the inner LLM.
    """

    def __init__(self, inner: Any, cache: AICache, prompt_version: str = PROMPT_VERSION):
        self.inner = inner
        self.cache = cache
        self.prompt_version = prompt_version
        self.name = inner.name if hasattr(inner, "name") else "cached"
        self.model = getattr(inner, "model", None)
        self.model_calls = 0
        self.cache_hits = 0

    def complete(self, agent: str, system: str, user: str, schema: dict, context: Any = None) -> LLMResult:
        bh = None
        if isinstance(context, dict):
            bh = context.get("bundle_hash")
            if not bh and "bundle" in context and isinstance(context["bundle"], dict):
                bh = context["bundle"].get("bundle_hash")
            ann = context.get("annotation")
            if ann:
                bh = f"{bh}:{digest(ann, 12)}"

        if bh and self.cache.enabled:
            cached = self.cache.get(bh, self.prompt_version, self.model, agent)
            if cached is not None:
                self.cache_hits += 1
                return cached

        self.model_calls += 1
        res = self.inner.complete(agent, system, user, schema, context)
        setattr(res, "_from_cache", False)

        if bh and self.cache.enabled:
            self.cache.put(bh, self.prompt_version, self.model, agent, res)

        return res
