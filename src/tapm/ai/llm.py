"""Provider-agnostic LLM layer for the annotation agents.

Control 3 (no tool access): every backend here sends a single request with a
system prompt, one user message (the evidence bundle) and a JSON schema for the
reply. No tools, no function calling, no network or shell capability is ever
offered to the model. Output is parsed and handed to the deterministic validator.

Backends: ``anthropic`` (default model: see AnthropicLLM; override with TAPM_ANTHROPIC_MODEL), ``openai``, ``ollama``,
``recorded`` (replay cassettes), ``simulated`` (deterministic templates, no model;
used offline and in CI, and always labelled as such), ``scripted`` (tests).
"""

from __future__ import annotations

import json
import os
import time
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from ..util import digest

PRICING = {k: v for k, v in json.loads((Path(__file__).parent / "pricing.json").read_text()).items() if not k.startswith("_")}


@dataclass
class LLMResult:
    text: str
    backend: str
    model: str | None
    input_tokens: int | None = None
    output_tokens: int | None = None
    latency_ms: int = 0
    stop_reason: str | None = None

    @property
    def cost_usd(self) -> float | None:
        price = PRICING.get(self.model or "")
        if not price or self.input_tokens is None or self.output_tokens is None:
            return 0.0 if self.backend in ("simulated", "scripted", "ollama") else None
        return round(self.input_tokens / 1e6 * price[0] + self.output_tokens / 1e6 * price[1], 6)


class AnthropicLLM:
    """Claude via the official SDK. Structured JSON output, refusal fallback on by default."""

    def __init__(self, model: str | None = None, effort: str = "medium"):
        import anthropic  # optional dependency: pip install '.[anthropic]'

        self.client = anthropic.Anthropic()
        self.model = model or os.environ.get("TAPM_ANTHROPIC_MODEL")
        if not self.model:
            raise RuntimeError("set --model or TAPM_ANTHROPIC_MODEL for the Anthropic backend")
        self.effort = effort
        self.name = f"anthropic:{self.model}"

    def complete(self, agent: str, system: str, user: str, schema: dict, context: Any = None) -> LLMResult:
        t0 = time.monotonic()
        resp = self.client.beta.messages.create(
            model=self.model,
            max_tokens=16000,
            betas=["server-side-fallback-2026-07-01"],
            fallbacks="default",
            system=system,
            messages=[{"role": "user", "content": user}],
            output_config={"effort": self.effort, "format": {"type": "json_schema", "schema": schema}},
        )
        ms = int((time.monotonic() - t0) * 1000)
        resp_model = getattr(resp, "model", None)
        if self.model:
            if not resp_model:
                raise RuntimeError(f"answering model is unspecified; differs from requested '{self.model}'")
            base_req = self.model.replace("-latest", "")
            if resp_model != self.model and not resp_model.startswith(base_req):
                raise RuntimeError(f"answering model '{resp_model}' differs from requested '{self.model}'")
        if resp.stop_reason == "refusal":
            text = json.dumps({"_refusal": True, "category": getattr(resp.stop_details, "category", None)})
        else:
            text = next((b.text for b in resp.content if b.type == "text"), "")
        return LLMResult(text, "anthropic", resp.model, resp.usage.input_tokens, resp.usage.output_tokens, ms, resp.stop_reason)


class OpenAILLM:
    def __init__(self, model: str | None = None):
        from openai import OpenAI  # optional dependency: pip install '.[openai]'

        self.model = model or os.environ.get("TAPM_OPENAI_MODEL")
        if not self.model:
            raise RuntimeError("set --model or TAPM_OPENAI_MODEL for the OpenAI backend")
        self.client = OpenAI()
        self.name = f"openai:{self.model}"

    def complete(self, agent: str, system: str, user: str, schema: dict, context: Any = None) -> LLMResult:
        t0 = time.monotonic()
        resp = self.client.chat.completions.create(
            model=self.model,
            messages=[{"role": "system", "content": system}, {"role": "user", "content": user}],
            response_format={"type": "json_schema", "json_schema": {"name": agent, "schema": schema, "strict": True}},
        )
        ms = int((time.monotonic() - t0) * 1000)
        resp_model = getattr(resp, "model", None)
        if self.model:
            if not resp_model:
                raise RuntimeError(f"answering model is unspecified; differs from requested '{self.model}'")
            base_req = self.model.replace("-latest", "")
            if resp_model != self.model and not resp_model.startswith(base_req):
                raise RuntimeError(f"answering model '{resp_model}' differs from requested '{self.model}'")
        u = resp.usage
        return LLMResult(resp.choices[0].message.content or "", "openai", self.model,
                         getattr(u, "prompt_tokens", None), getattr(u, "completion_tokens", None), ms,
                         resp.choices[0].finish_reason)


class OllamaLLM:
    def __init__(self, model: str | None = None, num_ctx: int | None = None, seed: int | None = None):
        self.model = model or os.environ.get("TAPM_OLLAMA_MODEL")
        if not self.model:
            raise RuntimeError("set --model or TAPM_OLLAMA_MODEL for the Ollama backend")
        self.host = os.environ.get("OLLAMA_HOST", "http://localhost:11434").rstrip("/")
        self.num_ctx = int(num_ctx) if num_ctx is not None else int(os.environ.get("TAPM_OLLAMA_NUM_CTX", "16384"))
        self.seed = int(seed) if seed is not None else int(os.environ.get("TAPM_OLLAMA_SEED", "42"))
        self.name = f"ollama:{self.model}"

    def complete(self, agent: str, system: str, user: str, schema: dict, context: Any = None) -> LLMResult:
        options = {"temperature": 0, "num_ctx": self.num_ctx, "seed": self.seed}
        body = json.dumps({"model": self.model, "stream": False, "format": schema, "options": options,
                           "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}]}).encode()
        t0 = time.monotonic()
        req = urllib.request.Request(f"{self.host}/api/chat", data=body, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=600) as r:
            data = json.loads(r.read().decode())
        ms = int((time.monotonic() - t0) * 1000)
        resp_model = data.get("model")
        if self.model:
            if not resp_model:
                raise RuntimeError(f"answering model is unspecified; differs from requested '{self.model}'")
            req_base = self.model.split(":")[0]
            resp_base = resp_model.split(":")[0]
            if resp_model != self.model and resp_base != req_base:
                raise RuntimeError(f"answering model '{resp_model}' differs from requested '{self.model}'")
        return LLMResult(data.get("message", {}).get("content", ""), "ollama", self.model,
                         data.get("prompt_eval_count"), data.get("eval_count"), ms, data.get("done_reason"))


class SimulatedLLM:
    """Deterministic, template-based stand-in. No model is called.

    Used for offline demos, CI and tests. Every annotation it produces is labelled
    ``backend: simulated``. The ``naive`` flag makes it *obey instructions found in
    its input*, a transparent stand-in for an injection-susceptible model used
    only by the UNSAFE side of the prompt-injection demo.
    """

    def __init__(self, naive: bool = False):
        self.naive = naive
        self.name = "simulated-naive" if naive else "simulated"
        self.model = None

    def complete(self, agent: str, system: str, user: str, schema: dict, context: Any = None) -> LLMResult:
        from .agents import simulate

        text = simulate(agent, context, naive=self.naive, raw_input=user)
        return LLMResult(text, self.name, None, None, None, 0, "end_turn")


class ScriptedLLM:
    """Returns pre-written outputs (used by the negative security tests)."""

    def __init__(self, outputs: dict[str, str | Callable[[Any], str]]):
        self.outputs = outputs
        self.name = "scripted"
        self.model = None

    def complete(self, agent: str, system: str, user: str, schema: dict, context: Any = None) -> LLMResult:
        out = self.outputs.get(agent)
        if out is None:
            from .agents import simulate

            text = simulate(agent, context)
        else:
            text = out(context) if callable(out) else out
        return LLMResult(text, "scripted", None, None, None, 0, "end_turn")


class CassetteLLM:
    """Record live responses (``inner`` given) or replay them (``inner`` None).

    With ``fallback`` set, a replay miss uses that backend instead of failing, and
    the annotation records which backend actually produced it.
    """

    def __init__(self, cassette_dir: str | Path, inner=None, fallback=None, prompt_version: str = "v1",
                 run_tag: str | None = None, model: str | None = None):
        self.dir = Path(cassette_dir) / "llm"
        self.inner = inner
        self.fallback = fallback
        self.prompt_version = prompt_version
        self.run_tag = run_tag  # separates repeated runs of the same input (variability experiments)
        self.name = f"recorded({inner.name})" if inner else ("recorded, fallback " + fallback.name if fallback else "recorded")
        self.model = getattr(inner, "model", None) or model

    def key(self, agent: str, context: Any, user: str) -> str:
        bh = context.get("bundle_hash") if isinstance(context, dict) else None
        parts = [agent, self.prompt_version, bh or digest(user, 24)]
        return digest(parts + [self.run_tag] if self.run_tag else parts, 24)

    def complete(self, agent: str, system: str, user: str, schema: dict, context: Any = None) -> LLMResult:
        path = self.dir / agent / f"{self.key(agent, context, user)}.json"
        if self.inner is None:
            if path.exists():
                d = json.loads(path.read_text())
                c_model = d.get("model")
                if self.model and c_model != self.model:
                    raise RuntimeError(f"answering model '{c_model or 'unspecified'}' in cassette differs from requested '{self.model}'")
                return LLMResult(d["text"], f"recorded:{d['backend']}", c_model, d.get("input_tokens"),
                                 d.get("output_tokens"), d.get("latency_ms", 0), d.get("stop_reason"))
            if self.fallback is not None:
                return self.fallback.complete(agent, system, user, schema, context)
            raise FileNotFoundError(f"no cassette for {agent} ({path.name}); record one with --llm <backend> --record")
        res = self.inner.complete(agent, system, user, schema, context)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"agent": agent, "backend": res.backend, "model": res.model, "text": res.text,
                                    "input_tokens": res.input_tokens, "output_tokens": res.output_tokens,
                                    "latency_ms": res.latency_ms, "stop_reason": res.stop_reason,
                                    "prompt_version": self.prompt_version, "recorded_at": time.strftime("%Y-%m-%d")},
                                   indent=2, sort_keys=True))
        return res


def make_llm(kind: str, model: str | None, cassette_dir: str | Path, record: bool = False, prompt_version: str = "v1",
             fallback: Any = None, num_ctx: int | None = None, seed: int | None = None):
    if kind == "simulated":
        return SimulatedLLM()
    if kind == "recorded":
        return CassetteLLM(cassette_dir, fallback=fallback, prompt_version=prompt_version, model=model)
    if kind == "ollama":
        live = OllamaLLM(model, num_ctx=num_ctx, seed=seed)
    elif kind in ("anthropic", "openai"):
        live = {"anthropic": AnthropicLLM, "openai": OpenAILLM}[kind](model)
    else:
        raise ValueError(f"unknown or unsupported LLM backend: '{kind}'")
    return CassetteLLM(cassette_dir, inner=live, prompt_version=prompt_version) if record else live
