"""Decision layer: *how* AI is allowed to participate, never *what* is true.

Jev (TypeSafe AI) returns typed decisions (choice / score / noul) instead of text.
Here it decides routing, evidence sufficiency and escalation for the agent harness.
It is never asked whether a permission exists, whether two resources connect, or
whether a path exists: those answers come from the deterministic graph.

Backends
--------
``local``     Deterministic rules over bundle features. Same answer shapes as Jev,
              probabilities are rule outputs (1.0 / 0.0), *not* calibrated.
              This is the offline default and is labelled as a stand-in.
``typesafe``  TypeSafe Jev over HTTPS: ``POST {TYPESAFE_BASE_URL}/v1/systemone``
              with ``Authorization: Bearer $TYPESAFE_API_KEY``. Request/response
              shapes follow the official SDK's schema (typesafe-sdk 0.7.2).
``recorded``  Replays answers captured from a live run (``cassettes/jev``).
"""

from __future__ import annotations

import json
import os
import time
import urllib.request
from pathlib import Path
from typing import Any

from ..util import digest
from .agents import ROSTER

AGENTS = ROSTER


def questions_for_path() -> dict[str, dict]:
    """The typed questions asked before any agent runs (Plan §6, decisions 1-3)."""
    return {
        "route": {
            "type": "choice",
            "instructions": "Choose how AI may participate for this deterministic attack path. "
                            "Do not judge whether the path is real; it was established by code.",
            "criteria": {
                "NARRATE_PATH": "Evidence is complete; a plain-language narrative of the existing path would help a developer.",
                "EXPLAIN": "A short explanation of the underlying findings is enough.",
                "HUMAN_REVIEW": "Evidence is conditional or incomplete; a human should read it before any AI text.",
                "NO_AI": "Low priority or self-explanatory; AI adds nothing.",
            },
        },
        "evidence_sufficiency": {
            "type": "choice",
            "instructions": "Is there enough deterministic evidence in the bundle for an evidence-bound annotation?",
            "criteria": {"YES": "Every hop cites NET/IAM/TF evidence with source locations.",
                         "REVIEW": "Some hops rest on IAM Conditions the pipeline does not evaluate.",
                         "NO": "Hops lack source-located evidence."},
        },
        "want_remediation": {"type": "noul", "instructions": "Would remediation guidance for this path be useful?",
                             "criteria": {"true": "Deterministic what-if shows a change that breaks or downgrades the path.",
                                          "false": "No actionable change."}},
        "want_framework_mapping": {"type": "noul", "instructions": "Would mapping this path to CWE / ATT&CK / NIST help triage?",
                                   "criteria": {"true": "The path has recognisable weakness classes.", "false": "Not useful."}},
    }


def question_escalation() -> dict[str, dict]:
    """Decision 4: after validation and adversarial review, may the annotation publish without a human?"""
    return {
        "publish_without_human": {
            "type": "noul",
            "instructions": "Given the validator result and the adversarial reviewer's issues, is this annotation safe to "
                            "publish in a PR comment without a human reading it first?",
            "criteria": {"true": "Validator passed and the reviewer found no substantive issue.",
                         "false": "Any doubt: route to human review."},
        }
    }


class LocalJev:
    name = "local-rules (Jev stand-in, not calibrated)"

    def decide(self, state: dict, questions: dict[str, dict]) -> dict[str, dict]:
        out: dict[str, dict] = {}
        for q, spec in questions.items():
            out[q] = getattr(self, f"_{q}")(state, spec)
        return out

    @staticmethod
    def _choice(label: str, options) -> dict:
        probs = {k: (1.0 if k == label else 0.0) for k in options}
        return {"type": "choice", "choice": label, "confidence": 1.0, "probabilities": probs}

    # Symbolic policy recovery is deterministic (and tested), so it does not force review on its own.
    # Unevaluated IAM Conditions and hops without source-located evidence do.
    def _route(self, s, spec):
        if s.get("priority") == "low":
            label = "NO_AI"
        elif s.get("conditional") or s.get("hops_without_source", 0):
            label = "HUMAN_REVIEW"
        else:
            label = "NARRATE_PATH"
        return self._choice(label, spec["criteria"])

    def _evidence_sufficiency(self, s, spec):
        if s.get("hops_without_source", 0):
            label = "NO"
        elif s.get("conditional"):
            label = "REVIEW"
        else:
            label = "YES"
        return self._choice(label, spec["criteria"])

    def _want_remediation(self, s, spec):
        return {"type": "noul", "noul": 1.0 if s.get("remedies_breaking", 0) or s.get("remedies_downgrading", 0) else 0.0}

    def _want_framework_mapping(self, s, spec):
        return {"type": "noul", "noul": 1.0 if s.get("priority") in ("high", "medium") else 0.0}

    def _publish_without_human(self, s, spec):
        ok = s.get("validator_accepted") and not s.get("reviewer_issues")
        return {"type": "noul", "noul": 1.0 if ok else 0.0}


class TypeSafeJev:
    def __init__(self, model: str | None = None, base_url: str | None = None, api_key: str | None = None, timeout: float = 30.0):
        self.model = model or os.environ.get("TYPESAFE_DEFAULT_MODEL", "jev-latest")
        self.base_url = (base_url or os.environ.get("TYPESAFE_BASE_URL", "https://api.typesafe.ai")).rstrip("/")
        self.api_key = api_key or os.environ.get("TYPESAFE_API_KEY")
        self.timeout = timeout
        self.name = f"typesafe:{self.model}"
        if not self.api_key:
            raise RuntimeError("TYPESAFE_API_KEY is not set (use --jev local for the offline stand-in)")

    def decide(self, state: dict, questions: dict[str, dict]) -> dict[str, dict]:
        body = json.dumps({"model": self.model, "state": state, "questions": questions}).encode()
        req = urllib.request.Request(f"{self.base_url}/v1/systemone", data=body, method="POST",
                                     headers={"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=self.timeout) as r:
            data = json.loads(r.read().decode())
        answers = data.get("answers") or {}
        missing = set(questions) - set(answers)
        if missing:
            raise RuntimeError(f"Jev response missing answers for {sorted(missing)}")
        self.last_usage = data.get("usage")
        return answers


class RecordingJev:
    """Wraps a live backend and records, or replays recorded answers."""

    def __init__(self, cassette_dir: str | Path, inner=None):
        self.dir = Path(cassette_dir) / "jev"
        self.inner = inner
        self.name = f"recorded({inner.name})" if inner else "recorded"

    def _key(self, state, questions) -> str:
        return digest([state, questions], 24)

    def decide(self, state: dict, questions: dict[str, dict]) -> dict[str, dict]:
        path = self.dir / f"{self._key(state, questions)}.json"
        if self.inner is None:
            if not path.exists():
                raise FileNotFoundError(f"no recorded Jev answer for this state ({path.name}); record with --jev typesafe --record")
            return json.loads(path.read_text())["answers"]
        answers = self.inner.decide(state, questions)
        self.dir.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"backend": self.inner.name, "recorded_at": time.strftime("%Y-%m-%d"),
                                    "state": state, "questions": questions, "answers": answers}, indent=2, sort_keys=True))
        return answers


def make_jev(kind: str, cassette_dir: str | Path, record: bool = False):
    if kind == "local":
        return LocalJev()
    if kind == "typesafe":
        live = TypeSafeJev()
        return RecordingJev(cassette_dir, live) if record else live
    if kind == "recorded":
        return RecordingJev(cassette_dir)
    raise ValueError(kind)


def path_state(bundle: dict) -> dict:
    """Features Jev sees: counts and flags derived from the bundle, no raw configuration."""
    subj = bundle["subject"]
    ev = bundle["evidence"]
    graph = {e["id"]: e for e in ev if e["kind"] == "GRAPH"}
    hops_without_source = 0
    for h in subj["hops"]:
        g = graph.get(h["edge"])
        cited = [e for e in ev if e["kind"] in ("NET", "IAM") and e.get("source")]
        if not g or not cited:
            hops_without_source += 1
    return {
        "subject": subj["id"],
        "priority": subj["priority"],
        "status": subj["status"],
        "preconditions": [p["id"] for p in subj["preconditions"]],
        "hops": len(subj["hops"]),
        "hops_without_source": hops_without_source,
        "conditional": any(e["data"].get("conditional") for e in graph.values()),
        "symbolic": any(e["kind"] == "IAM" and str(e["data"].get("provenance", "")).startswith("symbolic") for e in ev),
        "scanner_findings_on_path": sum(1 for e in ev if e["kind"] == "SCAN"),
        "remedies_breaking": sum(1 for r in bundle.get("deterministic_remediation", []) if r["effect"] == "breaks_path"),
        "remedies_downgrading": sum(1 for r in bundle.get("deterministic_remediation", []) if r["effect"] == "downgrades_path"),
        "target_sensitivity": subj["target_sensitivity"],
    }
