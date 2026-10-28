"""The evidence ledger (Plane 4).

Every deterministic fact the pipeline establishes becomes a ledger record with a
stable identifier:

    TF-###     a Terraform resource instance (plan + source location)
    NET-###    a network rule (security group rule, listener, public IP setting)
    IAM-###    an IAM policy statement that grants, denies or trusts
    GRAPH-###  a typed relationship in the security graph
    SCAN-###   a finding reported by a baseline scanner
    PATH-###   an attack path found by the path engine
    CMT-###    a source comment (always ``trust: untrusted``)
    APP-###    an answer from the app team in threat-answers.yaml (``trust: attested``: declared, not proven)

Identifiers are assigned *after* collection, in canonical order of each record's
key, so the same plan always yields the same IDs. AI annotations may only cite IDs
that exist here; see ``tapm.ai.validator``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..util import canonical

KINDS = ("TF", "NET", "IAM", "GRAPH", "SCAN", "PATH", "CMT", "APP")


@dataclass
class Record:
    kind: str
    key: Any
    summary: str
    source: dict | None = None
    data: dict = field(default_factory=dict)
    refs: list[str] = field(default_factory=list)  # handles until finalize(), then IDs
    trust: str = "trusted"
    id: str | None = None

    @property
    def handle(self) -> str:
        return handle(self.kind, self.key)


def handle(kind: str, key: Any) -> str:
    return f"{kind}|{canonical(key)}"


class Ledger:
    def __init__(self) -> None:
        self._records: dict[str, Record] = {}
        self._final = False
        self.ids: dict[str, str] = {}

    def add(self, kind: str, key: Any, summary: str, *, source: dict | None = None,
            data: dict | None = None, refs: list[str] | None = None, trust: str = "trusted") -> str:
        assert kind in KINDS, kind
        assert not self._final, "ledger already finalized"
        h = handle(kind, key)
        rec = self._records.get(h)
        if rec is None:
            self._records[h] = Record(kind, key, summary, source, dict(data or {}), sorted(set(refs or [])), trust)
        else:
            rec.refs = sorted(set(rec.refs) | set(refs or []))
            if data:
                rec.data.update(data)
        return h

    def has(self, h: str) -> bool:
        return h in self._records

    def get(self, h: str) -> Record:
        return self._records[h]

    def finalize(self) -> dict[str, str]:
        for kind in KINDS:
            recs = sorted((r for r in self._records.values() if r.kind == kind), key=lambda r: canonical(r.key))
            for i, r in enumerate(recs, start=1):
                r.id = f"{kind}-{i:03d}"
                self.ids[r.handle] = r.id
        for r in self._records.values():
            r.refs = sorted({self.ids[x] for x in r.refs if x in self.ids})
        self._final = True
        return self.ids

    def append(self, kind: str, key: Any, summary: str, *, source: dict | None = None,
               data: dict | None = None, refs: list[str] | None = None, trust: str = "trusted") -> str:
        """Add a record after finalize(); it receives the next ID for its kind."""
        assert self._final, "use add() before finalize()"
        h = handle(kind, key)
        if h in self._records:
            return self._records[h].id
        n = sum(1 for r in self._records.values() if r.kind == kind) + 1
        rec = Record(kind, key, summary, source, dict(data or {}), sorted(set(refs or [])), trust, id=f"{kind}-{n:03d}")
        self._records[h] = rec
        self.ids[h] = rec.id
        return rec.id

    def id_of(self, h: str) -> str:
        return self.ids[h]

    def records(self) -> list[Record]:
        return sorted(self._records.values(), key=lambda r: (KINDS.index(r.kind), int(r.id.split("-")[1]) if r.id else 0))

    def by_id(self) -> dict[str, Record]:
        return {r.id: r for r in self._records.values() if r.id}

    def to_json(self) -> dict:
        return {
            "records": [
                {
                    "id": r.id,
                    "kind": r.kind,
                    "summary": r.summary,
                    "source": r.source,
                    "data": r.data,
                    "refs": r.refs,
                    "trust": r.trust,
                }
                for r in self.records()
            ]
        }
