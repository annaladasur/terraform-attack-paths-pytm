"""Canonical serialisation and hashing.

Determinism is a design property, not a hope: every artifact the pipeline writes
goes through ``dump_json`` (sorted keys, fixed separators, trailing newline) so two
runs over the same plan are byte-identical and can be compared with a hash.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any, Iterable

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256(data: str | bytes) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def digest(obj: Any, length: int = 12) -> str:
    """Short content hash for stable identifiers."""
    return sha256(canonical(obj))[:length]


def dump_json(obj: Any, path: str | Path) -> str:
    text = json.dumps(obj, sort_keys=True, indent=2, ensure_ascii=False) + "\n"
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(text, encoding="utf-8")
    return sha256(text)


def load_json(path: str | Path) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def write_text(path: str | Path, text: str) -> str:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(text, encoding="utf-8")
    return sha256(text)


def number(prefix: str, keys: Iterable[Any]) -> dict[str, str]:
    """Assign PREFIX-001.. identifiers in canonical sort order of their keys.

    The same set of keys always produces the same identifiers, regardless of the
    order in which the pipeline discovered them.
    """
    ordered = sorted({canonical(k) for k in keys})
    return {k: f"{prefix}-{i:03d}" for i, k in enumerate(ordered, start=1)}


_ADDR_INDEX = re.compile(r"\[(\"[^\"]*\"|\d+)\]")


def base_address(address: str) -> str:
    """``module.a.aws_s3_bucket.b["x"]`` -> ``module.a.aws_s3_bucket.b``."""
    return _ADDR_INDEX.sub("", address)


def glob_to_regex(pattern: str, case_insensitive: bool = False) -> re.Pattern[str]:
    """IAM-style glob: ``*`` matches any run, ``?`` matches one character."""
    out = []
    for ch in pattern:
        if ch == "*":
            out.append(".*")
        elif ch == "?":
            out.append(".")
        else:
            out.append(re.escape(ch))
    flags = re.IGNORECASE if case_insensitive else 0
    return re.compile("^" + "".join(out) + "$", flags | re.DOTALL)


def as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]
