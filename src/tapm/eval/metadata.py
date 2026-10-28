"""Evaluation metadata collection: tool versions, git SHAs, command line, tag, gold hashes."""

from __future__ import annotations

import hashlib
import subprocess
import sys
from pathlib import Path
from typing import Any

from ..util import PROJECT_ROOT


def get_eval_tool_versions() -> dict[str, str]:
    from ..scanners.run import PINNED
    from ..terraform.offline_plan import PINNED_TERRAFORM

    return {
        "terraform": PINNED_TERRAFORM,
        "checkov": PINNED.get("checkov", "3.3.20"),
        "tfsec": PINNED.get("tfsec", "v1.28.14"),
        "trivy": PINNED.get("trivy", "0.74.0"),
    }


def get_eval_git_shas(
    gold_path: Path | None = None,
    gold_files: list[Path] | None = None,
) -> dict[str, Any]:
    code_sha = "unknown"
    gold_sha = "unknown"
    gold_files_map: dict[str, str] = {}

    try:
        proc = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            timeout=10,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            code_sha = proc.stdout.strip()
    except Exception:
        pass

    resolved_files: list[Path] = []
    if gold_files:
        resolved_files = [Path(f) for f in gold_files if Path(f).exists()]
    elif gold_path and Path(gold_path).exists():
        gp = Path(gold_path)
        if gp.is_file():
            resolved_files = [gp]
        elif (gp / "gold").is_dir():
            resolved_files = sorted((gp / "gold").glob("*.yaml"))
        elif gp.is_dir():
            resolved_files = sorted(gp.glob("*.yaml"))

    for f in resolved_files:
        try:
            rel = f.resolve().relative_to(PROJECT_ROOT.resolve())
            rel_str = str(rel)
        except ValueError:
            rel_str = str(f)
        try:
            data = f.read_bytes()
            gold_files_map[rel_str] = hashlib.sha256(data).hexdigest()
        except Exception:
            pass

    if resolved_files:
        try:
            proc = subprocess.run(
                ["git", "log", "-1", "--format=%H", "--", *(str(f) for f in resolved_files)],
                cwd=PROJECT_ROOT,
                capture_output=True,
                text=True,
                timeout=10,
            )
            if proc.returncode == 0 and proc.stdout.strip():
                gold_sha = proc.stdout.strip()
            else:
                gold_sha = code_sha
        except Exception:
            gold_sha = code_sha
    elif gold_path and Path(gold_path).exists():
        try:
            proc = subprocess.run(
                ["git", "log", "-1", "--format=%H", "--", str(gold_path)],
                cwd=PROJECT_ROOT,
                capture_output=True,
                text=True,
                timeout=10,
            )
            if proc.returncode == 0 and proc.stdout.strip():
                gold_sha = proc.stdout.strip()
            else:
                gold_sha = code_sha
        except Exception:
            gold_sha = code_sha
    else:
        gold_sha = code_sha

    res: dict[str, Any] = {
        "code": code_sha,
        "gold": gold_sha,
        "gold_commit": gold_sha,
    }
    if gold_files_map:
        res["gold_files"] = gold_files_map
    return res


def get_eval_metadata(
    gold_path: Path | None = None,
    tag: str | None = None,
    command: str | None = None,
    gold_files: list[Path] | None = None,
) -> dict[str, Any]:
    cmd_str = command or " ".join(sys.argv)
    shas = get_eval_git_shas(gold_path=gold_path, gold_files=gold_files)
    meta: dict[str, Any] = {
        "command": cmd_str,
        "tool_versions": get_eval_tool_versions(),
        "git_sha": shas,
    }
    if "gold_commit" in shas:
        meta["gold_commit"] = shas["gold_commit"]
    if "gold_files" in shas:
        meta["gold_files"] = shas["gold_files"]
    if tag is not None:
        meta["tag"] = tag
    return meta
