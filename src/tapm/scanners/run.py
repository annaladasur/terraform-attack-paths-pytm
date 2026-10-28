"""Run the pinned baseline scanners against a Terraform directory.

Each tool writes its native JSON next to a ``versions.json`` so baselines can be
replayed offline and audited later. A missing tool is recorded as missing; the
pipeline then falls back to the saved baseline, never to an invented one.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from ..util import PROJECT_ROOT, dump_json

PINNED = {"checkov": "3.3.20", "tfsec": "v1.28.14", "trivy": "0.74.0"}


def _which(tool: str) -> str | None:
    env = os.environ.get(f"TAPM_{tool.upper()}")
    if env and Path(env).exists():
        return env
    repo_scanners = PROJECT_ROOT / ".venv-scanners" / "bin" / tool
    if repo_scanners.exists():
        return str(repo_scanners)
    repo_tools = PROJECT_ROOT / ".tools" / "bin" / tool
    if repo_tools.exists():
        return str(repo_tools)
    return shutil.which(tool)


def _version(exe: str, tool: str) -> str:
    try:
        out = subprocess.run([exe, "--version"], capture_output=True, text=True, timeout=60).stdout
    except (subprocess.SubprocessError, OSError):
        return "unknown"
    for line in out.splitlines()[::-1]:
        line = line.strip()
        if line.lower().startswith("version:"):
            return line.split(":", 1)[1].strip()
        if line and line[0] in "v0123456789":
            return line
    return out.strip().splitlines()[-1] if out.strip() else "unknown"


def _clean_copy(src: Path, dst: Path) -> Path:
    """Copy only Terraform sources (*.tf, local modules) so every scanner sees the same input.

    Without this, Trivy also scans the committed plan.json and double-counts findings."""
    for f in sorted(src.rglob("*.tf")):
        rel = f.relative_to(src)
        if any(part.startswith(".") for part in rel.parts):
            continue
        (dst / rel).parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(f, dst / rel)
    return dst


def run_scanners(tf_dir: str | Path, out_dir: str | Path, tools: tuple[str, ...] = ("checkov", "tfsec", "trivy")) -> dict:
    out_dir = Path(out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="tapm-scan-") as tmp:
        clean = _clean_copy(Path(tf_dir).resolve(), Path(tmp) / Path(tf_dir).name)
        return _run(clean, out_dir, tools)


def _run(tf_dir: Path, out_dir: Path, tools: tuple[str, ...]) -> dict:
    versions: dict[str, dict] = {}
    for tool in tools:
        exe = _which(tool)
        if not exe:
            versions[tool] = {"status": "missing", "pinned": PINNED[tool]}
            continue
        ver = _version(exe, tool)
        if ver != PINNED[tool]:
            versions[tool] = {"status": "version_mismatch", "version": ver, "pinned": PINNED[tool]}
            continue
        if tool == "checkov":
            cmd = [exe, "-d", str(tf_dir), "--framework", "terraform", "-o", "json", "--quiet", "--compact", "--skip-download"]
        elif tool == "tfsec":
            cmd = [exe, str(tf_dir), "--format", "json", "--no-color", "--soft-fail"]
        else:
            cmd = [exe, "config", "--format", "json", "--quiet", "--skip-check-update", str(tf_dir)]
        t0 = time.monotonic()
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=900, cwd=tf_dir)
        ms = int((time.monotonic() - t0) * 1000)
        stdout = proc.stdout.strip() if proc.stdout else ""
        if not stdout:
            versions[tool] = {
                "status": "error",
                "error": "empty output",
                "version": ver,
                "pinned": PINNED[tool],
                "stderr": proc.stderr[-2000:] if proc.stderr else "",
            }
            continue
        try:
            data = json.loads(stdout)
        except json.JSONDecodeError:
            versions[tool] = {
                "status": "error",
                "error": "invalid json",
                "version": ver,
                "pinned": PINNED[tool],
                "stderr": proc.stderr[-2000:] if proc.stderr else "",
            }
            continue
        if data is None:
            versions[tool] = {
                "status": "error",
                "error": "null output",
                "version": ver,
                "pinned": PINNED[tool],
                "stderr": proc.stderr[-2000:] if proc.stderr else "",
            }
            continue
        data = _relativise(data, str(tf_dir))
        dump_json(data, out_dir / f"{tool}.json")
        versions[tool] = {
            "status": "ok",
            "version": ver,
            "pinned": PINNED[tool],
            "runtime_ms": ms,
            "command": " ".join([tool] + cmd[1:]).replace(str(tf_dir), "."),
        }
    dump_json(versions, out_dir / "versions.json")
    return versions


def validate_baseline(baseline_dir: str | Path, tools: tuple[str, ...] = ("checkov", "tfsec", "trivy")) -> dict:
    """Validate that baseline directory has versions.json and all required tools are 'ok' with matching pins.

    Raises RuntimeError if baseline is missing, incomplete, or any scanner is not 'ok'.
    """
    base = Path(baseline_dir)
    versions_file = base / "versions.json"
    if not versions_file.exists():
        raise RuntimeError(f"Baseline versions.json missing in {base}")
    try:
        versions = json.loads(versions_file.read_text(encoding="utf-8"))
    except Exception as e:
        raise RuntimeError(f"Baseline versions.json corrupted in {base}: {e}")
    for tool in tools:
        info = versions.get(tool)
        if not info:
            raise RuntimeError(f"Baseline in {base} missing scanner '{tool}'")
        status = info.get("status")
        if status != "ok":
            raise RuntimeError(
                f"Baseline in {base} scanner '{tool}' is not ok (status: '{status}')"
            )
        tool_json = base / f"{tool}.json"
        if not tool_json.exists():
            raise RuntimeError(f"Baseline in {base} missing findings file {tool}.json")
    return versions


def _relativise(obj, root: str):
    """Strip absolute paths so saved baselines are machine-independent."""
    if isinstance(obj, dict):
        return {k: _relativise(v, root) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_relativise(v, root) for v in obj]
    if isinstance(obj, str) and root in obj:
        return obj.replace(root + "/", "").replace(root, ".")
    return obj
