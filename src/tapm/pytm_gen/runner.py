"""Execute a generated pytm model: DFD (dot/png/svg), sequence diagram, pytm's findings and their classification."""

from __future__ import annotations

import base64
import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

# pytm writes the absolute path of its bundled icons into the DOT source; artifacts must not depend on
# (or reveal) where pytm happens to be installed.
_PYTM_IMAGES = re.compile(r'"[^"]*/pytm/images/([^"/]+)"')
_SVG_IMAGES = re.compile(r'((?:xlink:)?href)="([^"]*/pytm/images/[^"/]+)"')


def _portable_dot(dot: str) -> str:
    return _PYTM_IMAGES.sub(lambda m: f'"pytm/images/{m.group(1)}"', dot)


def _portable_svg(svg: str) -> str:
    def inline(m):
        p = Path(m.group(2))
        if not p.exists():
            return f'{m.group(1)}="pytm/images/{p.name}"'
        return f'{m.group(1)}="data:image/png;base64,{base64.b64encode(p.read_bytes()).decode()}"'
    return _SVG_IMAGES.sub(inline, svg)


def run_model(model_path: str | Path, out_dir: str | Path) -> dict:
    """One interpreter renders the DFD and the sequence diagram, resolves pytm's threats and classifies them
    (``classify.render_in_process``); the same output as ``python threat-model.py --seq --dfd --json``."""
    from .classify import render_model

    model_path, out_dir = Path(model_path), Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    res: dict = {"model": str(model_path.name)}
    controls = model_path.with_name("pytm-controls.json")
    render_model(model_path, controls if controls.exists() else None, out_dir)
    raw_dot = (out_dir / "_dfd.dot").read_text(encoding="utf-8")
    (out_dir / "dfd.dot").write_text(_portable_dot(raw_dot), encoding="utf-8")
    res["dfd_dot"] = "dfd.dot"
    (out_dir / "_seq.puml").replace(out_dir / "seq.puml")
    res["seq"] = "seq.puml"

    raw = json.loads((out_dir / "_pytm.json").read_text(encoding="utf-8"))
    (out_dir / "_pytm.json").unlink()
    findings = []
    for f in raw.get("findings", []) or []:
        findings.append({
            "threat_id": f.get("threat_id"),
            "element": f.get("target") or _elem_name(f.get("element")),
            "description": f.get("description"),
            "severity": f.get("severity"),
            **({"likelihood": f["likelihood"]} if f.get("likelihood") else {}),
            **({"response": f["response"]} if f.get("response") else {}),
        })
    findings.sort(key=lambda x: (str(x["element"]), str(x["threat_id"])))
    res["threats"] = findings
    res["threat_count"] = len(findings)
    if controls.exists():
        res["classification"] = json.loads((out_dir / "pytm-findings.json").read_text(encoding="utf-8"))

    # the overview (level 0: the attack path only) and pytm's --colormap coloured by what the plan decides
    extra = {}
    for kind in ("overview", "risk"):
        f = out_dir / f"_dfd_{kind}.dot"
        if f.exists():
            extra[kind] = f.read_text(encoding="utf-8")
            (out_dir / f"dfd-{kind}.dot").write_text(_portable_dot(extra[kind]), encoding="utf-8")
            res[f"dfd_{kind}"] = f"dfd-{kind}.dot"
            f.unlink()

    dot = shutil.which("dot")
    if dot:
        with tempfile.TemporaryDirectory(prefix="tapm-dfd-") as tmp:
            src = Path(tmp) / "dfd.dot"
            src.write_text(raw_dot, encoding="utf-8")  # render with the real icon paths
            jobs = [[dot, f"-T{fmt}", str(src), "-o", str(out_dir / f"dfd.{fmt}")] for fmt in ("png", "svg")]
            for kind, text in extra.items():
                k = Path(tmp) / f"{kind}.dot"
                k.write_text(text, encoding="utf-8")
                jobs.append([dot, "-Tpng", str(k), "-o", str(out_dir / f"dfd-{kind}.png")])
            procs = [subprocess.Popen(j) for j in jobs]  # independent renders: run them side by side
            for j, p in zip(jobs, procs):
                if p.wait(timeout=120) != 0:
                    raise subprocess.CalledProcessError(p.returncode, j)
            res["dfd_png"], res["dfd_svg"] = "dfd.png", "dfd.svg"
        svg = out_dir / "dfd.svg"
        svg.write_text(_portable_svg(svg.read_text(encoding="utf-8")), encoding="utf-8")
    else:
        res["dfd_png"] = None
        res["note"] = "Graphviz 'dot' not found; dfd.dot written, PNG not rendered."
    (out_dir / "_dfd.dot").unlink()
    return res


def _elem_name(e) -> str:
    if isinstance(e, dict):
        return e.get("name") or ""
    return str(e or "")
