"""Explicit local Terraform source collection for deterministic CI traceability.

Source text goes to the analysis service, not directly to an LLM. Plans alone do
not carry file/line locations. Symlinks and dependency-cache directories are not
read. Callers opt in by naming the source root.
"""
from __future__ import annotations

import os
from pathlib import Path


def collect_source_files(source_dir: str | Path) -> dict[str, str]:
    root = Path(source_dir).resolve(strict=True)
    if not root.is_dir():
        raise ValueError("source directory must be a directory")
    files: dict[str, str] = {}

    def source_error(error: OSError) -> None:
        raise error

    for folder, directories, names in os.walk(root, followlinks=False, onerror=source_error):
        directory = Path(folder)
        directories[:] = sorted(
            name for name in directories
            if name not in {".git", ".terraform"}
            and not (directory / name).is_symlink()
        )
        for name in sorted(names):
            if not name.endswith(".tf"):
                continue
            path = directory / name
            if path.is_symlink() or not path.is_file():
                raise ValueError(f"Terraform source must be a regular file: {path.relative_to(root)}")
            files[path.relative_to(root).as_posix()] = path.read_bytes().decode("utf-8")
    return files
