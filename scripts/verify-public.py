#!/usr/bin/env python3
"""Verify snapshot bytes. A manifest is a checksum inventory, not a signature or ancestry proof."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import subprocess


def verify(root: Path, *, frozen=False, tracked=False):
    root = root.resolve()
    manifest = json.loads((root / "release-manifest.json").read_text())
    if manifest.get("kind") != "reviewed-source-snapshot" or manifest.get("private_history_included") is not False or manifest.get("historical_precommitment_independently_verifiable") is not False:
        raise ValueError("Invalid snapshot scope")
    files = manifest["files"]
    if not isinstance(files, dict) or not files:
        raise ValueError("Empty snapshot inventory")
    for name in files:
        path = PurePosixPath(name)
        if path.is_absolute() or ".." in path.parts or ".git" in path.parts:
            raise ValueError(f"Unsafe manifest path: {name}")
    if not frozen:
        if tracked:
            proc = subprocess.run(["git", "-C", str(root), "ls-files", "-z", "--cached", "--others", "--exclude-standard"], capture_output=True, check=True)
            actual = {x.decode() for x in proc.stdout.split(b"\0") if x}
        else:
            actual = {p.relative_to(root).as_posix() for p in root.rglob("*") if ".git" not in p.relative_to(root).parts and (p.is_file() or p.is_symlink())}
        expected = set(files) | {"release-manifest.json"}
        if actual != expected:
            raise ValueError(f"Inventory mismatch; extra={sorted(actual-expected)}, missing={sorted(expected-actual)}")
    checked = 0
    for name, meta in files.items():
        if frozen and not (name.startswith(("fixtures/", "evaluations/", "plan-cache/", "conference-snapshot/"))):
            continue
        path = root / name
        if path.is_symlink() or root not in path.resolve().parents or not path.is_file():
            raise ValueError(f"Missing/unsafe file: {name}")
        if hashlib.sha256(path.read_bytes()).hexdigest() != meta["sha256"]:
            raise ValueError(f"Hash mismatch: {name}")
        if oct(path.stat().st_mode & 0o777) != meta["mode"]:
            raise ValueError(f"Mode mismatch: {name}")
        checked += 1
    if not checked:
        raise ValueError("No files verified")
    return checked


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--frozen", action="store_true", help="Check only frozen inputs/results after runtime artifacts have been generated")
    modes.add_argument("--tracked", action="store_true", help="Check tracked plus nonignored files after dependency setup")
    args = parser.parse_args()
    try:
        count = verify(args.root, frozen=args.frozen, tracked=args.tracked)
    except (ValueError, OSError, KeyError, subprocess.CalledProcessError) as exc:
        parser.exit(1, f"FAIL: {exc}\n")
    print(f"PASS: {count} snapshot files match; historical ancestry is not established")


if __name__ == "__main__":
    main()
