#!/usr/bin/env python3
"""Export committed package blobs to a new directory, never Git history or ignored files."""
from __future__ import annotations
import argparse
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import subprocess
import tarfile

# Speaker media/deck integration tests require material outside the standalone lab.
EXCLUDED = {"tests/test_recordings.py", "tests/test_deck_determinism.py", "release-manifest.json"}
RUNTIME = {".git", ".venv", ".tools", ".cache", "__pycache__", ".pytest_cache", "artifacts", ".terraform", "node_modules"}


def export(repo: Path, revision: str, prefix: str, destination: Path) -> dict:
    repo = repo.resolve()
    if destination.exists():
        raise ValueError("Destination must not exist; export never overwrites an existing clone")
    commit = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "--verify", revision + "^{commit}"], text=True).strip()
    tree = commit + (":" + prefix.strip("/") if prefix and prefix != "." else "")
    raw = subprocess.check_output(["git", "-C", str(repo), "archive", "--format=tar", tree])
    entries = []
    with tarfile.open(fileobj=io.BytesIO(raw)) as archive:
        for item in archive.getmembers():
            name = PurePosixPath(item.name)
            if name.is_absolute() or ".." in name.parts or any(p in RUNTIME or p.startswith(".venv") for p in name.parts) or name.parts[:2] == ("labs", "workspace"):
                raise ValueError(f"Unsafe/runtime export path: {item.name}")
            if item.isdir():
                continue
            if not item.isfile():
                raise ValueError(f"Symlinks and special files are not exported: {item.name}")
            if name.name.startswith(".env") and name.name != ".env.example":
                raise ValueError(f"Environment state is not exported: {item.name}")
            if name.suffix in {".tfstate", ".tfplan", ".pem", ".key"} or name.name == "tfplan":
                raise ValueError(f"Sensitive runtime file: {item.name}")
            if str(name) in EXCLUDED:
                continue
            data = archive.extractfile(item).read()
            entries.append((str(name), data, 0o755 if item.mode & 0o111 else 0o644))
    if not {"README.md", "LICENSE", "src/tapm/__init__.py", "PUBLIC-RELEASE.md"} <= {e[0] for e in entries}:
        raise ValueError("Source is not the reviewed standalone package")
    manifest = {"schema_version": 1, "kind": "reviewed-source-snapshot", "source_revision": commit,
                "source_prefix": prefix, "private_history_included": False,
                "historical_precommitment_independently_verifiable": False,
                "excluded_source_paths": sorted(EXCLUDED - {"release-manifest.json"}),
                "files": {name: {"sha256": hashlib.sha256(data).hexdigest(), "mode": oct(mode)} for name, data, mode in sorted(entries)}}
    destination.mkdir(parents=True)
    for name, data, mode in entries:
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        target.chmod(mode)
    (destination / "release-manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("destination", type=Path)
    parser.add_argument("--revision", default="HEAD")
    parser.add_argument("--repo", type=Path)
    args = parser.parse_args()
    project = Path(__file__).resolve().parents[1]
    repo = args.repo or Path(subprocess.check_output(["git", "-C", str(project), "rev-parse", "--show-toplevel"], text=True).strip())
    prefix = project.relative_to(repo.resolve()).as_posix()
    result = export(repo, args.revision, prefix, args.destination)
    print(f"Exported {len(result['files'])} committed files; no source-repository history, tags or runtime state")


if __name__ == "__main__":
    main()
