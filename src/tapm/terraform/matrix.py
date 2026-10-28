"""Many root modules: dependency mapping, affected-module detection, CI matrix, and sharded nightly sweep (W1.5).

Critic B M4:
"Nothing scales the check to hundreds of root modules. Fix: map each change to its affected
root modules (changed files -> root modules -> consumers of a changed shared module), feed
those to a CI matrix, and shard the nightly sweep."

Acceptance criterion:
"A test repo with three root modules and one shared module re-plans only the affected ones."
"""

from __future__ import annotations

import fnmatch
import json
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path
import re
import subprocess
from typing import Any, Callable


RELEVANT_EXTENSIONS = (".tf", ".tfvars", ".tfvars.json")
LOCK_FILENAMES = (".terraform.lock.hcl", "terraform.lock.hcl")
GATE_ONLY_FILENAMES = (
    "attack-path-exceptions.yaml",
    "threat-answers.yaml",
)


@dataclass
class ModuleInfo:
    """Represents a Terraform module directory (root or shared)."""

    path: str  # Path relative to repository root, forward slashes
    abs_path: Path
    name: str  # Short name / identifier
    is_root: bool
    dependencies: set[str] = field(default_factory=set)  # direct local child module paths
    transitive_dependencies: set[str] = field(default_factory=set)  # all direct & indirect local dependencies
    consuming_roots: set[str] = field(default_factory=set)  # root modules that consume this module


@dataclass
class AffectedModule:
    """A root module affected by changed files."""

    module: str  # Relative path to root module
    name: str  # Short name
    replan: bool  # True if .tf / .tfvars / lockfile changed; False if only exceptions/answers changed
    reasons: list[str] = field(default_factory=list)  # Changed files that triggered this root
    shared_dependencies: list[str] = field(default_factory=list)  # Which shared modules caused this


def extract_local_module_sources(tf_text: str) -> list[tuple[str, str]]:
    """Extract (module_name, source_path) from Terraform code for local sources (./.. or ../..)."""
    results: list[tuple[str, str]] = []
    # Match module "<name>" { ... } blocks
    pattern = re.compile(r'module\s+"([^"]+)"\s*\{([^}]*)\}', re.DOTALL)
    for m in pattern.finditer(tf_text):
        name = m.group(1)
        body = m.group(2)
        # Find source = "..." inside body
        src_match = re.search(r'source\s*=\s*"([^"]+)"', body)
        if src_match:
            src = src_match.group(1).strip()
            # Clean off any query parameters or sub-paths if present
            clean_src = src.split("?")[0]
            if clean_src.startswith("./") or clean_src.startswith("../"):
                results.append((name, clean_src))
    return results


class ModuleGraph:
    """Discovers Terraform root and shared modules, builds dependency graphs, and maps changes."""

    def __init__(
        self,
        repo_root: str | Path,
        roots: list[str] | None = None,
        roots_pattern: str | None = None,
    ) -> None:
        self.repo_root = Path(repo_root).resolve()
        self.roots_filter = roots
        self.roots_pattern = roots_pattern
        self.modules: dict[str, ModuleInfo] = {}  # rel_path -> ModuleInfo
        self.root_paths: set[str] = set()
        self.shared_paths: set[str] = set()
        self.build()

    def _normalize_rel(self, path: Path) -> str:
        try:
            rel = str(path.resolve().relative_to(self.repo_root))
            return "" if rel == "." else rel.replace("\\", "/")
        except ValueError:
            return str(path).replace("\\", "/")

    def build(self) -> None:
        """Scan repository, detect modules, parse dependencies, and build dependency graph."""
        self.modules.clear()
        self.root_paths.clear()
        self.shared_paths.clear()

        # 1. Find all directories containing *.tf files
        tf_dirs: set[Path] = set()
        for tf_file in self.repo_root.rglob("*.tf"):
            parts = tf_file.relative_to(self.repo_root).parts
            if any(p.startswith(".") or p in ("venv", ".venv", "node_modules", "vendor") for p in parts):
                continue
            tf_dirs.add(tf_file.parent.resolve())

        # 2. Extract direct dependencies for each directory
        raw_deps: dict[str, set[str]] = {}
        for d in sorted(tf_dirs):
            rel_d = self._normalize_rel(d)
            deps: set[str] = set()
            for f in sorted(d.glob("*.tf")):
                if f.name.endswith("_override.tf") or f.name == "override.tf":
                    continue
                try:
                    content = f.read_text(encoding="utf-8")
                except Exception:
                    continue
                for _, src in extract_local_module_sources(content):
                    target_dir = (d / src).resolve()
                    if target_dir.exists() and target_dir.is_dir():
                        rel_target = self._normalize_rel(target_dir)
                        deps.add(rel_target)
            raw_deps[rel_d] = deps

        # 3. Classify which directories are root modules vs shared modules
        all_module_dirs = sorted(raw_deps.keys())
        all_referenced_targets: set[str] = set()
        for targets in raw_deps.values():
            all_referenced_targets.update(targets)

        # Classification rules:
        # If explicit roots filter or pattern given:
        #   Use explicit roots.
        # Otherwise:
        #   A directory is a root module if:
        #   - It matches standard root conventions (under roots/, infra/, envs/, live/, stacks/, or top-level)
        #   - OR it is NOT exclusively in a shared directory (modules/, shared/, common/) and not only called as a child
        for rel_d in all_module_dirs:
            d_path = (self.repo_root / rel_d).resolve() if rel_d else self.repo_root
            is_root = False
            if self.roots_filter is not None:
                is_root = rel_d in self.roots_filter
            elif self.roots_pattern is not None:
                is_root = fnmatch.fnmatch(rel_d, self.roots_pattern)
            else:
                # Automatic classification
                parts = Path(rel_d).parts if rel_d else ()
                is_shared_dir = any(p in ("modules", "shared", "common", "submodules") for p in parts)
                if is_shared_dir:
                    is_root = False
                elif rel_d in all_referenced_targets and not any(p in ("roots", "infra", "envs", "live", "stacks") for p in parts):
                    is_root = False
                else:
                    is_root = True

            name = Path(rel_d).name if rel_d else "root"
            info = ModuleInfo(
                path=rel_d,
                abs_path=d_path,
                name=name,
                is_root=is_root,
                dependencies=set(raw_deps.get(rel_d, set())),
            )
            self.modules[rel_d] = info
            if is_root:
                self.root_paths.add(rel_d)
            else:
                self.shared_paths.add(rel_d)

        # 4. Compute transitive dependencies for every module
        for rel_d, info in self.modules.items():
            visited: set[str] = set()
            stack = list(info.dependencies)
            while stack:
                dep = stack.pop()
                if dep not in visited:
                    visited.add(dep)
                    if dep in self.modules:
                        stack.extend(self.modules[dep].dependencies - visited)
            info.transitive_dependencies = visited

        # 5. Compute consuming root modules (reverse graph)
        # Every root module consumes itself
        for root_d in self.root_paths:
            self.modules[root_d].consuming_roots.add(root_d)
            # Add to all direct and transitive dependencies
            for dep in self.modules[root_d].transitive_dependencies:
                if dep in self.modules:
                    self.modules[dep].consuming_roots.add(root_d)

    def locate_module_for_path(self, rel_path: str) -> str | None:
        """Find the module directory that best encompasses the given relative file path."""
        norm_path = rel_path.replace("\\", "/")
        path_obj = Path(norm_path)

        # Check candidate ancestor directories in decreasing order of length
        candidates = sorted(self.modules.keys(), key=lambda p: len(p.split("/")), reverse=True)
        for cand in candidates:
            if not cand:  # root directory
                return ""
            try:
                # If path starts with cand/ or is cand
                if norm_path == cand or norm_path.startswith(cand + "/"):
                    return cand
            except ValueError:
                continue
        return None

    def classify_file(self, rel_path: str) -> tuple[bool, bool]:
        """Classify if a file is relevant to Terraform evaluation and whether it requires re-planning.

        Returns: (is_relevant, requires_replan)
        """
        p = Path(rel_path)
        name = p.name

        # Plan-triggering files:
        if name.endswith(".tf") or name.endswith(".tfvars") or name.endswith(".tfvars.json"):
            return True, True
        if name in LOCK_FILENAMES or any(name.endswith(l) for l in LOCK_FILENAMES):
            return True, True

        # Gate-only files:
        if name in GATE_ONLY_FILENAMES or any(name.endswith(g) for g in GATE_ONLY_FILENAMES):
            return True, False

        return False, False

    def affected_roots(self, changed_files: list[str | Path]) -> list[AffectedModule]:
        """Map a list of changed file paths to the root modules they affect."""
        affected_map: dict[str, AffectedModule] = {}

        for raw_f in changed_files:
            f_str = str(raw_f).replace("\\", "/")
            if os.path.isabs(f_str):
                try:
                    f_str = str(Path(f_str).resolve().relative_to(self.repo_root)).replace("\\", "/")
                except ValueError:
                    pass

            is_rel, req_replan = self.classify_file(f_str)
            if not is_rel:
                continue

            mod_key = self.locate_module_for_path(f_str)
            if mod_key is None or mod_key not in self.modules:
                continue

            target_mod = self.modules[mod_key]
            # Root modules consuming target_mod
            consumers = target_mod.consuming_roots
            for root_key in sorted(consumers):
                if root_key not in affected_map:
                    root_info = self.modules[root_key]
                    affected_map[root_key] = AffectedModule(
                        module=root_key,
                        name=root_info.name,
                        replan=False,
                        reasons=[],
                        shared_dependencies=[],
                    )

                aff = affected_map[root_key]
                aff.reasons.append(f_str)
                if req_replan:
                    aff.replan = True
                if mod_key != root_key and mod_key not in aff.shared_dependencies:
                    aff.shared_dependencies.append(mod_key)

        # Sort by module path
        return [affected_map[k] for k in sorted(affected_map.keys())]

    @staticmethod
    def shard(
        items: list[Any],
        shard_index: int,
        total_shards: int,
    ) -> list[Any]:
        """Deterministically shard a list of items across total_shards (1-indexed)."""
        if total_shards <= 0:
            raise ValueError(f"total_shards must be > 0, got {total_shards}")
        if not (1 <= shard_index <= total_shards):
            raise ValueError(f"shard_index must be between 1 and {total_shards}, got {shard_index}")

        # Deterministic round-robin allocation
        return [item for i, item in enumerate(items) if (i % total_shards) == (shard_index - 1)]

    def generate_matrix(
        self,
        affected: list[AffectedModule] | list[str] | None = None,
        *,
        fmt: str = "github",
        shards: int | None = None,
        shard_index: int | None = None,
        all_roots: bool = False,
    ) -> dict | list:
        """Generate CI matrix JSON according to target format.

        Supported formats:
        - 'github': GitHub Actions / Gitea Actions matrix ({"include": [...]})
        - 'gitlab': GitLab CI parallel matrix
        - 'json': Structured report dictionary
        - 'text': Newline-separated module paths
        """
        # Determine base modules to use
        if all_roots or affected is None:
            modules_list = [
                AffectedModule(
                    module=r,
                    name=self.modules[r].name,
                    replan=True,
                    reasons=["all-roots"],
                    shared_dependencies=[],
                )
                for r in sorted(self.root_paths)
            ]
        elif affected and isinstance(affected[0], str):
            modules_list = [
                AffectedModule(
                    module=str(r),
                    name=self.modules.get(str(r), ModuleInfo(str(r), self.repo_root / str(r), Path(str(r)).name, True)).name,
                    replan=True,
                    reasons=[],
                    shared_dependencies=[],
                )
                for r in affected
            ]
        else:
            modules_list = list(affected)  # type: ignore

        # Sharding logic:
        # Case 1: Sharded sweep for nightly (emitting matrix of shards)
        if shards is not None and shard_index is None:
            shard_entries = []
            for s in range(1, shards + 1):
                shard_mods = self.shard(modules_list, s, shards)
                shard_mod_paths = [m.module for m in shard_mods]
                shard_entries.append({
                    "shard": s,
                    "total_shards": shards,
                    "modules": shard_mod_paths,
                    "count": len(shard_mod_paths),
                })
            if fmt == "github":
                return {"include": shard_entries}
            elif fmt == "gitlab":
                return shard_entries
            elif fmt == "json":
                return {
                    "shards": shards,
                    "matrix": {"include": shard_entries},
                    "total_modules": len(modules_list),
                }
            elif fmt == "text":
                lines = []
                for entry in shard_entries:
                    lines.append(f"Shard {entry['shard']}/{entry['total_shards']}: {','.join(entry['modules'])}")
                return lines

        # Case 2: Specific shard selected
        if shards is not None and shard_index is not None:
            modules_list = self.shard(modules_list, shard_index, shards)

        # Output formatting for module items
        if fmt == "github":
            include_items = [
                {
                    "module": m.module,
                    "name": m.name,
                    "replan": m.replan,
                }
                for m in modules_list
            ]
            return {"include": include_items}

        elif fmt == "gitlab":
            return [
                {
                    "MODULE": m.module,
                    "NAME": m.name,
                    "REPLAN": str(m.replan).lower(),
                }
                for m in modules_list
            ]

        elif fmt == "json":
            return {
                "repo_root": str(self.repo_root),
                "count": len(modules_list),
                "has_affected": len(modules_list) > 0,
                "all_roots": sorted(self.root_paths),
                "all_shared": sorted(self.shared_paths),
                "affected_roots": [m.module for m in modules_list],
                "modules": [
                    {
                        "module": m.module,
                        "name": m.name,
                        "replan": m.replan,
                        "reasons": m.reasons,
                        "shared_dependencies": m.shared_dependencies,
                    }
                    for m in modules_list
                ],
                "matrix": {
                    "include": [
                        {
                            "module": m.module,
                            "name": m.name,
                            "replan": m.replan,
                        }
                        for m in modules_list
                    ]
                },
            }

        elif fmt == "text":
            return [m.module for m in modules_list]

        raise ValueError(f"Unknown matrix format: {fmt}")


def plan_affected_modules(
    repo_root: str | Path,
    affected_modules: list[AffectedModule],
    *,
    out_dir: Path | None = None,
    planner: Callable[[Path, Path], dict] | None = None,
    use_cache: bool = True,
) -> dict[str, Any]:
    """Execute re-planning for only the affected root modules that require replanning.

    Acceptance criterion:
    A test repo with three root modules and one shared module re-plans only the affected ones.
    """
    repo = Path(repo_root).resolve()
    if out_dir:
        out_dir = Path(out_dir).resolve()
        out_dir.mkdir(parents=True, exist_ok=True)

    results: dict[str, Any] = {
        "planned": [],
        "gate_only": [],
        "skipped": [],
        "total_affected": len(affected_modules),
    }

    if planner is None:
        from .offline_plan import plan_fixture

        def default_planner(mod_dir: Path, plan_file: Path) -> dict:
            return plan_fixture(mod_dir, plan_file, use_cache=use_cache, context_dir=repo)

        planner = default_planner

    for aff in affected_modules:
        mod_dir = (repo / aff.module).resolve()
        if not aff.replan:
            results["gate_only"].append({
                "module": aff.module,
                "reasons": aff.reasons,
            })
            continue

        target_plan = (out_dir / aff.name / "plan.json") if out_dir else (mod_dir / "plan.json")
        target_plan.parent.mkdir(parents=True, exist_ok=True)

        plan_info = planner(mod_dir, target_plan)
        results["planned"].append({
            "module": aff.module,
            "plan_file": str(target_plan),
            "reasons": aff.reasons,
            "shared_dependencies": aff.shared_dependencies,
            "info": plan_info,
        })

    return results


def get_git_changed_files(repo_root: Path, diff_ref: str | None = None) -> list[str]:
    """Extract list of changed files from git repository."""
    cmd = ["git", "diff", "--name-only"]
    if diff_ref:
        cmd.append(diff_ref)
    else:
        cmd.append("HEAD")

    try:
        p = subprocess.run(cmd, cwd=repo_root, capture_output=True, text=True, check=True)
        files = [line.strip() for line in p.stdout.splitlines() if line.strip()]
        # Also grab untracked/staged files
        p_status = subprocess.run(
            ["git", "status", "--porcelain"],
            cwd=repo_root,
            capture_output=True,
            text=True,
            check=True,
        )
        for line in p_status.stdout.splitlines():
            line = line.strip()
            if line:
                parts = line.split(maxsplit=1)
                if len(parts) == 2:
                    files.append(parts[1])
        return sorted(set(files))
    except Exception as exc:
        return []
