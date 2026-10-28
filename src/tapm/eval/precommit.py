"""Pre-commitment verification for evaluation results (Check C8).

Provably verifies that:
1. Results JSON explicitly records the gold commit SHA and sha256 checksums of each gold file.
2. The gold commit is an ancestor of the results commit in git history.
3. Every gold file has remained unchanged since the gold commit (byte & hash match, zero diff).
4. The label commit touches only label, manifest, or documentation files (pure label commit;
   zero engine code, plans, baselines, or results).
5. Supports future evaluations three-commit protocol:
   Commit 1: labels only
   Commit 2: plans and baselines
   Commit 3: evaluation results
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..util import PROJECT_ROOT


def _find_repo_root() -> Path:
    try:
        proc = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            check=True,
        )
        return Path(proc.stdout.strip())
    except Exception:
        return PROJECT_ROOT.parent.parent


REPO_ROOT = _find_repo_root()

# Patterns considered non-label files that invalidate label commit purity
FORBIDDEN_LABEL_COMMIT_PATTERNS = [
    "/src/", "src/",
    "/plans/", "plans/",
    "/baselines/", "baselines/",
    "/results/", "results/",
    "/tests/", "tests/",
    "/deck/", "deck/",
]


@dataclass
class PrecommitReport:
    result_path: str
    gold_commit: str
    results_commit: str
    gold_files_count: int
    is_ancestor: bool
    gold_unchanged: bool
    label_commit_pure: bool
    passed: bool
    errors: list[str] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)


def _resolve_file_path(rel_or_abs: str | Path, repo_root: Path) -> Path | None:
    p = Path(rel_or_abs)
    if p.is_absolute() and p.exists():
        return p
    candidates = [
        repo_root / p,
        PROJECT_ROOT / p,
        PROJECT_ROOT.parent / p,
        repo_root / "OWASP-GLOBAL-AppSec-US-2026/terraform-attack-paths-pytm" / p,
    ]
    for c in candidates:
        if c.exists():
            return c.resolve()
    return None


def verify_precommitment(
    result_input: Path | str | dict,
    repo_root: Path | None = None,
) -> PrecommitReport:
    """Verifies pre-commitment provability for an evaluation results file or dict.

    Returns a PrecommitReport with passed=True iff all C8 criteria pass.
    """
    root = repo_root or REPO_ROOT
    result_path_str = "in-memory"
    if isinstance(result_input, (str, Path)):
        p = Path(result_input)
        result_path_str = str(p)
        if not p.is_absolute():
            resolved = _resolve_file_path(p, root)
            if resolved:
                p = resolved
        data = json.loads(p.read_text(encoding="utf-8"))
    else:
        data = result_input

    errors: list[str] = []
    details: dict[str, Any] = {}

    # 1. Extract gold_commit
    gold_commit = (
        data.get("gold_commit")
        or data.get("git_sha", {}).get("gold_commit")
        or data.get("git_sha", {}).get("gold")
        or data.get("metadata", {}).get("gold_commit")
        or data.get("metadata", {}).get("git_sha", {}).get("gold")
        or ""
    )
    if not gold_commit or gold_commit == "unknown" or len(gold_commit) < 7:
        errors.append("Missing or invalid gold_commit in results JSON")
        gold_commit = "unknown"

    # 2. Extract results_commit
    results_commit = (
        data.get("git_sha", {}).get("code")
        or data.get("metadata", {}).get("git_sha", {}).get("code")
        or ""
    )
    if (not results_commit or results_commit == "unknown") and result_path_str != "in-memory":
        try:
            proc = subprocess.run(
                ["git", "log", "-1", "--format=%H", "--", result_path_str],
                cwd=root,
                capture_output=True,
                text=True,
            )
            if proc.returncode == 0 and proc.stdout.strip():
                results_commit = proc.stdout.strip()
        except Exception:
            pass

    if not results_commit or results_commit == "unknown":
        try:
            proc = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=root,
                capture_output=True,
                text=True,
            )
            if proc.returncode == 0 and proc.stdout.strip():
                results_commit = proc.stdout.strip()
        except Exception:
            pass

    if not results_commit or results_commit == "unknown":
        errors.append("Could not determine results commit SHA")
        results_commit = "unknown"

    # 3. Extract gold_files hashes
    gold_files = (
        data.get("gold_files")
        or data.get("git_sha", {}).get("gold_files")
        or data.get("metadata", {}).get("gold_files")
        or {}
    )
    if not isinstance(gold_files, dict) or not gold_files:
        errors.append("Missing or empty gold_files hashes in results JSON")
        gold_files = {}

    details["gold_commit"] = gold_commit
    details["results_commit"] = results_commit
    details["gold_files"] = gold_files

    # 4. Check ancestry: is gold_commit an ancestor of results_commit?
    is_ancestor = False
    if gold_commit != "unknown" and results_commit != "unknown":
        try:
            proc = subprocess.run(
                ["git", "merge-base", "--is-ancestor", gold_commit, results_commit],
                cwd=root,
                capture_output=True,
                text=True,
            )
            if proc.returncode == 0:
                is_ancestor = True
            else:
                errors.append(
                    f"Gold commit {gold_commit[:10]} is not an ancestor of results commit {results_commit[:10]}"
                )
        except Exception as e:
            errors.append(f"Git ancestry check failed: {e}")
    else:
        errors.append("Cannot perform ancestry check with unknown commit SHAs")

    # 5. Check gold files immutability (hash match and git diff clean)
    gold_unchanged = True
    for rel_path, expected_hash in gold_files.items():
        resolved_file = _resolve_file_path(rel_path, root)
        if not resolved_file or not resolved_file.exists():
            errors.append(f"Gold file missing on disk: {rel_path}")
            gold_unchanged = False
            continue

        actual_hash = hashlib.sha256(resolved_file.read_bytes()).hexdigest()
        if actual_hash != expected_hash:
            errors.append(
                f"Gold file hash mismatch for {rel_path}: expected {expected_hash}, got {actual_hash}"
            )
            gold_unchanged = False

        if gold_commit != "unknown":
            try:
                proc = subprocess.run(
                    ["git", "diff", "--name-only", gold_commit, results_commit, "--", str(resolved_file)],
                    cwd=root,
                    capture_output=True,
                    text=True,
                )
                if proc.returncode == 0 and proc.stdout.strip():
                    errors.append(
                        f"Gold file {rel_path} modified between gold commit {gold_commit[:10]} and results commit {results_commit[:10]}"
                    )
                    gold_unchanged = False
            except Exception as e:
                errors.append(f"Git diff check failed for {rel_path}: {e}")
                gold_unchanged = False

    # 6. Check label commit purity: touches only label files
    label_commit_pure = True
    if gold_commit != "unknown":
        try:
            proc = subprocess.run(
                ["git", "diff-tree", "--no-commit-id", "--name-only", "-r", gold_commit],
                cwd=root,
                capture_output=True,
                text=True,
            )
            if proc.returncode == 0:
                touched_files = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
                details["touched_files_in_label_commit"] = touched_files
                for tf in touched_files:
                    for forbidden in FORBIDDEN_LABEL_COMMIT_PATTERNS:
                        if forbidden in tf:
                            errors.append(
                                f"Label commit {gold_commit[:10]} touched non-label path: {tf}"
                            )
                            label_commit_pure = False
                            break
            else:
                errors.append(f"git diff-tree failed on gold_commit {gold_commit[:10]}")
                label_commit_pure = False
        except Exception as e:
            errors.append(f"Label purity check failed: {e}")
            label_commit_pure = False

    passed = (
        len(errors) == 0
        and is_ancestor
        and gold_unchanged
        and label_commit_pure
        and len(gold_files) > 0
    )

    return PrecommitReport(
        result_path=result_path_str,
        gold_commit=gold_commit,
        results_commit=results_commit,
        gold_files_count=len(gold_files),
        is_ancestor=is_ancestor,
        gold_unchanged=gold_unchanged,
        label_commit_pure=label_commit_pure,
        passed=passed,
        errors=errors,
        details=details,
    )


def verify_all_precommitments(
    target_files: list[str | Path] | None = None,
    repo_root: Path | None = None,
) -> list[PrecommitReport]:
    root = repo_root or REPO_ROOT
    if not target_files:
        default_files = [
            PROJECT_ROOT / "evaluations/results/tier2-heldout.json",
            PROJECT_ROOT / "evaluations/results/realworld-benign.json",
        ]
        target_files = [f for f in default_files if f.exists()]

    reports: list[PrecommitReport] = []
    for tf in target_files:
        reports.append(verify_precommitment(tf, repo_root=root))
    return reports


def verify_precommitment_cli(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="tapm eval verify-precommit",
        description="Verify evaluation pre-commitment (ancestor, hash match, label commit purity) (Check C8)",
    )
    parser.add_argument(
        "files",
        nargs="*",
        help="Results JSON files to verify (defaults to tier2-heldout.json and realworld-benign.json)",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress detailed report",
    )
    args = parser.parse_args(argv)

    reports = verify_all_precommitments(target_files=args.files or None)
    all_passed = True

    if not args.quiet:
        print("# Pre-Commitment Verification (Check C8)")
        print()
        print("| Result File | Gold Commit | Results Commit | Gold Files | Ancestor | Unchanged | Pure Label Commit | Status |")
        print("|---|---|---|---|---|---|---|---|")

    for rep in reports:
        status_str = "PASS" if rep.passed else "FAIL"
        if not rep.passed:
            all_passed = False
        if not args.quiet:
            short_gold = rep.gold_commit[:8] if rep.gold_commit != "unknown" else "unknown"
            short_res = rep.results_commit[:8] if rep.results_commit != "unknown" else "unknown"
            anc_str = "PASS" if rep.is_ancestor else "FAIL"
            unch_str = "PASS" if rep.gold_unchanged else "FAIL"
            pure_str = "PASS" if rep.label_commit_pure else "FAIL"
            pname = Path(rep.result_path).name
            print(
                f"| {pname} | `{short_gold}` | `{short_res}` | {rep.gold_files_count} | {anc_str} | {unch_str} | {pure_str} | **{status_str}** |"
            )

    if not args.quiet:
        print()
        for rep in reports:
            if not rep.passed:
                print(f"Errors for {rep.result_path}:")
                for err in rep.errors:
                    print(f"  - {err}")
                print()

    if all_passed:
        if not args.quiet:
            print("✓ All pre-commitment checks PASSED.")
        return 0
    else:
        if not args.quiet:
            print("✗ Pre-commitment checks FAILED.")
        return 1


if __name__ == "__main__":
    sys.exit(verify_precommitment_cli(sys.argv[1:]))
