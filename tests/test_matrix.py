"""Tests for W1.5: Many root modules (dependency mapping, affected CI matrix, sharded sweep).

Acceptance criterion:
"A test repo with three root modules and one shared module re-plans only the affected ones."
"""

from __future__ import annotations

import json
from pathlib import Path
import pytest

from tapm.cli import main
from tapm.terraform.matrix import (
    AffectedModule,
    ModuleGraph,
    extract_local_module_sources,
    plan_affected_modules,
)


@pytest.fixture
def test_repo_acceptance(tmp_path: Path) -> Path:
    """Create test repository with three root modules and one shared module."""
    repo = tmp_path / "repo"
    repo.mkdir()

    # Three root modules: roots/app, roots/database, roots/frontend
    # One shared module: modules/shared_vpc
    roots_dir = repo / "roots"
    modules_dir = repo / "modules"
    app_dir = roots_dir / "app"
    db_dir = roots_dir / "database"
    fe_dir = roots_dir / "frontend"
    vpc_dir = modules_dir / "shared_vpc"

    app_dir.mkdir(parents=True)
    db_dir.mkdir(parents=True)
    fe_dir.mkdir(parents=True)
    vpc_dir.mkdir(parents=True)

    # modules/shared_vpc/main.tf
    (vpc_dir / "main.tf").write_text(
        """
resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"
}
""",
        encoding="utf-8",
    )

    # roots/app/main.tf consumes modules/shared_vpc
    (app_dir / "main.tf").write_text(
        """
module "vpc" {
  source = "../../modules/shared_vpc"
}

resource "aws_instance" "app" {
  ami           = "ami-12345"
  instance_type = "t3.micro"
}
""",
        encoding="utf-8",
    )

    # roots/database/main.tf consumes modules/shared_vpc
    (db_dir / "main.tf").write_text(
        """
module "network" {
  source = "../../modules/shared_vpc"
}

resource "aws_db_instance" "db" {
  engine = "postgres"
}
""",
        encoding="utf-8",
    )

    # roots/frontend/main.tf does NOT consume modules/shared_vpc
    (fe_dir / "main.tf").write_text(
        """
resource "aws_s3_bucket" "static" {
  bucket = "my-static-site"
}
""",
        encoding="utf-8",
    )

    # Extra non-terraform files
    docs_dir = repo / "docs"
    docs_dir.mkdir()
    (docs_dir / "README.md").write_text("# Project Docs\n", encoding="utf-8")

    return repo


def test_extract_local_module_sources():
    tf = """
module "vpc" {
  source = "../../modules/shared_vpc"
  cidr = "10.0.0.0/16"
}

module "remote" {
  source = "terraform-aws-modules/vpc/aws"
}

# Commented module
# module "commented" {
#   source = "./modules/ignored"
# }

module "s3" {
  source = "./modules/s3?ref=v1.0"
}
"""
    sources = extract_local_module_sources(tf)
    assert ("vpc", "../../modules/shared_vpc") in sources
    assert ("s3", "./modules/s3") in sources
    assert not any(s[1].startswith("terraform-aws-modules") for s in sources)


def test_acceptance_three_roots_one_shared_dependency_graph(test_repo_acceptance: Path):
    """ModuleGraph accurately detects roots and consumes mapping."""
    graph = ModuleGraph(test_repo_acceptance)

    assert graph.root_paths == {"roots/app", "roots/database", "roots/frontend"}
    assert "modules/shared_vpc" in graph.shared_paths

    # Dependencies
    assert "modules/shared_vpc" in graph.modules["roots/app"].dependencies
    assert "modules/shared_vpc" in graph.modules["roots/database"].dependencies
    assert len(graph.modules["roots/frontend"].dependencies) == 0

    # Reverse dependencies
    vpc_consumers = graph.modules["modules/shared_vpc"].consuming_roots
    assert vpc_consumers == {"roots/app", "roots/database"}


def test_acceptance_three_roots_one_shared_replans_only_affected(test_repo_acceptance: Path):
    """Acceptance criterion:

    A test repo with three root modules and one shared module re-plans only the affected ones.
    """
    graph = ModuleGraph(test_repo_acceptance)
    planned_records: list[str] = []

    def mock_planner(mod_dir: Path, target_plan: Path) -> dict:
        planned_records.append(str(mod_dir.relative_to(test_repo_acceptance)).replace("\\", "/"))
        target_plan.write_text("{}", encoding="utf-8")
        return {"source": "mock"}

    # Case 1: Changing shared module affects roots/app and roots/database, but NOT roots/frontend
    changed_shared = ["modules/shared_vpc/main.tf"]
    aff_shared = graph.affected_roots(changed_shared)
    affected_mod_names = [m.module for m in aff_shared]
    assert affected_mod_names == ["roots/app", "roots/database"]
    assert "roots/frontend" not in affected_mod_names

    planned_records.clear()
    plan_res = plan_affected_modules(test_repo_acceptance, aff_shared, planner=mock_planner)
    assert planned_records == ["roots/app", "roots/database"]
    assert len(plan_res["planned"]) == 2
    assert "roots/frontend" not in planned_records

    # Case 2: Changing roots/frontend/main.tf affects ONLY roots/frontend
    changed_fe = ["roots/frontend/main.tf"]
    aff_fe = graph.affected_roots(changed_fe)
    assert [m.module for m in aff_fe] == ["roots/frontend"]

    planned_records.clear()
    plan_res = plan_affected_modules(test_repo_acceptance, aff_fe, planner=mock_planner)
    assert planned_records == ["roots/frontend"]
    assert len(plan_res["planned"]) == 1

    # Case 3: Changing non-terraform file (e.g. docs/README.md) affects NO root modules
    changed_docs = ["docs/README.md"]
    aff_docs = graph.affected_roots(changed_docs)
    assert len(aff_docs) == 0

    planned_records.clear()
    plan_res = plan_affected_modules(test_repo_acceptance, aff_docs, planner=mock_planner)
    assert len(planned_records) == 0
    assert len(plan_res["planned"]) == 0

    # Case 4: Changing exceptions or answers file affects root module but replan=False
    exc_file = test_repo_acceptance / "roots" / "app" / "attack-path-exceptions.yaml"
    exc_file.write_text("exceptions: []\n", encoding="utf-8")
    aff_exc = graph.affected_roots(["roots/app/attack-path-exceptions.yaml"])
    assert len(aff_exc) == 1
    assert aff_exc[0].module == "roots/app"
    assert aff_exc[0].replan is False

    planned_records.clear()
    plan_res = plan_affected_modules(test_repo_acceptance, aff_exc, planner=mock_planner)
    # Because replan is False, planner is NOT invoked
    assert len(planned_records) == 0
    assert len(plan_res["planned"]) == 0
    assert len(plan_res["gate_only"]) == 1


def test_transitive_nested_module_dependencies(tmp_path: Path):
    """Transitive module changes propagate to all consuming root modules."""
    repo = tmp_path / "repo_transitive"
    repo.mkdir()

    root_payments = repo / "roots" / "payments"
    root_auth = repo / "roots" / "auth"
    mod_billing = repo / "modules" / "billing"
    mod_network = repo / "modules" / "network"

    for d in (root_payments, root_auth, mod_billing, mod_network):
        d.mkdir(parents=True)

    # mod_network/main.tf
    (mod_network / "main.tf").write_text('resource "aws_vpc" "v" {}', encoding="utf-8")

    # mod_billing/main.tf consumes mod_network
    (mod_billing / "main.tf").write_text(
        'module "net" { source = "../network" }\nresource "aws_sqs_queue" "q" {}',
        encoding="utf-8",
    )

    # root_payments consumes mod_billing (transitively consumes mod_network)
    (root_payments / "main.tf").write_text(
        'module "bill" { source = "../../modules/billing" }',
        encoding="utf-8",
    )

    # root_auth consumes mod_network directly
    (root_auth / "main.tf").write_text(
        'module "net" { source = "../../modules/network" }',
        encoding="utf-8",
    )

    graph = ModuleGraph(repo)
    assert "modules/network" in graph.modules["roots/payments"].transitive_dependencies
    assert "modules/network" in graph.modules["roots/auth"].transitive_dependencies

    # Modifying mod_network affects BOTH root_payments and root_auth
    aff_net = graph.affected_roots(["modules/network/main.tf"])
    assert {m.module for m in aff_net} == {"roots/auth", "roots/payments"}

    # Modifying mod_billing affects ONLY root_payments
    aff_bill = graph.affected_roots(["modules/billing/main.tf"])
    assert {m.module for m in aff_bill} == {"roots/payments"}


def test_sharded_nightly_sweep(tmp_path: Path):
    """Sharding partitions modules deterministically with no missing or overlapping modules."""
    repo = tmp_path / "repo_shards"
    repo.mkdir()

    roots = [f"roots/service_{i:02d}" for i in range(1, 11)]
    for r in roots:
        d = repo / r
        d.mkdir(parents=True)
        (d / "main.tf").write_text('resource "aws_instance" "i" {}', encoding="utf-8")

    graph = ModuleGraph(repo)
    assert len(graph.root_paths) == 10

    # Sharded sweep matrix for 4 shards
    matrix = graph.generate_matrix(fmt="github", shards=4, all_roots=True)
    assert "include" in matrix
    assert len(matrix["include"]) == 4

    all_sharded_modules = []
    for entry in matrix["include"]:
        assert entry["total_shards"] == 4
        all_sharded_modules.extend(entry["modules"])

    # Disjoint union covers all 10 modules with zero duplicates
    assert sorted(all_sharded_modules) == sorted(roots)
    assert len(set(all_sharded_modules)) == 10

    # Individual shard retrieval
    s1 = graph.generate_matrix(fmt="github", shards=4, shard_index=1, all_roots=True)
    s2 = graph.generate_matrix(fmt="github", shards=4, shard_index=2, all_roots=True)
    s1_mods = [item["module"] for item in s1["include"]]
    s2_mods = [item["module"] for item in s2["include"]]
    assert len(set(s1_mods).intersection(set(s2_mods))) == 0


def test_matrix_output_formats(test_repo_acceptance: Path):
    """Test github, gitlab, json, and text formats."""
    graph = ModuleGraph(test_repo_acceptance)
    aff = graph.affected_roots(["modules/shared_vpc/main.tf"])

    # GitHub format
    gh = graph.generate_matrix(aff, fmt="github")
    assert "include" in gh
    assert len(gh["include"]) == 2
    assert gh["include"][0]["module"] == "roots/app"
    assert gh["include"][0]["replan"] is True

    # GitLab format
    gl = graph.generate_matrix(aff, fmt="gitlab")
    assert isinstance(gl, list)
    assert len(gl) == 2
    assert gl[0]["MODULE"] == "roots/app"
    assert gl[0]["REPLAN"] == "true"

    # JSON format
    js = graph.generate_matrix(aff, fmt="json")
    assert isinstance(js, dict)
    assert js["count"] == 2
    assert js["has_affected"] is True
    assert js["affected_roots"] == ["roots/app", "roots/database"]

    # Text format
    txt = graph.generate_matrix(aff, fmt="text")
    assert txt == ["roots/app", "roots/database"]


def test_cli_matrix_command(test_repo_acceptance: Path, capsys):
    """Test tapm matrix CLI subcommand with different arguments."""
    # 1. Test --changed
    main(["matrix", str(test_repo_acceptance), "--changed", "modules/shared_vpc/main.tf", "--format", "json"])
    out, _ = capsys.readouterr()
    data = json.loads(out)
    assert data["count"] == 2
    assert data["affected_roots"] == ["roots/app", "roots/database"]

    # 2. Test --all --format github
    main(["matrix", str(test_repo_acceptance), "--all", "--format", "github"])
    out, _ = capsys.readouterr()
    gh_data = json.loads(out)
    assert len(gh_data["include"]) == 3

    # 3. Test sharding: --all --shards 2
    main(["matrix", str(test_repo_acceptance), "--all", "--shards", "2", "--format", "json"])
    out, _ = capsys.readouterr()
    shard_data = json.loads(out)
    assert shard_data["shards"] == 2
    assert len(shard_data["matrix"]["include"]) == 2


def test_cli_matrix_plan_flag(test_repo_acceptance: Path, tmp_path: Path):
    """Test tapm matrix --plan execution."""
    out_dir = tmp_path / "plan_out"
    dummy_plans = []

    # Monkeypatch plan_affected_modules planner to record execution
    import tapm.terraform.matrix as matrix_mod

    orig_plan_affected = matrix_mod.plan_affected_modules

    def fake_plan_affected(*args, **kwargs):
        kwargs["planner"] = lambda m, p: {"status": "ok", "path": str(p)}
        return orig_plan_affected(*args, **kwargs)

    matrix_mod.plan_affected_modules = fake_plan_affected
    try:
        main([
            "matrix",
            str(test_repo_acceptance),
            "--changed",
            "roots/frontend/main.tf",
            "--plan",
            "--out-dir",
            str(out_dir),
            "--format",
            "json",
        ])
    finally:
        matrix_mod.plan_affected_modules = orig_plan_affected


def test_github_output_env_var(test_repo_acceptance: Path, tmp_path: Path, monkeypatch):
    """Verify that $GITHUB_OUTPUT receives matrix outputs when running in GitHub Actions."""
    gh_out_file = tmp_path / "gh_output.txt"
    gh_out_file.touch()
    monkeypatch.setenv("GITHUB_OUTPUT", str(gh_out_file))

    main(["matrix", str(test_repo_acceptance), "--changed", "roots/app/main.tf", "--format", "github"])

    content = gh_out_file.read_text(encoding="utf-8")
    assert "matrix=" in content
    assert "count=1" in content
    assert "has_affected=true" in content
