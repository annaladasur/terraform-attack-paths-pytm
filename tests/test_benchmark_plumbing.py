"""Tests for W0.1: benchmark plumbing for real backends, model-mismatch check, and fallback behavior."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from tapm.ai.harness import run_ai
from tapm.ai.llm import AnthropicLLM, CassetteLLM, OllamaLLM, OpenAILLM, SimulatedLLM, make_llm
from tapm.ai.remediate import run_remediation
from tapm.cli import build_parser
from tapm.eval.report import render
from tapm.eval.runner import run_benchmark, run_manifest, summarise


def test_recorded_backend_fails_without_fallback_on_missing_cassette(tmp_path):
    """When kind=='recorded' and no cassette exists, make_llm fails instead of silently falling back."""
    llm = make_llm("recorded", None, tmp_path / "empty_cassettes")
    with pytest.raises(FileNotFoundError, match="no cassette"):
        llm.complete("path_narrator", "sys", "user", {})


def test_recorded_backend_allows_explicit_fallback(tmp_path):
    """When explicit fallback is provided, missing cassette delegates to fallback."""
    llm = make_llm("recorded", None, tmp_path / "empty_cassettes", fallback=SimulatedLLM())
    res = llm.complete("unsafe_reviewer", "sys", "user", {})
    assert res.backend == "simulated"


def test_anthropic_model_mismatch_raises():
    """Answering model differing from requested model fails immediately."""
    mock_anthropic = MagicMock()
    with patch.dict("sys.modules", {"anthropic": mock_anthropic}):
        llm = AnthropicLLM(model="test-requested-model")
        mock_resp = MagicMock()
        mock_resp.model = "test-other-model"
        mock_resp.stop_reason = "end_turn"
        mock_resp.content = [MagicMock(type="text", text="{}")]
        llm.client = MagicMock()
        llm.client.beta.messages.create.return_value = mock_resp

        with pytest.raises(RuntimeError, match="differs from requested"):
            llm.complete("path_narrator", "sys", "user", {})


def test_openai_model_mismatch_raises():
    """OpenAI answering model differing from requested model fails immediately."""
    mock_openai = MagicMock()
    with patch.dict("sys.modules", {"openai": mock_openai}):
        llm = OpenAILLM(model="test-requested-model")
        mock_resp = MagicMock()
        mock_resp.model = "test-other-model"
        mock_resp.choices = [MagicMock(message=MagicMock(content="{}"), finish_reason="stop")]
        mock_resp.usage = MagicMock(prompt_tokens=10, completion_tokens=5)
        llm.client = MagicMock()
        llm.client.chat.completions.create.return_value = mock_resp

        with pytest.raises(RuntimeError, match="differs from requested"):
            llm.complete("path_narrator", "sys", "user", {})


def test_ollama_model_mismatch_raises():
    """Ollama answering model differing from requested model fails immediately."""
    llm = OllamaLLM(model="test-requested-model:v1")
    fake_body = json.dumps({"model": "test-other-model:v1", "message": {"content": "{}"}}).encode()
    mock_conn = MagicMock()
    mock_conn.read.return_value = fake_body
    mock_conn.__enter__.return_value = mock_conn

    with patch("urllib.request.urlopen", return_value=mock_conn):
        with pytest.raises(RuntimeError, match="differs from requested"):
            llm.complete("path_narrator", "sys", "user", {})


def test_ollama_sets_num_ctx_and_seed():
    """Ollama requests must include num_ctx and seed in options to avoid silent truncation."""
    llm = OllamaLLM(model="test-model:v1", num_ctx=32768, seed=1337)
    fake_body = json.dumps({"model": "test-model:v1", "message": {"content": "{}"}}).encode()
    mock_conn = MagicMock()
    mock_conn.read.return_value = fake_body
    mock_conn.__enter__.return_value = mock_conn

    with patch("urllib.request.urlopen", return_value=mock_conn) as mock_urlopen:
        llm.complete("path_narrator", "sys", "user", {})
        req = mock_urlopen.call_args[0][0]
        data = json.loads(req.data.decode())
        assert data["options"]["num_ctx"] == 32768
        assert data["options"]["seed"] == 1337
        assert data["options"]["temperature"] == 0


def test_cassette_model_mismatch_raises(tmp_path):
    """Replaying a cassette with a different recorded model raises RuntimeError."""
    cass_dir = tmp_path / "cassettes"
    llm_dir = cass_dir / "llm" / "path_narrator"
    llm_dir.mkdir(parents=True)
    cassette_data = {
        "agent": "path_narrator",
        "backend": "anthropic",
        "model": "test-recorded-model",
        "text": "{}",
    }
    llm = CassetteLLM(cass_dir, model="test-requested-model")
    key = llm.key("path_narrator", None, "user")
    (llm_dir / f"{key}.json").write_text(json.dumps(cassette_data))

    with pytest.raises(RuntimeError, match="in cassette differs from requested"):
        llm.complete("path_narrator", "sys", "user", {})


def test_bench_cli_flags():
    """tapm bench parser accepts --llm, --decision, --model, --max-paths, and --no-fallback."""
    p = build_parser()
    args = p.parse_args(["bench", "--llm", "recorded", "--decision", "typesafe", "--model", "custom-model", "--max-paths", "2"])
    assert args.llm == "recorded"
    assert args.jev == "typesafe"
    assert args.model == "custom-model"
    assert args.max_paths == 2
    assert args.no_fallback is True


def test_tier2_and_terrara_cli_flags():
    """tapm tier2 and terrara parsers accept LLM, decision, model, and max-paths flags."""
    p = build_parser()
    t2_args = p.parse_args(["tier2", "--llm", "simulated", "--decision", "local", "--max-paths", "1"])
    assert t2_args.llm == "simulated"
    assert t2_args.jev == "local"
    assert t2_args.max_paths == 1

    tb_args = p.parse_args(["terrara", "--llm", "recorded", "--decision", "typesafe", "--model", "my-model"])
    assert tb_args.llm == "recorded"
    assert tb_args.jev == "typesafe"
    assert tb_args.model == "my-model"


def test_run_ai_respects_max_paths(demo_run, tmp_path):
    """run_ai caps path annotation to max_paths."""
    out_all = run_ai(demo_run, {"llm": "simulated", "jev": "local", "cassette_dir": str(tmp_path)})
    out_capped = run_ai(demo_run, {"llm": "simulated", "jev": "local", "cassette_dir": str(tmp_path), "max_paths": 1})
    assert len(out_capped["decisions"]) <= 1
    assert len(out_capped["annotations"]) <= len(out_all["annotations"])


def test_report_states_backend_for_ai_numbers():
    """Report markdown explicitly labels AI numbers with their backend."""
    rows = [
        {
            "case_id": "006-test",
            "repo": "synthetic",
            "commit": "",
            "resources": 10,
            "edges": 12,
            "iam_edges": 3,
            "scanner_findings": 5,
            "expected_paths": 1,
            "predicted_paths": 1,
            "true_positive_paths": 1,
            "false_positive_paths": 0,
            "false_negative_paths": 0,
            "runtime_ms": 150,
            "llm_calls": 3,
            "jev_calls": 2,
            "cost_usd": 0.0,
            "unsupported_annotations": 0,
            "checkov_findings": 2,
            "tfsec_findings": 2,
            "trivy_findings": 1,
            "pytm_threats": 5,
            "edge_tp": 10,
            "edge_fp": 0,
            "edge_fn": 0,
            "iam_expected": 2,
            "iam_correct": 2,
            "false_paths_reported": 0,
            "replay_identical": "10/10",
            "ai_backend": "test_backend_live",
            "ai_generated": 3,
            "ai_accepted": 3,
            "ai_rejected": 0,
            "ai_human_review": 0,
            "checkov_hops_covered": 1,
            "tfsec_hops_covered": 1,
            "trivy_hops_covered": 1,
            "gold_path_hops": 3,
            "pytm_generic": 5,
            "pytm_confirmed": 2,
            "pytm_mitigated": 0,
            "pytm_needs_app_team": 3,
            "pytm_ruled_out": 0,
            "pytm_pack": 0,
            "pytm_hops_covered": 2,
            "pytm_pack_hops_covered": 2,
            "rem_paths": 1,
            "rem_break": 1,
            "rem_downgrade_only": 0,
            "rem_no_fix": 0,
            "rem_attempts": 1,
            "rem_rejected": 0,
            "rem_unverified": 0,
            "rem_whatif_checked": 1,
            "rem_whatif_agree": 1,
        }
    ]
    s = summarise(rows)
    assert s["ai"]["backend"] == "test_backend_live"
    assert "test_backend_live" in s["ai"]["backends"]


def test_anthropic_fails_without_model():
    """AnthropicLLM fails closed if no model is passed and TAPM_ANTHROPIC_MODEL is not set."""
    mock_anthropic = MagicMock()
    with patch.dict("sys.modules", {"anthropic": mock_anthropic}), patch.dict("os.environ", {}, clear=True):
        with pytest.raises(RuntimeError, match="set --model or TAPM_ANTHROPIC_MODEL"):
            AnthropicLLM()


def test_cassette_fails_when_recorded_model_is_missing_and_model_requested(tmp_path):
    """Replaying a cassette without a model recorded fails if the caller explicitly requested a model."""
    cass_dir = tmp_path / "cassettes"
    llm_dir = cass_dir / "llm" / "path_narrator"
    llm_dir.mkdir(parents=True)
    cassette_data = {
        "agent": "path_narrator",
        "backend": "simulated",
        "model": None,
        "text": "{}",
    }
    llm = CassetteLLM(cass_dir, model="test-requested-model")
    key = llm.key("path_narrator", None, "user")
    (llm_dir / f"{key}.json").write_text(json.dumps(cassette_data))

    with pytest.raises(RuntimeError, match="differs from requested"):
        llm.complete("path_narrator", "sys", "user", {})


def test_make_llm_unknown_backend_raises():
    """make_llm raises ValueError for unknown or unsupported backend strings."""
    with pytest.raises(ValueError, match="unknown or unsupported"):
        make_llm("invalid-backend", None, "/tmp")


def test_bench_tier2_terrara_support_llm_off():
    """bench, tier2, and terrara CLIs support --llm off and bench supports --out."""
    p = build_parser()
    args_b = p.parse_args(["bench", "--llm", "off", "--out", "/tmp/custom-bench"])
    assert args_b.llm == "off"
    assert args_b.out == "/tmp/custom-bench"

    args_t2 = p.parse_args(["tier2", "--llm", "off"])
    assert args_t2.llm == "off"

    args_tb = p.parse_args(["terrara", "--llm", "off"])
    assert args_tb.llm == "off"


def test_run_benchmark_with_custom_out_dir(tmp_path):
    """run_benchmark respects out_dir without touching evaluations/results/."""
    from tapm.util import PROJECT_ROOT

    custom_out = tmp_path / "custom_results"
    res = run_benchmark(PROJECT_ROOT, fixtures=["001"], replay_n=0, ai_cfg={"llm": "off"}, out_dir=custom_out)
    assert (custom_out / "results.csv").exists()
    assert (custom_out / "metrics.json").exists()
    assert (custom_out / "manifest.json").exists()
    assert res["summary"]["fixtures"] == 1
    assert res["summary"]["ai"]["backend"] == "off"


def test_run_remediation_respects_default_path_cap(demo_run):
    """run_remediation caps at 3 paths even when max_paths is explicitly None in cfg."""
    # Ensure demo_run has at least 1 path
    assert len(demo_run.paths) >= 1
    doc = run_remediation(demo_run, {"llm": "simulated", "max_paths": None})
    assert len(doc["paths"]) <= 3


def test_scanner_runner_empty_stdout_sets_error(tmp_path):
    """Empty scanner stdout sets status: 'error' and does not write tool.json."""
    from tapm.scanners.run import run_scanners
    import subprocess

    tf_dir = tmp_path / "tf"
    tf_dir.mkdir()
    (tf_dir / "main.tf").write_text("resource \"aws_s3_bucket\" \"b\" {}\n")
    out_dir = tmp_path / "baselines"

    fake_proc = subprocess.CompletedProcess(args=["checkov"], returncode=1, stdout="", stderr="ImportError: broken module")
    with patch("tapm.scanners.run._which", return_value="/fake/checkov"), \
         patch("tapm.scanners.run._version", return_value="3.3.20"), \
         patch("subprocess.run", return_value=fake_proc):
        v = run_scanners(tf_dir, out_dir, tools=("checkov",))

    assert v["checkov"]["status"] == "error"
    assert v["checkov"]["error"] == "empty output"
    assert not (out_dir / "checkov.json").exists()
    assert (out_dir / "versions.json").exists()


def test_scanner_runner_non_json_stdout_sets_error(tmp_path):
    """Non-JSON scanner stdout sets status: 'error' and does not write tool.json."""
    from tapm.scanners.run import run_scanners
    import subprocess

    tf_dir = tmp_path / "tf"
    tf_dir.mkdir()
    (tf_dir / "main.tf").write_text("resource \"aws_s3_bucket\" \"b\" {}\n")
    out_dir = tmp_path / "baselines"

    fake_proc = subprocess.CompletedProcess(args=["tfsec"], returncode=0, stdout="Fatal error: failed to parse", stderr="")
    with patch("tapm.scanners.run._which", return_value="/fake/tfsec"), \
         patch("tapm.scanners.run._version", return_value="v1.28.14"), \
         patch("subprocess.run", return_value=fake_proc):
        v = run_scanners(tf_dir, out_dir, tools=("tfsec",))

    assert v["tfsec"]["status"] == "error"
    assert v["tfsec"]["error"] == "invalid json"
    assert not (out_dir / "tfsec.json").exists()


def test_scanner_runner_null_stdout_sets_error(tmp_path):
    """Scanner output of literal 'null' sets status: 'error' and does not write tool.json."""
    from tapm.scanners.run import run_scanners
    import subprocess

    tf_dir = tmp_path / "tf"
    tf_dir.mkdir()
    (tf_dir / "main.tf").write_text("resource \"aws_s3_bucket\" \"b\" {}\n")
    out_dir = tmp_path / "baselines"

    fake_proc = subprocess.CompletedProcess(args=["checkov"], returncode=0, stdout="null\n", stderr="")
    with patch("tapm.scanners.run._which", return_value="/fake/checkov"), \
         patch("tapm.scanners.run._version", return_value="3.3.20"), \
         patch("subprocess.run", return_value=fake_proc):
        v = run_scanners(tf_dir, out_dir, tools=("checkov",))

    assert v["checkov"]["status"] == "error"
    assert v["checkov"]["error"] == "null output"
    assert not (out_dir / "checkov.json").exists()


def test_scanner_runner_version_mismatch_sets_version_mismatch(tmp_path):
    """Scanner version differing from pin sets status: 'version_mismatch' and does not run."""
    from tapm.scanners.run import run_scanners

    tf_dir = tmp_path / "tf"
    tf_dir.mkdir()
    (tf_dir / "main.tf").write_text("resource \"aws_s3_bucket\" \"b\" {}\n")
    out_dir = tmp_path / "baselines"

    with patch("tapm.scanners.run._which", return_value="/fake/trivy"), \
         patch("tapm.scanners.run._version", return_value="0.69.3"), \
         patch("subprocess.run") as mock_subproc:
        v = run_scanners(tf_dir, out_dir, tools=("trivy",))
        mock_subproc.assert_not_called()

    assert v["trivy"]["status"] == "version_mismatch"
    assert v["trivy"]["version"] == "0.69.3"
    assert v["trivy"]["pinned"] == "0.74.0"
    assert not (out_dir / "trivy.json").exists()


def test_validate_baseline_checks(tmp_path):
    """validate_baseline succeeds on valid baselines and raises RuntimeError on any failure."""
    from tapm.scanners.run import validate_baseline

    base = tmp_path / "base"
    base.mkdir()
    (base / "checkov.json").write_text("{}")
    (base / "tfsec.json").write_text("{}")
    (base / "trivy.json").write_text("{}")

    # Valid versions.json
    valid_versions = {
        "checkov": {"status": "ok", "version": "3.3.20", "pinned": "3.3.20"},
        "tfsec": {"status": "ok", "version": "v1.28.14", "pinned": "v1.28.14"},
        "trivy": {"status": "ok", "version": "0.74.0", "pinned": "0.74.0"},
    }
    (base / "versions.json").write_text(json.dumps(valid_versions))
    v = validate_baseline(base)
    assert v["checkov"]["status"] == "ok"

    # Status error raises
    valid_versions["checkov"]["status"] = "error"
    (base / "versions.json").write_text(json.dumps(valid_versions))
    with pytest.raises(RuntimeError, match="scanner 'checkov' is not ok"):
        validate_baseline(base)

    # Status version_mismatch raises
    valid_versions["checkov"]["status"] = "version_mismatch"
    (base / "versions.json").write_text(json.dumps(valid_versions))
    with pytest.raises(RuntimeError, match="scanner 'checkov' is not ok"):
        validate_baseline(base)

    # Missing scanner raises
    del valid_versions["checkov"]
    (base / "versions.json").write_text(json.dumps(valid_versions))
    with pytest.raises(RuntimeError, match="missing scanner 'checkov'"):
        validate_baseline(base)


def test_cmd_tier2_and_realworld_exit_non_zero_on_invalid_baseline(monkeypatch):
    """tapm tier2 and tapm realworld abort with non-zero exit when a baseline scanner is not ok."""
    from tapm.cli import cmd_tier2, cmd_realworld

    args_t2 = MagicMock()
    args_t2.cases = None
    args_t2.manifest = None
    args_t2.tag = "run"
    args_t2.heldout = False
    args_t2.llm = "off"

    with patch("tapm.eval.tier2.run_tier2", side_effect=RuntimeError("Baseline scanner checkov is not ok")):
        with pytest.raises(SystemExit):
            cmd_tier2(args_t2)

    args_rw = MagicMock()
    args_rw.cases = None
    args_rw.manifest = None
    args_rw.tag = "benign"

    with patch("tapm.eval.realworld.run_realworld", side_effect=RuntimeError("Baseline scanner trivy is not ok")):
        with pytest.raises(SystemExit):
            cmd_realworld(args_rw)


def test_get_pinned_terraform_enforces_version_and_rejects_mismatch():
    """get_pinned_terraform asserts exact 1.16.4 version and rejects off-pin binaries."""
    import subprocess
    from tapm.terraform.offline_plan import PINNED_TERRAFORM, get_pinned_terraform

    assert PINNED_TERRAFORM == "1.16.4"

    # Mismatch raises RuntimeError
    fake_proc_bad = subprocess.CompletedProcess(args=["terraform", "version"], returncode=0, stdout="Terraform v1.5.7\n")
    with patch("tapm.terraform.offline_plan.terraform_bin", return_value="/fake/bin/terraform"), \
         patch("subprocess.run", return_value=fake_proc_bad):
        with pytest.raises(RuntimeError, match="Terraform version mismatch: .* reports 1.5.7, expected pinned 1.16.4"):
            get_pinned_terraform()

    # Exact match succeeds
    fake_proc_good = subprocess.CompletedProcess(args=["terraform", "version"], returncode=0, stdout="Terraform v1.16.4\non darwin_arm64\n")
    with patch("tapm.terraform.offline_plan.terraform_bin", return_value="/opt/pinned/terraform"), \
         patch("subprocess.run", return_value=fake_proc_good):
        exe = get_pinned_terraform()
        assert exe == "/opt/pinned/terraform"

    # Missing binary raises RuntimeError
    with patch("tapm.terraform.offline_plan.terraform_bin", return_value=None):
        with pytest.raises(RuntimeError, match="Terraform binary not found"):
            get_pinned_terraform()


def test_plan_generators_use_get_pinned_terraform():
    """generate_heldout_plans and generate_realworld_plans import and require get_pinned_terraform."""
    import scripts.generate_heldout_plans as ghp
    import scripts.generate_realworld_plans as grp

    assert hasattr(ghp, "get_pinned_terraform")
    assert hasattr(grp, "get_pinned_terraform")
    assert ghp.PINNED_TERRAFORM == "1.16.4"
    assert grp.PINNED_TERRAFORM == "1.16.4"


def test_eval_metadata_collection():
    """get_eval_metadata collects tool versions, git shas, and command."""
    from tapm.eval.metadata import get_eval_metadata, get_eval_tool_versions, get_eval_git_shas

    tools = get_eval_tool_versions()
    assert tools["terraform"] == "1.16.4"
    assert tools["checkov"] == "3.3.20"
    assert tools["tfsec"] == "v1.28.14"
    assert tools["trivy"] == "0.74.0"

    shas = get_eval_git_shas()
    assert "code" in shas
    assert "gold" in shas
    assert len(shas["code"]) == 40 or shas["code"] == "unknown"

    meta = get_eval_metadata(tag="my-tag", command="tapm test")
    assert meta["tag"] == "my-tag"
    assert meta["command"] == "tapm test"
    assert meta["tool_versions"] == tools
    assert meta["git_sha"] == shas


def test_eval_commands_write_results_routing(tmp_path, monkeypatch):
    """cmd_tier2, cmd_realworld, cmd_strata pass write_results and route outputs accordingly."""
    from tapm.cli import cmd_tier2, cmd_realworld, cmd_strata

    captured_tier2 = {}
    def mock_run_tier2(*args, **kw):
        captured_tier2.update(kw)
        return {"summary": {"tag": kw.get("tag", "run")}}

    captured_rw = {}
    def mock_run_realworld(*args, **kw):
        captured_rw.update(kw)
        return {"summary": {"tag": kw.get("tag", "benign")}}

    captured_strata = {}
    def mock_gen_strata(*args, **kw):
        captured_strata.update(kw)
        return Path("/mock/strata.json")

    monkeypatch.setattr("tapm.eval.tier2.run_tier2", mock_run_tier2)
    monkeypatch.setattr("tapm.eval.realworld.run_realworld", mock_run_realworld)
    monkeypatch.setattr("tapm.eval.strata.generate_strata", mock_gen_strata)

    # 1. Default (no write_results)
    args = MagicMock()
    args.cases = None
    args.manifest = None
    args.tag = "run"
    args.heldout = False
    args.llm = "off"
    args.write_results = False
    cmd_tier2(args)
    assert captured_tier2["write_results"] is False

    args_rw = MagicMock()
    args_rw.cases = None
    args_rw.manifest = None
    args_rw.tag = "benign"
    args_rw.write_results = False
    cmd_realworld(args_rw)
    assert captured_rw["write_results"] is False

    args_st = MagicMock()
    args_st.dir = None
    args_st.out = None
    args_st.json = False
    args_st.write_results = False
    cmd_strata(args_st)
    assert captured_strata["write_results"] is False

    # 2. With write_results=True
    args.write_results = True
    cmd_tier2(args)
    assert captured_tier2["write_results"] is True

    args_rw.write_results = True
    cmd_realworld(args_rw)
    assert captured_rw["write_results"] is True

    args_st.write_results = True
    cmd_strata(args_st)
    assert captured_strata["write_results"] is True


def test_cli_subparsers_have_write_results_option():
    """tier2, realworld, strata subparsers expose --write-results flag."""
    from tapm.cli import build_parser

    parser = build_parser()
    subparsers_action = next(a for a in parser._actions if a.dest == "cmd")
    choices = subparsers_action.choices

    for cmd_name in ("tier2", "realworld", "strata"):
        sub = choices[cmd_name]
        action_names = [opt for act in sub._actions for opt in act.option_strings]
        assert "--write-results" in action_names, f"--write-results missing from {cmd_name}"


def test_strata_has_no_generated_at_and_report_is_idempotent():
    """strata.json omits volatile generated_at and report rendering is idempotent."""
    from tapm.eval.report import render
    from tapm.eval.strata import compute_strata

    data = compute_strata()
    assert "generated_at" not in data

    rendered_1 = render()
    rendered_2 = render()
    assert rendered_1 == rendered_2


def test_critic_script_exists_and_executable():
    """scripts/critic.sh is executable, valid bash syntax, and runs checks."""
    import os
    import subprocess
    from tapm.util import PROJECT_ROOT

    critic_sh = PROJECT_ROOT / "scripts" / "critic.sh"
    assert critic_sh.exists()
    assert os.access(critic_sh, os.X_OK)

    # bash -n syntax check
    res = subprocess.run(["bash", "-n", str(critic_sh)], capture_output=True, text=True)
    assert res.returncode == 0, f"bash -n failed: {res.stderr}"

    # Run individual passing checks
    res_run = subprocess.run(["bash", str(critic_sh), "C11", "C12", "C16"], capture_output=True, text=True)
    assert res_run.returncode == 0, f"critic.sh check failed: {res_run.stderr}\n{res_run.stdout}"
    assert "✓ All executed critic checks PASSED" in res_run.stdout


def test_critic_ci_workflow_valid_and_actions_pinned():
    """Verify .github/workflows/critic.yml runs make critic on PR to main and actions are pinned by SHA (Q2)."""
    import re
    import yaml
    from tapm.util import PROJECT_ROOT

    repo_root = PROJECT_ROOT if (PROJECT_ROOT / "release-manifest.json").exists() else PROJECT_ROOT.parent.parent
    critic_yml = repo_root / ".github" / "workflows" / "critic.yml"
    assert critic_yml.exists(), f"Missing {critic_yml}"

    data = yaml.safe_load(critic_yml.read_text(encoding="utf-8"))
    assert data["name"] == "critic"

    # Triggers on PR to main and push to main
    on_clause = data.get("on") or data.get(True)
    assert "pull_request" in on_clause
    assert "main" in on_clause["pull_request"]["branches"]

    # Runs make critic
    critic_job = data["jobs"]["critic"]
    steps = critic_job["steps"]
    run_steps = [s.get("run") for s in steps if "run" in s]
    assert any("make critic" in r for r in run_steps)

    # Every action in .github/workflows/*.yml is pinned by a full 40-character commit SHA
    sha_regex = re.compile(r"^[a-zA-Z0-9_\-\./]+@[0-9a-f]{40}$")
    workflows_dir = repo_root / ".github" / "workflows"
    for wf in workflows_dir.glob("*.yml"):
        wf_data = yaml.safe_load(wf.read_text(encoding="utf-8"))
        for job_name, job in wf_data.get("jobs", {}).items():
            for step in job.get("steps", []):
                uses = step.get("uses")
                if uses:
                    # Strip comments if any
                    uses_ref = uses.split("#")[0].strip()
                    assert sha_regex.match(uses_ref), f"Action '{uses}' in {wf.name} not pinned by 40-char SHA"
