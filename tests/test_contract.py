"""Contract validation tests ensuring code, CLI, documentation, and deck agree (A24, Check C11).

Verifies:
1. CLI subcommands and flags in tapm --help match canonical contract;
2. tapm report accepts artifacts-dir (no --fixture) and requires --file / --server for platform;
3. tapm gate levels are strictly observe, recommend, validate, prevent (pass is a verdict, not a level);
4. Analysis service endpoints match server.py (no /v1/analyze, no /v1/tasks, no SSE, no Prometheus);
5. Exception file is canonically attack-path-exceptions.yaml (not .tapm-exception.yml);
6. Demo repo branches are main, pr-42, fix, injection;
7. Scans docs, deck, kit, and plan for non-existent flags, endpoints, file names, and branch names.
"""

from __future__ import annotations

import argparse
from pathlib import Path
import re
import pytest

from tapm.cli import build_parser
from tapm.gate import LEVELS, EXCEPTIONS_FILE
from tapm.service.server import AnalysisRequestHandler, FORBIDDEN_ARTIFACT_NAMES

ROOT = Path(__file__).resolve().parents[1]
OWASP_ROOT = ROOT.parent
DOCS_DIR = ROOT / "docs"
CONTRACT_MD = DOCS_DIR / "contract.md"
DECK_BUILD_JS = OWASP_ROOT / "deck" / "build-deck.js"


def test_contract_document_exists_and_covers_required_sections():
    """docs/contract.md exists and contains all required canonical specification sections."""
    assert CONTRACT_MD.exists(), "docs/contract.md must exist"
    content = CONTRACT_MD.read_text(encoding="utf-8")

    # Required sections
    assert "# Interface Contract:" in content
    assert "## 1. Command-Line Interface (`tapm`)" in content
    assert "## 2. Analysis Service REST API (`tapm serve`)" in content
    assert "## 3. Adoption Levels vs Gate Verdicts (`tapm gate`)" in content
    assert "## 4. Risk Governance & Exception Format" in content
    assert "## 5. Demo Repository Branch Topology" in content

    # Key terms and specific AC checks
    assert "POST /v1/jobs" in content
    assert "GET /v1/jobs/{id}" in content
    assert "GET /v1/metrics" in content
    assert "attack-path-exceptions.yaml" in content
    assert "observe, recommend, validate, prevent" in content or "observe" in content
    assert "pr-42" in content
    assert "fix" in content
    assert "injection" in content


def test_cli_parser_subcommands_and_report_contract():
    """CLI parser exposes documented subcommands and enforces report contract (no --fixture)."""
    parser = build_parser()
    assert isinstance(parser, argparse.ArgumentParser)

    # Subparsers check
    subparsers_action = next(a for a in parser._actions if isinstance(a, argparse._SubParsersAction))
    choices = subparsers_action.choices

    expected_cmds = [
        "plan", "scan", "model", "paths", "story", "run", "explain", "inject",
        "gate", "measure", "canary", "enrich", "serve", "submit", "git-status",
        "git-comment", "report", "matrix", "tier2", "realworld", "strata",
        "bench", "terrara", "verify-precommit"
    ]
    for cmd in expected_cmds:
        assert cmd in choices, f"Missing CLI subcommand: {cmd}"

    # Report command contract
    report_parser = choices["report"]
    report_actions = {a.dest: a for a in report_parser._actions}

    # artifacts positional arg
    assert "artifacts" in report_actions, "tapm report must accept positional artifacts dir"
    # persona options
    assert "persona" in report_actions
    assert set(report_actions["persona"].choices) == {"platform", "developer", "appsec", "executive"}
    # platform file and server inputs
    assert "file" in report_actions
    assert "server" in report_actions
    # output formats
    assert "format" in report_actions
    assert set(report_actions["format"].choices) == {"markdown", "text", "json", "sarif"}

    # CRITICAL: There is NO --fixture flag on tapm report (finding F14)
    assert "fixture" not in report_actions, "tapm report must not have a --fixture flag"

    with pytest.raises(SystemExit):
        report_parser.parse_args(["--fixture", "006"])


def test_gate_adoption_levels_and_verdicts():
    """Gate adoption levels are strictly observe, recommend, validate, prevent; pass is a verdict (F24)."""
    assert LEVELS == ("observe", "recommend", "validate", "prevent"), f"Unexpected levels: {LEVELS}"
    assert "pass" not in LEVELS, "'pass' is an evaluation verdict, not an adoption level (Finding F24)"

    gate_parser = build_parser()._actions[1].choices["gate"]  # type: ignore[attr-defined]
    gate_actions = {a.dest: a for a in gate_parser._actions}
    assert "level" in gate_actions
    assert set(gate_actions["level"].choices) == {"observe", "recommend", "validate", "prevent"}
    assert "pass" not in gate_actions["level"].choices


def test_service_endpoints_match_contract():
    """Analysis service server.py handles exact documented endpoints and forbids plan downloads (F23)."""
    import inspect

    do_get_source = inspect.getsource(AnalysisRequestHandler.do_GET)
    do_post_source = inspect.getsource(AnalysisRequestHandler.do_POST)

    # Documented endpoints present
    assert '"/v1/metrics"' in do_get_source
    assert '"/v1/jobs"' in do_get_source
    assert r'"/v1/jobs/([^/]+)"' in do_get_source
    assert r'"/v1/jobs/([^/]+)/logs"' in do_get_source
    assert r'"/v1/jobs/([^/]+)/artifacts/(.+)"' in do_get_source
    assert '"/v1/jobs"' in do_post_source
    assert r'"/v1/jobs/([^/]+)/enrich"' in do_post_source

    # Non-existent endpoints from outdated briefs NOT present (Finding F23)
    assert "/v1/analyze" not in do_post_source
    assert "/v1/tasks" not in do_get_source
    assert "text/event-stream" not in do_get_source  # No SSE
    assert "prometheus" not in do_get_source.lower()  # No Prometheus format

    # Plan files strictly forbidden
    assert "FORBIDDEN_ARTIFACT_NAMES" in inspect.getsource(AnalysisRequestHandler._serve_artifact)
    assert "plan.json" in FORBIDDEN_ARTIFACT_NAMES


def test_canonical_exception_filename():
    """Canonical exception file is attack-path-exceptions.yaml (Finding F26)."""
    assert EXCEPTIONS_FILE == "attack-path-exceptions.yaml"
    assert EXCEPTIONS_FILE != ".tapm-exception.yml"


def test_canonical_demo_branches():
    """Demo repo seed script and bundle maintain canonical branches main, pr-42, fix, injection (F27)."""
    seed_script = ROOT / "examples" / "local-stack" / "seed-demo-repo.sh"
    assert seed_script.exists()
    seed_text = seed_script.read_text(encoding="utf-8")

    assert "main" in seed_text
    assert "pr-42" in seed_text
    assert "fix" in seed_text
    assert "injection" in seed_text


def test_scan_docs_and_kit_for_discrepancies():
    """Scan docs, kit, deck build, and active plans to ensure zero active mentions of phantom contracts."""
    files_to_scan = []

    # Include all markdown in docs/
    for p in DOCS_DIR.rglob("*.md"):
        files_to_scan.append(p)

    # Include kit markdown files
    kit_dir = OWASP_ROOT / "kit"
    if kit_dir.exists():
        for p in kit_dir.rglob("*.md"):
            files_to_scan.append(p)

    # Include examples
    examples_dir = ROOT / "examples"
    if examples_dir.exists():
        for p in examples_dir.rglob("*.md"):
            files_to_scan.append(p)

    # Include talk markdown files
    talk_dir = OWASP_ROOT / "talk"
    if talk_dir.exists():
        for p in talk_dir.rglob("*.md"):
            files_to_scan.append(p)

    # Include DEMO-BUILD-PLAN.md
    plan_file = OWASP_ROOT / "DEMO-BUILD-PLAN.md"
    if plan_file.exists():
        files_to_scan.append(plan_file)

    # Include deck/build-deck.js
    if DECK_BUILD_JS.exists():
        files_to_scan.append(DECK_BUILD_JS)

    for file_path in files_to_scan:
        text = file_path.read_text(encoding="utf-8")
        rel = file_path.relative_to(OWASP_ROOT)

        # 1. No tapm report --fixture
        if file_path != CONTRACT_MD:
            assert not re.search(r"tapm\s+report[^\n]*--fixture", text), (
                f"Found invalid 'tapm report --fixture' in {rel}"
            )

        # 2. No active reference to /v1/analyze as an endpoint
        assert "POST /v1/analyze" not in text, f"Found 'POST /v1/analyze' in {rel}"

        # 3. No active reference to /v1/tasks as an endpoint
        assert "GET /v1/tasks" not in text, f"Found 'GET /v1/tasks' in {rel}"

        # 4. No active reference to .tapm-exception.yml
        # (Exclude docs/contract.md itself where it documents resolving the finding)
        if file_path != CONTRACT_MD:
            assert ".tapm-exception.yml" not in text, f"Found '.tapm-exception.yml' in {rel}"

        # 5. No reference to pr-42-vulnerable or injection-test as active branch names
        if file_path != CONTRACT_MD:
            assert "pr-42-vulnerable" not in text, f"Found 'pr-42-vulnerable' in {rel}"
            assert "injection-test" not in text, f"Found 'injection-test' in {rel}"


def test_no_draft_pr_exemption_claim():
    """Verify zero claims of draft-PR exemption exist in docs, deck, kit, talk, and plans (A25, D5, F25)."""
    # 1. Verify gate parser --draft help text documents draft exception entries, not PR draft exemption
    gate_parser = build_parser()._actions[1].choices["gate"]  # type: ignore[attr-defined]
    gate_actions = {a.dest: a for a in gate_parser._actions}
    assert "draft" in gate_actions
    assert "print draft accepted-risk entries" in gate_actions["draft"].help
    assert "exempt" not in gate_actions["draft"].help.lower()
    assert "pull request" not in gate_actions["draft"].help.lower()

    # 2. Verify submit parser does NOT have a draft-PR exemption flag
    submit_parser = build_parser()._actions[1].choices["submit"]  # type: ignore[attr-defined]
    submit_actions = {a.dest: a for a in submit_parser._actions}
    assert "draft" not in submit_actions
    assert "exempt_draft" not in submit_actions

    # 3. Scan docs, kit, talk, deck, and plans: no mentions of draft-PR exemption
    disallowed_pattern = re.compile(r"(draft[\s-]+pr|pr[\s-]+draft)[\s-]+exempt", re.IGNORECASE)

    files_to_scan = []
    for p in DOCS_DIR.rglob("*.md"):
        files_to_scan.append(p)
    kit_dir = OWASP_ROOT / "kit"
    if kit_dir.exists():
        for p in kit_dir.rglob("*.md"):
            files_to_scan.append(p)
    talk_dir = OWASP_ROOT / "talk"
    if talk_dir.exists():
        for p in talk_dir.rglob("*.md"):
            files_to_scan.append(p)
    if DECK_BUILD_JS.exists():
        files_to_scan.append(DECK_BUILD_JS)

    for file_path in files_to_scan:
        text = file_path.read_text(encoding="utf-8")
        rel = file_path.relative_to(OWASP_ROOT)
        # contract.md documents that there is no draft-PR exemption; exclude that explanation
        if file_path == CONTRACT_MD:
            continue
        m = disallowed_pattern.search(text)
        assert m is None, f"Found forbidden draft-PR exemption claim in {rel}: {m.group(0)}"



def test_cli_overview_flags_match_parser_and_representative_forms():
    """Attendees must be able to use the documented contract against this CLI."""
    import argparse
    from tapm.cli import build_parser

    parser = build_parser()
    commands = next(action for action in parser._actions if isinstance(action, argparse._SubParsersAction)).choices
    overview = CONTRACT_MD.read_text().split("### 1.2", 1)[0]
    checked = 0
    for line in overview.splitlines():
        match = re.match(r"\| `([^`]+)` \|.*\| `([^`]+)` \|$", line)
        if not match:
            continue
        command, arguments = match.groups()
        assert command in commands
        documented = set(re.findall(r"--[a-z][a-z-]*", arguments))
        assert documented <= set(commands[command]._option_string_actions), (command, documented)
        checked += 1
    assert checked >= 20
    for argv in (["serve", "--token", "example"], ["measure", "artifacts/example", "--json"],
                 ["git-comment", "--repo", "owner/repo", "--pr", "1", "--body-file", "comment.md", "--marker", "example"],
                 ["tier2", "--heldout", "--tag", "replay"]):
        parser.parse_args(argv)
