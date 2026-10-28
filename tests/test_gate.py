"""The PR check at each adoption level, accepted risks, the canary and the counts-only metrics (kit/)."""

from __future__ import annotations

import csv
import datetime as dt
import json
import shutil

import pytest
import yaml

from conftest import DEMO, FIXTURES, ROOT, fixture_dirs

from tapm.gate import canary, canary_expectation, draft_exceptions, evaluate, load_exceptions, markdown
from tapm.measure import fill_worksheet, run_counts, summarize

TODAY = dt.date(2026, 11, 5)


@pytest.fixture(scope="module")
def paths(demo_run):
    return [p.to_json() for p in demo_run.paths]


def accept(**kw):
    e = {"id": "RISK-042", "entry": "internet", "target": "aws_s3_bucket.customer_data", "owner": "payments-platform",
         "reason": "WAF blocks SSRF until the SDK upgrade", "expires": "2026-12-01"}
    e.update(kw)
    return e


def test_observe_and_recommend_never_fail_but_say_what_would_block(paths):
    for level in ("observe", "recommend"):
        g = evaluate(paths, [], level=level, today=TODAY)
        assert g["decision"] == "pass"
        assert g["without_decision"] == 1 and g["paths"][0]["decision"] == "would_block"


def test_validate_blocks_a_path_without_a_decision_and_passes_an_accepted_one(paths):
    assert evaluate(paths, [], level="validate", today=TODAY)["decision"] == "fail"
    g = evaluate(paths, [accept()], level="validate", today=TODAY)
    assert g["decision"] == "pass" and g["accepted"] == 1 and g["paths"][0]["exception"] == "RISK-042"


def test_threshold_leaves_lower_priority_paths_alone(paths):
    low = [{**p, "priority": "medium"} for p in paths]
    assert evaluate(low, [], level="prevent", fail_on="high", today=TODAY)["decision"] == "pass"
    assert evaluate(low, [], level="prevent", fail_on="medium", today=TODAY)["decision"] == "fail"


def test_an_accepted_risk_matches_by_entry_target_and_via_never_by_path_number(paths):
    renumbered = [{**p, "id": "PATH-007", "key": "different"} for p in paths]
    assert evaluate(renumbered, [accept()], level="validate", today=TODAY)["decision"] == "pass"
    assert evaluate(paths, [accept(via=["aws_instance.app"])], level="validate", today=TODAY)["decision"] == "pass"
    elsewhere = evaluate(paths, [accept(via=["aws_instance.other"])], level="validate", today=TODAY)
    assert elsewhere["decision"] == "fail"
    assert evaluate(paths, [accept(target="aws_s3_bucket.reports")], level="validate", today=TODAY)["decision"] == "fail"


def test_expired_long_or_unfinished_acceptances_do_not_count(paths):
    cases = {
        "expired": accept(expires="2026-11-01"),
        "too long": accept(expires="2027-06-01"),
        "todo owner": accept(owner="TODO"),
        "no reason": accept(reason=""),
        "bad date": accept(expires="next quarter"),
    }
    for name, e in cases.items():
        g = evaluate(paths, [e], level="validate", today=TODAY)
        assert g["decision"] == "fail", name
        assert g["exceptions"][0]["state"] in ("expired", "invalid"), name
        assert g["exceptions"][0]["problems"], name


def test_prevent_needs_a_second_person_and_a_compensating_control(paths):
    base = accept(expires="2026-11-20")
    assert evaluate(paths, [base], level="prevent", today=TODAY)["decision"] == "fail"
    same = {**base, "compensating_control": "WAF rule 123", "approved_by": "payments-platform"}
    g = evaluate(paths, [same], level="prevent", today=TODAY)
    assert g["decision"] == "fail" and any("other than the owner" in p for p in g["exceptions"][0]["problems"])
    ok = {**same, "approved_by": "appsec-lead"}
    assert evaluate(paths, [ok], level="prevent", today=TODAY)["decision"] == "pass"
    assert evaluate(paths, [{**ok, "expires": "2026-12-20"}], level="prevent", today=TODAY)["decision"] == "fail"


def test_an_acceptance_for_a_fixed_path_is_reported_as_unused(paths):
    g = evaluate(paths, [accept(), accept(id="RISK-9", target="aws_s3_bucket.gone")], level="validate", today=TODAY)
    assert g["decision"] == "pass"
    assert {e["id"]: e["state"] for e in g["exceptions"]} == {"RISK-042": "valid", "RISK-9": "unused"}


def test_a_broken_exceptions_file_fails_the_blocking_levels_only(tmp_path, paths):
    f = tmp_path / "attack-path-exceptions.yaml"
    f.write_text("exceptions: [unclosed\n")
    entries, problems = load_exceptions(f)
    assert entries == [] and problems
    assert evaluate(paths, entries, level="recommend", today=TODAY, file_problems=problems)["decision"] == "pass"
    assert evaluate(paths, [accept()], level="validate", today=TODAY, file_problems=problems)["decision"] == "fail"
    assert load_exceptions(tmp_path / "missing.yaml") == ([], [])


def test_the_draft_names_every_open_path_and_does_not_count_until_filled_in(paths):
    g = evaluate(paths, [], level="validate", today=TODAY)
    draft = draft_exceptions(g, paths)
    entries = yaml.safe_load(draft)["exceptions"]
    assert len(entries) == 1 and entries[0]["target"] == "aws_s3_bucket.customer_data"
    assert evaluate(paths, entries, level="validate", today=TODAY)["decision"] == "fail"  # TODOs never count


def test_gate_cli_writes_the_pr_section_and_exits_3_when_blocked(tmp_path, demo_run, capsys):
    from tapm.cli import main

    out = tmp_path / "run"
    shutil.copytree(demo_run.cfg.out_dir, out)
    main(["gate", str(out), "--level", "observe", "--today", str(TODAY)])
    assert "would block" in (out / "gate.md").read_text()
    with pytest.raises(SystemExit) as e:
        main(["gate", str(out), "--level", "validate", "--today", str(TODAY)])
    assert e.value.code == 3
    exc = tmp_path / "attack-path-exceptions.yaml"
    exc.write_text(yaml.safe_dump({"exceptions": [accept()]}))
    main(["gate", str(out), "--level", "validate", "--exceptions", str(exc), "--today", str(TODAY)])
    g = json.loads((out / "gate.json").read_text())
    assert g["decision"] == "pass" and "RISK-042" in (out / "gate.md").read_text()


def test_canary_expectations_come_from_the_gold_labels():
    assert canary_expectation(DEMO, "high") == "block"
    assert canary_expectation(FIXTURES / "001-clean", "high") == "pass"
    assert canary_expectation(FIXTURES / "013-count", "high") == "pass"  # its paths are medium
    assert canary_expectation(FIXTURES / "013-count", "medium") == "block"


def test_the_check_agrees_with_the_gold_labels_on_every_fixture(tmp_path):
    r = canary(fixture_dirs(), level="prevent", fail_on="high", workdir=tmp_path)
    assert r["failed"] == 0, [c for c in r["canaries"] if c["result"] != "ok"]
    assert {c["expect"] for c in r["canaries"]} == {"block", "pass"}


def test_a_canary_whose_result_differs_from_its_expectation_is_a_control_failure(tmp_path):
    fx = tmp_path / "canary-006"
    shutil.copytree(DEMO, fx)
    (fx / "gold.yaml").unlink()
    (fx / "canary.yaml").write_text("expect: pass\n")
    r = canary([fx], level="prevent", fail_on="high", workdir=tmp_path / "work")
    assert r["failed"] == 1 and r["canaries"][0]["result"] == "false_block"


def test_measure_reports_counts_only(tmp_path, demo_run):
    out = tmp_path / "run"
    shutil.copytree(demo_run.cfg.out_dir, out)
    (out / "gate.json").write_text(json.dumps(evaluate([p.to_json() for p in demo_run.paths], [accept()],
                                                       level="validate", today=TODAY)))
    rec = run_counts(out)
    assert rec["paths"] == 1 and rec["paths_in_scope"] == 1 and rec["accepted"] == 1 and rec["exceptions_valid"] == 1
    assert rec["scanner_findings"] == 40
    names = {n for p in demo_run.paths for n in p.nodes}
    assert not any(n in json.dumps(rec) for n in names)  # nothing from the plan leaves `tapm measure`
    s = summarize([out, out])
    assert s["runs"] == 2 and s["metrics"]["M3"]["value"] == 2 and s["metrics"]["M6"]["value"] == 100.0


def test_measure_fills_the_kit_worksheet(tmp_path):
    ws = tmp_path / "baseline-worksheet.csv"
    shutil.copyfile(ROOT / "kit" / "baseline-worksheet.csv", ws)
    s = summarize([ROOT / "conference-snapshot"])
    n = fill_worksheet(ws, s, "baseline", on=TODAY)
    rows = {r["metric_id"]: r for r in csv.DictReader(ws.open())}
    assert n >= 5
    assert rows["M1"]["baseline_value"] == "162" and rows["M1"]["baseline_date"] == str(TODAY)
    assert rows["M2"]["baseline_value"] == "9"
    assert rows["M8"]["baseline_value"] == ""  # manual metrics stay for people to fill


def dispute(**kw):
    e = {"id": "DISPUTE-001", "disposition": "not_reachable", "entry": "internet",
         "target": "aws_s3_bucket.customer_data", "owner": "payments-platform",
         "reason": "Security group restricts ingress to corporate VPN; not reachable from internet"}
    e.update(kw)
    return e


def test_dispute_a_false_path_passes_gate_at_validate_and_prevent(paths):
    # Dispute treats path as decided: unblocks merge at validate and prevent
    gv = evaluate(paths, [dispute()], level="validate", today=TODAY)
    assert gv["decision"] == "pass"
    assert gv["not_reachable"] == 1
    assert gv["accepted"] == 0
    assert gv["without_decision"] == 0
    assert gv["paths"][0]["decision"] == "not_reachable"
    assert gv["paths"][0]["exception"] == "DISPUTE-001"

    # Prevent passes without compensating control (false paths have no residual risk to compensate)
    gp = evaluate(paths, [dispute()], level="prevent", today=TODAY)
    assert gp["decision"] == "pass"
    assert gp["not_reachable"] == 1

    # PR markdown reflects dispute
    md = markdown(gv)
    assert "Disputed false paths: DISPUTE-001" in md
    assert "disputed as not reachable (DISPUTE-001)" in md


def test_dispute_validation_rules(paths):
    # Missing required fields
    for field in ("id", "entry", "target", "owner", "reason"):
        bad = dispute()
        del bad[field]
        g = evaluate(paths, [bad], level="validate", today=TODAY)
        assert g["decision"] == "fail"
        assert any(f"missing '{field}'" in p for p in g["exceptions"][0]["problems"])

    # TODO values not accepted
    g_todo = evaluate(paths, [dispute(owner="TODO team", reason="TODO fill in")], level="validate", today=TODAY)
    assert g_todo["decision"] == "fail"
    assert any("owner" in p for p in g_todo["exceptions"][0]["problems"])

    # Unknown disposition
    g_unk = evaluate(paths, [dispute(disposition="ignore_finding")], level="validate", today=TODAY)
    assert g_unk["decision"] == "fail"
    assert any("unknown disposition" in p for p in g_unk["exceptions"][0]["problems"])

    # Optional expiry is honored if provided
    g_exp = evaluate(paths, [dispute(expires="2026-11-01")], level="validate", today=TODAY)
    assert g_exp["decision"] == "fail"
    assert g_exp["exceptions"][0]["state"] == "expired"

    # Unused dispute reported if path does not exist in plan
    g_unused = evaluate(paths, [dispute(target="aws_s3_bucket.nonexistent")], level="validate", today=TODAY)
    assert g_unused["decision"] == "fail"  # original path still unhandled
    assert g_unused["exceptions"][0]["state"] == "unused"


def test_dispute_counted_into_m8_and_reported_separately(tmp_path, demo_run):
    from tapm.gate import markdown

    out = tmp_path / "run"
    shutil.copytree(demo_run.cfg.out_dir, out)
    g_data = evaluate([p.to_json() for p in demo_run.paths], [dispute()], level="validate", today=TODAY)
    (out / "gate.json").write_text(json.dumps(g_data))
    (out / "gate.md").write_text(markdown(g_data))

    rec = run_counts(out)
    assert rec["paths"] == 1
    assert rec["paths_in_scope"] == 1
    assert rec["accepted"] == 0
    assert rec["not_reachable"] == 1
    assert rec["without_decision"] == 0
    assert rec["exceptions_total"] == 0  # accepted risks total is 0
    assert rec["disputes_total"] == 1
    assert rec["disputes_valid"] == 1

    s = summarize([out])
    assert s["metrics"]["M3"]["value"] == 1
    assert s["metrics"]["M5"]["value"] == 0
    assert s["metrics"]["M6"]["value"] == 0.0  # M6 accepted-risk coverage NOT inflated
    assert s["metrics"]["M8"]["value"] == 100.0  # M8 false-path rate counted: 1/1 = 100.0%
    assert s["metrics"]["M8"]["n"] == "1/1"

