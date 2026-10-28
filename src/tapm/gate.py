"""The pull-request check at each adoption level, risk acceptance with an owner and an expiry, and the canary that
proves the check still blocks what it should (kit/adoption-ladder.md).

    tapm run infra --plan plan.json --out attack-paths     # deterministic; never fails on its own
    tapm gate attack-paths --level validate                # the level decides whether CI fails (exit 3)

Levels:
  observe    record the paths and the counts ``tapm measure`` reads; never fails.
  recommend  as observe, and the report says which paths *would* block; never fails.
  validate   fails while a path at or above ``--fail-on`` has no decision. A decision is either a fix (the path is
             gone from the plan) or an accepted risk in ``attack-path-exceptions.yaml`` with an owner, a reason and
             an expiry at most 90 days out.
  prevent    as validate, but an accepted risk also needs a compensating control and ``approved_by``, someone other
             than the owner (put the file under CODEOWNERS), and runs at most 30 days.
Level 5, continuously validate, is ``tapm canary`` on a schedule plus ``tapm gate`` on the default branch, so an
accepted risk that expires shows up without waiting for a pull request.

An accepted risk names a path by its entry and target (and optionally nodes it must pass through), never by its
PATH-### number: path numbers follow the ranking and change when unrelated resources change.
"""

from __future__ import annotations

import datetime as dt
from pathlib import Path

LEVELS = ("observe", "recommend", "validate", "prevent")
BLOCKING = {"validate", "prevent"}
PRIORITY = {"low": 1, "medium": 2, "high": 3}
EXCEPTIONS_FILE = "attack-path-exceptions.yaml"
MAX_DAYS = {"observe": 90, "recommend": 90, "validate": 90, "prevent": 30}
VALID_DISPOSITIONS = ("accepted_risk", "not_reachable")
DEFAULT_DISPOSITION = "accepted_risk"
REQUIRED = ("id", "entry", "target", "owner", "reason", "expires")
REQUIRED_DISPUTE = ("id", "entry", "target", "owner", "reason")
TODO = "TODO"


# ------------------------------------------------------------------ accepted risks
def load_exceptions(path: str | Path | None) -> tuple[list[dict], list[str]]:
    """Entries of ``attack-path-exceptions.yaml`` and file-level problems. A missing file is an empty list."""
    import yaml

    if not path or not Path(path).exists():
        return [], []
    try:
        doc = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as e:
        return [], [f"{Path(path).name}: not valid YAML ({str(e).splitlines()[0]})"]
    if not isinstance(doc, dict) or not isinstance(doc.get("exceptions", []), list):
        return [], [f"{Path(path).name}: expected a top-level 'exceptions:' list"]
    return [e if isinstance(e, dict) else {"_raw": e} for e in doc.get("exceptions") or []], []


def _date(v) -> dt.date | None:
    if isinstance(v, dt.datetime):
        return v.date()
    if isinstance(v, dt.date):
        return v
    try:
        return dt.date.fromisoformat(str(v))
    except ValueError:
        return None


def check_exception(e: dict, level: str, today: dt.date) -> tuple[str, list[str]]:
    """(state, problems): state is valid, expired or invalid. Problems say what to fix, in the file's own words."""
    if "_raw" in e:
        return "invalid", ["each entry must be a mapping (id, entry, target, owner, reason, expires)"]
    disp = e.get("disposition", DEFAULT_DISPOSITION)
    if disp not in VALID_DISPOSITIONS:
        return "invalid", [f"unknown disposition {disp!r}; must be one of {VALID_DISPOSITIONS}"]

    if disp == "not_reachable":
        problems = [f"missing '{k}'" for k in REQUIRED_DISPUTE if not str(e.get(k) or "").strip()]
        problems += [f"'{k}' is still {TODO}" for k in ("owner", "reason")
                     if str(e.get(k) or "").strip().upper().startswith(TODO)]
        if e.get("via") is not None and not isinstance(e["via"], list):
            problems.append("'via' must be a list of resource addresses")
        expires = _date(e.get("expires")) if e.get("expires") else None
        if e.get("expires") and expires is None:
            problems.append(f"'expires' is not a date (YYYY-MM-DD): {e['expires']!r}")
        if expires and (expires - today).days > MAX_DAYS[level]:
            problems.append(f"expires {expires} is more than {MAX_DAYS[level]} days out; dispute for less and review it again")
        if level == "prevent":
            if e.get("approved_by") and str(e.get("approved_by")).strip() == str(e.get("owner") or "").strip():
                problems.append("'approved_by' must be someone other than the owner")
        if problems:
            return "invalid", problems
        if expires and expires < today:
            return "expired", [f"expired on {expires}"]
        return "valid", []

    problems = [f"missing '{k}'" for k in REQUIRED if not str(e.get(k) or "").strip()]
    problems += [f"'{k}' is still {TODO}" for k in ("owner", "reason", "approved_by", "compensating_control")
                 if str(e.get(k) or "").strip().upper().startswith(TODO)]
    if e.get("via") is not None and not isinstance(e["via"], list):
        problems.append("'via' must be a list of resource addresses")
    expires = _date(e.get("expires")) if e.get("expires") else None
    if e.get("expires") and expires is None:
        problems.append(f"'expires' is not a date (YYYY-MM-DD): {e['expires']!r}")
    if expires and (expires - today).days > MAX_DAYS[level]:
        problems.append(f"expires {expires} is more than {MAX_DAYS[level]} days out; accept for less and review it again")
    if level == "prevent":
        if not str(e.get("compensating_control") or "").strip():
            problems.append("missing 'compensating_control' (required at prevent)")
        if not str(e.get("approved_by") or "").strip():
            problems.append("missing 'approved_by' (required at prevent)")
        elif str(e.get("approved_by")).strip() == str(e.get("owner") or "").strip():
            problems.append("'approved_by' must be someone other than the owner")
    if problems:
        return "invalid", problems
    if expires < today:
        return "expired", [f"expired on {expires}"]
    return "valid", []


def covers(e: dict, path: dict) -> bool:
    return (str(e.get("entry")) == path["entry"] and str(e.get("target")) == path["target"]
            and all(v in path["nodes"] for v in (e.get("via") or []) if isinstance(e.get("via"), list)))


# ------------------------------------------------------------------ the check
def evaluate(paths: list[dict], exceptions: list[dict], *, level: str = "observe", fail_on: str = "high",
             today: dt.date | None = None, file_problems: list[str] | None = None) -> dict:
    """Decide every path at or above ``fail_on``: accepted (a valid exception covers it) or not. Whether a path
    without a decision fails the check depends on the level."""
    if level not in LEVELS:
        raise ValueError(f"level must be one of {LEVELS}")
    if fail_on not in PRIORITY:
        raise ValueError(f"fail_on must be one of {tuple(PRIORITY)}")
    today = today or dt.date.today()
    states = []
    for i, e in enumerate(exceptions):
        state, problems = check_exception(e, level, today)
        exp = _date(e.get("expires")) if isinstance(e, dict) and e.get("expires") else None
        disp = e.get("disposition", DEFAULT_DISPOSITION) if isinstance(e, dict) else DEFAULT_DISPOSITION
        states.append({"id": str(e.get("id") or f"entry {i + 1}"), "disposition": disp,
                       "state": state, "problems": problems,
                       "owner": e.get("owner") if isinstance(e, dict) else None,
                       "reason": e.get("reason") if isinstance(e, dict) else None,
                       "expires": str(exp) if exp else None,
                       "days_left": (exp - today).days if exp else None, "matches": []})
    rows = []
    for p in paths:
        in_scope = PRIORITY.get(p.get("priority"), 0) >= PRIORITY[fail_on]
        row = {k: p.get(k) for k in ("id", "key", "entry", "target", "priority", "status")}
        row["exception"] = None
        row["disposition"] = None
        for e, st in zip(exceptions, states):
            if "_raw" not in e and covers(e, p):
                st["matches"].append(p["id"])
                if st["state"] == "valid" and row["exception"] is None:
                    row["exception"] = st["id"]
                    row["disposition"] = st.get("disposition", DEFAULT_DISPOSITION)
        if not in_scope:
            row["decision"] = "below_threshold"
        elif row["exception"]:
            if row["disposition"] == "not_reachable":
                row["decision"] = "not_reachable"
            else:
                row["decision"] = "accepted"
        else:
            row["decision"] = "blocking" if level in BLOCKING else "would_block"
        rows.append(row)
    for st in states:
        if st["state"] == "valid" and not st["matches"]:
            st["state"] = "unused"
            if st.get("disposition") == "not_reachable":
                st["problems"] = ["covers no path in this plan: the disputed path is not in the plan, so remove the entry"]
            else:
                st["problems"] = ["covers no path in this plan: the path is fixed, so remove the entry"]
    problems = list(file_problems or [])
    blocking = [r for r in rows if r["decision"] == "blocking"]
    fail = level in BLOCKING and (bool(blocking) or bool(problems))
    return {
        "level": level, "fail_on": fail_on, "today": str(today), "decision": "fail" if fail else "pass",
        "paths_total": len(rows), "in_scope": sum(r["decision"] != "below_threshold" for r in rows),
        "accepted": sum(r["decision"] == "accepted" for r in rows),
        "not_reachable": sum(r["decision"] == "not_reachable" for r in rows),
        "without_decision": sum(r["decision"] in ("blocking", "would_block") for r in rows),
        "paths": rows, "exceptions": states, "problems": problems,
    }


def draft_exceptions(gate: dict, paths: list[dict], today: dt.date | None = None) -> str:
    """YAML entries for the paths that still need a decision. Every TODO must be replaced before the entry counts:
    at rollout this is how the paths already on the default branch get an owner instead of blocking every PR."""
    today = today or dt.date.fromisoformat(gate["today"])
    by_id = {p["id"]: p for p in paths}
    lines = ["exceptions:"]
    for r in gate["paths"]:
        if r["decision"] not in ("blocking", "would_block"):
            continue
        p = by_id[r["id"]]
        via = [n for n in p["nodes"][1:-1]]
        lines += [f"  - id: {TODO}-risk-id            # your ticket or risk register ID",
                  f"    # disposition: not_reachable # uncomment to dispute as false path (counted in M8)",
                  f"    entry: {p['entry']}",
                  f"    target: {p['target']}",
                  f"    via: [{', '.join(via)}]   # drop to accept every path between entry and target",
                  f"    owner: {TODO}                  # a named team or person",
                  f"    reason: {TODO}",
                  f"    compensating_control: {TODO}   # required at prevent",
                  f"    expires: {today + dt.timedelta(days=30)}       # at most 90 days (validate) or 30 (prevent); optional for not_reachable",
                  f"    # approved_by: someone other than the owner (required at prevent)"]
    return "\n".join(lines) + "\n" if len(lines) > 1 else ""


def markdown(gate: dict, draft: str = "") -> str:
    """The section a CI job posts on the pull request."""
    head = f"### Attack-path check · level **{gate['level']}** · threshold **{gate['fail_on']}**"
    n = gate["without_decision"]
    if gate["decision"] == "fail":
        verdict = f"**Blocked:** {n} path(s) at or above {gate['fail_on']} need a decision before merge."
    elif n and gate["level"] not in BLOCKING:
        verdict = f"**Would block at validate:** {n} path(s) at or above {gate['fail_on']} have no decision yet."
    else:
        verdict = f"**Pass:** every path at or above {gate['fail_on']} is fixed or accepted."
    out = [head, "", verdict]
    if gate["problems"]:
        out += [""] + [f"- ⚠ {p}" for p in gate["problems"]]
    decided = [r for r in gate["paths"] if r["decision"] != "below_threshold"]
    if decided:
        out += ["", "| Path | Priority | From → to | Decision |", "|---|---|---|---|"]
        say = {"accepted": "accepted risk {x}",
               "not_reachable": "disputed as not reachable ({x})",
               "blocking": "none yet: fix it, or accept it with an owner and an expiry",
               "would_block": "none yet (would block at validate)"}
        for r in decided:
            out.append(f"| {r['id']} | {r['priority']} | `{r['entry']}` → `{r['target']}` | "
                       f"{say[r['decision']].format(x=r['exception'])} |")
    notes = [e for e in gate["exceptions"] if e["state"] != "valid"]
    valid_risks = [e for e in gate["exceptions"] if e["state"] == "valid" and e.get("disposition") != "not_reachable"]
    valid_disputes = [e for e in gate["exceptions"] if e["state"] == "valid" and e.get("disposition") == "not_reachable"]
    if valid_risks:
        out += ["", "Accepted risks: " + "; ".join(f"{e['id']} (owner {e['owner']}, {e['days_left']} days left)"
                                                   for e in valid_risks)]
    if valid_disputes:
        out += ["", "Disputed false paths: " + "; ".join(f"{e['id']} (owner {e['owner']}, reason: {e.get('reason') or 'disputed'})"
                                                         for e in valid_disputes)]
    if notes:
        out += ["", f"`{EXCEPTIONS_FILE}` entries that don't count:"]
        out += [f"- {e['id']} ({e['state']}): {'; '.join(e['problems'])}" for e in notes]
    if draft:
        out += ["", f"<details><summary>Draft {EXCEPTIONS_FILE} entries (replace every TODO)</summary>", "",
                "```yaml", draft.rstrip(), "```", "</details>"]
    return "\n".join(out) + "\n"


# ------------------------------------------------------------------ Level 5: does the check still work?
DEFAULT_CANARIES = ("006", "013", "021", "001", "018", "020")


def canary_expectation(fx: Path, fail_on: str) -> str | None:
    """block or pass. From ``canary.yaml`` (``expect: block|pass``) if present, else from the fixture's gold labels."""
    import yaml

    if (fx / "canary.yaml").exists():
        return (yaml.safe_load((fx / "canary.yaml").read_text()) or {}).get("expect")
    if (fx / "gold.yaml").exists():
        gold = yaml.safe_load((fx / "gold.yaml").read_text()) or {}
        hit = any(PRIORITY.get(p.get("priority"), 0) >= PRIORITY[fail_on] for p in gold.get("expected_paths") or [])
        return "block" if hit else "pass"
    return None


def canary(fixture_dirs: list[Path], *, level: str = "prevent", fail_on: str = "high", workdir: Path) -> dict:
    """Run each canary through the same check, with no accepted risks: a known-bad plan must block and a known-good
    plan must pass. A miss is a control failure (kit metric M15)."""
    from .cli import fixture_config
    from .pipeline import run_deterministic

    gate_level = level if level in BLOCKING else "validate"
    rows = []
    for fx in fixture_dirs:
        expect = canary_expectation(fx, fail_on)
        cfg = fixture_config(fx, str(workdir / fx.name), no_dfd=True)
        res = run_deterministic(cfg)
        g = evaluate([p.to_json() for p in res.paths], [], level=gate_level, fail_on=fail_on)
        got = "block" if g["decision"] == "fail" else "pass"
        rows.append({"canary": fx.name, "expect": expect, "got": got, "paths_in_scope": g["in_scope"],
                     "result": "ok" if expect == got else ("missed" if expect == "block" else "false_block")
                     if expect else "no_expectation"})
    failed = [r for r in rows if r["result"] in ("missed", "false_block", "no_expectation")]
    return {"level": gate_level, "fail_on": fail_on, "canaries": rows, "failed": len(failed),
            "control_failure_rate": round(len(failed) / len(rows), 3) if rows else None}
