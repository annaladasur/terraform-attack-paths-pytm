# Decision matrix

Each decision below is one a reviewer makes on a Terraform PR today, usually by reading scanner output. The evidence
column is what the check puts in front of them instead.

## 1. Can this Terraform change merge?

Paths come from `tapm run`; the decision comes from `tapm gate` at your level. Priorities and statuses are defined in
`../docs/methodology.md`.

| Path | Observe / Recommend | Validate | Prevent |
|---|---|---|---|
| No path at or above the threshold | Merge | Merge | Merge |
| Path at or above the threshold, **fixed in this PR** (it's gone from the plan) | Merge | Merge | Merge |
| Path at or above the threshold with a **valid accepted risk** | Merge | Merge | Merge if the entry has a compensating control and an approver other than the owner, and expires within 30 days |
| Path at or above the threshold, **no decision** | Merge; the comment says "would block" | **Blocked** until fixed or accepted | **Blocked** until fixed or accepted by an approver |
| The exceptions file doesn't parse | Merge; reported | **Blocked** | **Blocked** |

**Status changes what a reviewer does, not what the gate does.**
- `direct`: every hop is a fact in the plan. Fix before merge.
- `plausible`: at least one hop assumes something the plan can't show, such as `workload_ssrf` (an SSRF in the app).
  The path card names the assumption; ask the app owner.
- `review`: a hop depends on an IAM `Condition`, or the target was classified by name. A person confirms the path
  before it counts.

## 2. Which scanner findings do we fix first?

| Finding | Order |
|---|---|
| On a reported path (`scanner-findings.json`: `paths` is not empty) | First. The path card names the hop fix that breaks or downgrades the path |
| Not on a path, high or critical | Next, by your scanner's own severity |
| Not on a path, medium or low | Backlog. They are still real per-resource issues, and scanners remain the tool for them |

## 3. Which of pytm's threats need action?

| pytm says | Meaning | Action |
|---|---|---|
| confirmed | The plan decides the threat applies | Fix, or accept it like a path |
| ruled out | The plan decides it doesn't apply (evidence cited) | None |
| mitigated | A control in the plan neutralizes it (for example S3 Block Public Access) | None; keep the control |
| needs the app team | The plan can't know (input validation, authentication in the app) | Ask the first-screen questions. Answers go in `threat-answers.yaml` and are reviewed like code |

A wrong "yes" hides a real threat, so answers get the same review as code.

## 4. Is this fix real?

| Remediation verdict | Meaning | Action |
|---|---|---|
| `PROVEN_BREAK` | The patch was applied to a copy, re-planned, and the path is gone with no new paths | A human reviews the diff and merges it |
| `PROVEN_DOWNGRADE` | Re-planned; the path remains at a lower priority | Merge if the lower priority is below your threshold; otherwise keep going |
| No verified fix | Every proposal was rejected or changed nothing | A person designs the fix. A scanner going quiet is not proof |

## 5. Can this AI sentence go in the PR comment?

| Validator result | Action |
|---|---|
| Accepted: every claim cites evidence IDs that exist and say what the sentence says | Publish as an annotation, labeled as AI-written |
| Held for review | A person reads it before it is published |
| Rejected | Dropped. It never reaches the PR |

A model never adds, removes or re-ranks a path, and never blocks or unblocks a merge. "Accepted" means "supported by
cited evidence", not "true".

## 6. Does this accepted risk stay?

| Situation | Action |
|---|---|
| Expired | The gate stops counting it. Renew it with a new expiry and a reason, or fix the path |
| The path is gone | `tapm gate` reports the entry as unused. Delete it |
| No compensating control | Fine at validate; required at prevent |
| The owner left the team | Reassign the owner before renewing |

## 7. When do we move up a level?

Use the exit criteria in [`adoption-ladder.md`](adoption-ladder.md). They are measured, not negotiated: M8 under 10%
before any blocking, M5 = 0 on new PRs before prevent.
