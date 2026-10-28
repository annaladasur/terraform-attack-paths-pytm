# Adoption ladder

Start at Level 1 within an authorized pilot scope. Move up only when the exit criteria are met. Observe adds no merge-blocking policy; the CI identity, plan access, model processing and report audience still require appropriate authorization. Starting a pilot does not waive those decisions.

| Level | Deploy | Measure | Exit criteria |
|---|---|---|---|
| **1 Observe** | `tapm run` on every PR that touches the pilot's Terraform, and nightly on the default branch. `tapm gate --level observe`. Output goes to the job summary and artifacts, not to the PR. | M1, M3, M4, M11, M14 automatically; M9 and M16 by hand | Representative runs; baseline row in the worksheet; you know how many paths are open on the default branch (M3) |
| **2 Recommend** | `--level recommend`: the PR comment shows the paths, the questions and "would block". Draft accepted risks for the paths already open on the default branch (`tapm gate --draft`) and give each an owner. | M2, M8 (weekly sample), M10 | False-path rate (M8) under an agreed threshold on a labeled sample. Every path open on the default branch has an owner |
| **3 Validate** | `--level validate` as a required check on the pilot repo. A path at or above `high` needs a fix or an accepted risk (owner, reason, expiry ≤ 90 days). The team may accept its own risks. | M5 on new PRs, M6, M9, M12 | M5 = 0 on new PRs over the agreed sample; M9 no worse than baseline; M12 ≥ 90% |
| **4 Prevent** | `--level prevent`: an accepted risk also needs a compensating control and `approved_by` (not the owner), and runs ≤ 30 days. CODEOWNERS puts AppSec on `attack-path-exceptions.yaml`. Consider `--fail-on medium`. | M3 trend, M6, M7, M12 | M3 trending down on the default branch; accepted risks renewed on time |
| **5 Continuously validate** | `tapm canary` nightly with your own canaries added. Nightly `tapm gate` on the default branch alerts on expired risks. Quarterly review of accepted risks. | M15; M12 over time | Ongoing. A canary failure is an incident for the check's owner |

## Owners and rollback

Owners follow the split in [`prerequisites.md`](prerequisites.md).

| Level | Owner | Roll back to the level below when |
|---|---|---|
| **1 Observe** | Platform or DevOps team (the CI job and the plan role) | The plan step can't run in CI for a root module. Run it on a schedule instead of per PR |
| **2 Recommend** | AppSec, with repo owners reviewing the paths | PR comments go unread. Investigate relevance and workflow before changing the threshold |
| **3 Validate** | Repo owners (answers and their own accepted risks); AppSec (the threshold) | M9 climbs, or accepted risks get copied without reading. Look at M8 first: false paths are the usual cause |
| **4 Prevent** | AppSec (approvals, threshold) | A block had no fix or approver available when production needed the change. Record the rollback like a policy change: owner, reason, expiry |
| **5 Continuously validate** | AppSec | A canary fails (M15). Treat it as an incident and page the check's owner |

**Fail-open or fail-closed.** Decide this per level before you enforce. *Recommendation:* if `tapm` itself crashes,
the job is red at every level, because a silent pass hides a broken control. At Levels 1-3, a human may merge past
it with a recorded reason. At Level 4, only the accepted-risk approver may. `tapm gate` never passes a run whose
exceptions file it couldn't read.

## Where the talk's demo sits

| Demo beat | Level |
|---|---|
| Scanners only (40 findings, no path) | Before Level 1 |
| `tapm run`: the path, the evidence, the questions | Levels 1-2 |
| `tapm gate --level validate`: blocked, then the verified fix, then pass | Level 3 |
| `tapm canary`: 21 fixtures, 0 control failures | Level 5 |

## Policy-governed routing beyond this prototype

The levels above describe the implemented gate and declared exception fields. A general zero/one/two-person classifier is a recommended extension, not implemented or measured here. Policy defines delegated scope, hard blocks and protected review floors. Authenticate authority through repository controls; a typed name is not approval. Collect and adjudicate feedback, evaluate false-low routing on held-out cases, shadow/canary, and independently approve promotion. Protect classifier and policy changes, monitor drift and retain a safe stop/recovery path. The classifier cannot authorize its own expanded scope.
