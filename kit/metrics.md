# Metrics

Fix these before you change anything, and record the baseline in [`baseline-worksheet.csv`](baseline-worksheet.csv).
`tapm measure` fills every row marked *auto* from the output of `tapm run` and `tapm gate`. It writes counts only (no
resource names, no paths, nothing from the plan), for local comparisons. Counts can still be sensitive; apply your own information policy. No external report is requested.

```bash
tapm measure runs/*/ --worksheet my-worksheet.csv --at baseline     # optional legacy comparison slots: --at day30 / day90 / day180
```

- **Percentages:** report n with every percentage (`tapm measure` prints it next to the value).
- **Targets:** the targets are suggestions to adapt, not results.
- **Where to measure:** PR runs answer "what does a change open?" (M2, M4). Scheduled runs on the default branch answer
  "what is open right now?" (M3, M5, M6, M12). Keep the two series apart.

| ID | Metric | Definition | Source | Level | Direction | Suggested target |
|---|---|---|---|---|---|---|
| M1 | Review items per change, before | Scanner findings + pytm's generic threats for the same plan (PR #42: 162 review items = 40 scanner findings + 122 generic threats): what a reviewer is handed without paths | auto | 1 | baseline | Record it; it is the "before" |
| M2 | Review items per change, after | Paths + the first six questions + data questions: the first screen of the PR comment | auto | 1-2 | ↓ vs M1 | Fits one screen |
| M3 | Open attack paths | Paths at or above the threshold (default `high`) | auto | 1 | ↓ on the default branch | Trend down each month |
| M4 | Changes that open a path | Runs with at least one path at or above the threshold | auto | 1 | Watch | Know the rate before you enforce |
| M5 | Paths without a decision | Paths at or above the threshold with no fix and no valid accepted risk. On the default branch: paths that merged without one | auto | 1 (baseline), 3 | ↓ | 0 on new changes at Level 3 |
| M6 | Accepted-risk coverage | Share of open paths at or above the threshold covered by a valid accepted risk | auto | 2-3 | ↑ | 100% of the paths you keep |
| M7 | Verified-fix rate | Share of remediated paths whose fix was re-planned and the path was gone (`tapm run --remediate`) | auto | 2 | ↑ | Most fixes proven before merge |
| M8 | False-path rate | Share of reported paths a reviewer marks as not reachable (auto from `disposition: not_reachable` in exceptions file, or weekly sample) | auto | 2 | ↓ | < 10% before Level 4 |
| M9 | Time to a security decision | Median time from a Terraform PR opening to its security decision (check green, answers and acceptances merged) | manual (PR timestamps) | 1 (baseline), 3 | ↓ | Trend down; not slower than baseline |
| M10 | Questions answered | Share of first-screen questions answered in `threat-answers.yaml` | auto | 2-3 | ↑ | Most first-screen questions answered |
| M11 | Scanner findings on a path | Share of scanner findings that sit on a reported path: the ones to fix first | auto | 1 | Watch | Use it to order the backlog |
| M12 | Accepted-risk hygiene | Share of accepted risks that are valid (owner, reason, unexpired, within the level's limit) | auto | 3 | ↑ | ≥ 90%; expired entries fixed within a week |
| M13 | AI statements held back | Share of AI annotations the validator rejected or sent to a person. Unsupported statements published must stay at 0 | auto | any (AI is optional) | Watch | Published without evidence = 0 |
| M14 | Pipeline time | p95 time of `tapm run` per change | auto | 1 | Watch | Small next to `terraform plan` |
| M15 | Control failure rate | Canaries whose result differs from their expectation (`tapm canary`, nightly) | auto (`tapm canary`) | 5 | ↓ | 0; any failure pages the check's owner |
| M16 | Threat-model freshness | Share of Terraform root modules whose model was regenerated on their latest merged change | manual (CI inventory) | 1 | ↑ | 100% of root modules in scope |

## Reading them together

- **Fewer items is not the goal by itself.** Read M2 next to M8 and M5. A short PR comment that misses real paths, or
  reports paths nobody believes, is not an improvement.
- **Speed.** Read M9 next to M5. If decisions get faster because people accept everything, M6 rises while M3 stays
  flat. That's a signal to tighten who may accept (Level 4).
- **Accepted risk is a decision, not a fix.** Report M3 and M6 together. A falling M5 with a flat M3 means the
  paths were accepted, not removed.
- **AI numbers are optional.** Leave M13 empty if you run without a model. The paths, the gate and every other metric
  don't depend on one.

## Classifier evaluation is separate

If a team adds risk routing, define required tier r and proposed tier p as0,1or2 people. Under-routing among human-required cases is count(p < r) / count(r > 0) over the same adjudicated sample. Also report count(p = 0 and r > 0) / count(r > 0), and count(p = 1 and r = 2) / count(r = 2), with counts and uncertainty. Evaluate reviewed held-out and regression cases, include sampled automatic routes and incidents, and inspect category-specific errors, abstentions, review effort and latency. Approval clicks alone are noisy feedback. Adjudication, shadow/canary tests and independently approved promotion precede authority changes. These are proposed measures, not implemented classifier results; path precision and recall do not establish routing accuracy.
