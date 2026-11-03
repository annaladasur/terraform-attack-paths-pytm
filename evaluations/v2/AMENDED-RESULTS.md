# V2 amended-input known regression

This is a separately presealed material-input correction. Original final-source run: **25/28**, retained with failures. Empty synthetic boundaries and role trusts were replaced with valid policies; expected booleans stayed unchanged. This is not the original sealed28 pass.


Observed: sealed regression/known-input evaluation. Previously evaluated repositories remain familiar inputs; no unseen-repository claim.

Operational checks: **28/28**, Wilson 95% [0.8794, 1.0]. These boolean checks are not coverage precision/recall.

| Check family | Passed / total | Wilson 95% interval |
|---|---:|---|
| accounting | 5/5 | [0.5655, 1.0] |
| iam | 15/15 | [0.7961, 1.0] |
| known_plan | 2/2 | [0.3424, 1.0] |
| paths | 6/6 | [0.6097, 1.0] |

Protocol sealed at `2026-11-03T02:37:09.200528+00:00`; first engine call in this run after `2026-11-03T03:14:33.243329+00:00`. Protocol SHA-256 `e1fb26ab895dac5d9249439c124f444e11f4ca46308d710209193f66226770c6`. Expected/input bundle SHA-256 `990b249360a73244a822b91e8ea88942fd1681d97e0a11ca7a2b351c581bc7bc`.

The initial protocol hash was `2305864510b41c4201ec57501e39700d42dd38aa7a053e8b0ad596d0d12ba3c0`. The first execution was **27/28**; its synthetic what-if harness lacked an empty ledger. The protocol retains that error and the runner amendments. Expected outcomes and input specifications have stayed unchanged.

Familiar-plan label-limited coverage: precision **3/3** (Wilson 95% [0.4385, 1.0]), recall **3/3** (Wilson 95% [0.4385, 1.0]). The two familiar plans emitted 3 unique pairs; excluded prediction labels are {'VALID': 3, 'INVALID': 0, 'OUT_OF_SCOPE': 0, 'UNKNOWN': 0, 'UNLABELED': 0}. These are narrow known-input coverage counts, not the whole Tier-2 corpus.

Every known-plan prediction is inventoried by exact entry-target pair; multiple displayed routes count once. Frozen gold is retained. Supplemental exact labels cannot override it. UNKNOWN, OUT_OF_SCOPE and UNLABELED are visible exclusions from label-limited precision/recall, so a clean operational run does not mean perfect whole-output accuracy.

Historical context only: original blind precision **28/32**, recall **28/36**; historical same-corpus retest precision **33/34**, recall **33/36**. One human labeler, with eight automated disputed proposals. These are frozen historical records, not this supplemental run's metrics.

Frozen artifact integrity: all unchanged. No frozen results or gold written.

| Check | Result |
|---|---|
| identity-allow | PASS |
| identity-deny-overrides | PASS |
| boundary-intersection-allow | PASS |
| boundary-implicit-deny | PASS |
| boundary-explicit-deny | PASS |
| boundary-nonmatching-deny | PASS |
| boundary-conditional-allow | PASS |
| unresolved-boundary-arn | PASS |
| unknown-boundary-after-apply | PASS |
| identity-conditional-deny | PASS |
| public-resource-deny-overrides | PASS |
| public-resource-conditional-deny | PASS |
| role-resource-boundary-implicit-deny | PASS |
| user-resource-boundary-implicit-bypass | PASS |
| user-resource-boundary-explicit-deny | PASS |
| same-entry-new-target | PASS |
| duplicate-route-counts-once | PASS |
| out-of-scope-is-visible | PASS |
| exact-unknown-adjudication | PASS |
| near-match-is-unmatched | PASS |
| global-display-cap | PASS |
| zero-pair-display-cap | PASS |
| display-depth-does-not-limit-verification | PASS |
| verification-budget-is-unknown | PASS |
| order-and-irrelevant-padding | PASS |
| what-if-keeps-capped-alternative | PASS |
| familiar-codebuild-new-parameter-pairs | PASS |
| familiar-vpc-new-admin-negative | PASS |
