# Development log: what the first runs caught

Kept because the talk promises examples of where each layer helped and where it did not. Every entry names the commit range and what changed.

## Tier 1 corpus, first engine run (2026-09-29)

Gold labels for fixtures 001-005, 007-018, 020, 021 were committed (`0a737ab`) before the engine was run on them. Fixture 006 is the **development fixture**: the engine was built against it, so it is not a blind test. Fixture 019 is 006 plus comments.

First run: **19 of 21 fixtures matched their gold labels.** Both misses were engine bugs; the gold labels were right.

| Fixture | Symptom | Root cause | Fix |
|---|---|---|---|
| 002-public-s3 | missed `internet -> principal:any -> exports` | public bucket policy added `ALLOWS` edges from `principal:any` without creating the node, so the `EXPOSES internet -> principal:any` edge was never built | create the synthetic node where the edge is created |
| 017-cross-module-references | missed the whole path | public-subnet check matched `ref.startswith("aws_internet_gateway.")`, which fails for `module.web.aws_internet_gateway.main` | replace all string-prefix checks with resource-type checks from the plan |

Found while designing the corpus, before first run: the plan's `configuration` omits `locals`, so `local.x` references were unresolvable; policy interpolations through `var.` and `module.x.output` lost the attribute (`.arn` vs `.id`); an unknown ARN segment inside a concretised pattern was treated as a glob; and a conditional IAM grant was penalised twice in the priority score.

## AI stage, first run over the corpus (simulated backend)

Backend: `simulated` (deterministic templates, no model). These are findings about the templates, the validator and the routing, not about any LLM.

| Count | What happened | Verdict | Change |
|---|---|---|---|
| 2 | Remediation template emitted an S3 policy example for paths ending at a Secrets Manager secret and a DynamoDB table, naming `s3:GetObject` | **Validator right**: the annotation named permissions no cited evidence grants | template now uses the actions of the hop's own `ALLOWS` edge |
| 4 | Finding explainer quoted a scanner's own severity ("tfsec ..., critical") on a medium-priority path | **Validator false positive**: quoting a scanner's label is not escalation | escalation check ignores parenthesised scanner citations |
| 25 | Annotations held for human review on every path whose policies were recovered symbolically | **Routing too conservative**: symbolic recovery is deterministic and tested | only unevaluated IAM Conditions and hops without source-located evidence route to humans |

After the changes: 56 generated, 52 accepted, 0 rejected, 4 held (all on fixture 011, the conditional-IAM fixture, which is the intended behaviour).

## Scanner baselines

Trivy initially reported 20 findings on fixture 019 against 10 on the identical fixture 006: it was also scanning the committed `plan.json`. Scanners now run on a clean copy containing only `.tf` sources, so all three tools see identical input.

## Tier 2 (real-world), blind first run vs. second run

Gold labels for all ten cases were committed (`de0cff6`) from each project's documentation before the engine ran.

**Blind first run: TP 28, FN 8, FP 4, TN 1. Reachability precision 87.5%, recall 77.8%.**

| Miss | Case | Root cause | Class | Change for run 2 |
|---|---|---|---|---|
| FN | cloudgoat-iam_privesc_by_attachment | mighty role's admin policy attached via `managed_policy_arns = [aws_iam_policy.x.arn]`, unknown at plan time and silently dropped | engine gap (common pattern) | resolve `managed_policy_arns` references to customer-managed policies |
| FN | cloudgoat-iam_privesc_by_key_rotation | same `managed_policy_arns` gap on the secrets role | engine gap | same |
| FN | cloudgoat-iam_privesc_by_ec2 | EC2 user-data takeover (`ec2:ModifyInstanceAttribute` + Stop/Start) not in the primitive catalogue | missing primitive (published technique) | add `PE-EC2-MODIFY-USERDATA` |
| FN | cloudgoat-cloud_breach_s3, cloudgoat-ec2_ssrf | ingress allowed only from a specific *public* CIDR (the player's IP); only 0.0.0.0/0 counted as internet | modelling gap | public non-wildcard CIDRs expose the resource with precondition `source_ip_allowed` |
| FP | iam-vulnerable fp1, fp2 | admin-equivalence shortcut (`iam:*` on `*`) ignored an explicit `Deny iam:*` | **engine bug** | admin-equivalence honours unconditional Deny |
| FP | iam-vulnerable fp4 | policy Resource `arn:aws:iam::aws:policy/fp4-*` (AWS-managed namespace) matched a customer policy because unknown accounts were assumed to match any literal account | **engine bug** | the `aws` account never matches customer resources |
| FP | iam-vulnerable fp5 | Condition that cannot be met; conditions are not evaluated | known limitation | none (reported as `review`) |
| FN | iam-vulnerable privesc9, privesc12, AssumeRole-start (users) | the users cannot use the roles they modify / the chain trusts the lab operator | **label dispute** | none; see `tier2/ADJUDICATION.md` |

Also found while running: the PyTM generator crashed on configurations with more than one VPC (sorting `Node` objects); fixed before scoring.

**Second run: TP 33, FN 3, FP 1, TN 4. Precision 97.1%, recall 91.7%.** All three FNs are the disputed labels; the FP is fp5. Tier 1 remained 21/21 after every change.

Caveat for the talk: run 2 improved on the corpus it was measured on. The honest headline is the **blind** run; run 2 shows what a few general fixes buy. A held-out set (new repositories not seen during development) is needed before quoting run-2 numbers as accuracy.

## Performance: what-if on IAM-Vulnerable (2026-09-29)

IAM-Vulnerable (265 resources, 38 paths) took 31 s, and 30.4 s of that was the remediation what-if. Each hop of each
path deep-copied the whole graph and re-ran the full path search, and the search itself scanned every edge on every
expansion. The fix: build the adjacency index once per search, use a shallow graph copy with a replaced edge, and
re-run only from the path's own entry. **31 s → 0.9 s.** The attack paths, what-if results and evidence ledgers are
byte-identical before and after for all 21 fixtures and 10 Tier-2 cases.

## Lab: stale plan keys (2026-09-29)

Making the plan-cache key ignore trailing commas changed the key of three committed configurations (fixtures 010 and
016, `demo/base`). Their stored keys went stale, so `tapm paths 010` tried to re-plan. The tests had not caught it
because they read `plan.json` directly. Keys and cache entries were regenerated, and
`test_committed_plans_match_their_sources` now guards it.

## PyTM fed with evidence (2026-09-29)

* pytm 1.4's `check()` copies `protocol`, `port` and `isEncrypted` from each flow's **sink element** onto the flow,
  overwriting what the model set on the flow. The earlier generator set `protocol` and `isEncrypted` on flows, so
  pytm silently evaluated every flow as protocol `""` and unencrypted. These facts now live on the elements.
* A first version counted `arn:aws:s3:::bucket/*` (objects of one named bucket) and symbolic
  `tf:aws_s3_bucket.x.arn/*` as wildcard grants, so the clean fixture had a "confirmed" least-privilege threat.
  Wildcard detection is now ARN-aware.
* A flow into a TLS listener carried pytm's default `tlsVersion = NONE`, below the listener's minimum, which made
  AC10 fire on the load balancer. A client cannot negotiate below the listener policy, so the flow now carries the
  listener's minimum.

## Verified remediation: what the loop found (2026-09-29)

Running the patch loop over every Tier-1 path found two problems that no earlier test had:

| Found | Kind | Fix |
|---|---|---|
| On fixture 012 (`for_each`), a correct narrowing (`aws_s3_bucket.data["scratch"].arn`) re-planned as "no effect": the IAM evaluator stripped the instance key from symbolic references, so a grant on one instance matched every instance | **engine bug** (over-approximation: extra ALLOWS edges on indexed resources) | indexed references name one instance; unindexed ones still name all. Tier 1 and Tier 2 results unchanged. |
| On fixture 002, the simulated author read an object path (`${aws_s3_bucket.exports.arn}/*`) as a wildcard and moved the public grant onto another bucket; the path disappeared, so the verifier accepted it | **verifier gap** | the author uses the ARN-aware wildcard test, and the verifier now rejects any patch that adds or widens a grant, exposure, route or trust ("a remediation only narrows") |

Also: on fixture 015 the static what-if and the re-plan agreed that IMDSv2 changes nothing (the instance is
directly exposed, so code execution at the edge keeps the path high). The simulated author now skips hops the
what-if marks `no_effect`.

## TerrARA's benchmark: blind first run vs. second run (2026-09-29)

The 13 vulnerabilities that TerrARA's public samples document were written down and committed (`57e3e8f`) before
the pipeline ran on the samples (`evaluations/terrara/`). The first run found **no attack path on any of the nine
samples** and covered 6 of the 13 (5 by a question, 1 by a plan-confirmed threat). Every miss was a gap in general
AWS semantics, not in a sample:

| Found | Kind | Fix |
|---|---|---|
| API Gateway REST/HTTP APIs were not internet entries (AWSGoat m1, four TerrARA samples) | **coverage gap** | unauthenticated, non-PRIVATE routes `EXPOSE` the API, which `ROUTES_TO` its Lambda / instance / LB; conditional without an `aws_lambda_permission` |
| ECS services were not modelled (AWSGoat m2, KaiMonkey) | **coverage gap** | LB → service via its target group; task role; container-instance role through `ECS_CLUSTER` in user data, with a new `container_escape` precondition when the host blocks containers from IMDS |
| `jsonencode({ "Statement" : [...] })`: python-hcl2 keeps the quotes on keys, so the recovered policy was silently empty (AWSGoat m1) | **parser bug** | unquote keys in symbolic recovery |
| Glue job PassRole, and writing a policy onto a role one can take over | **missing primitives** | `PE-PASSROLE-GLUE-JOB`, `PE-PASSROLE-GLUE-UPDATE-JOB`, `PE-POLICY-ON-ASSUMABLE-ROLE` |
| `AmazonSSMFullAccess` unresolved | **catalogue gap** | added (approximate, like the others) |

Two documented scenario goals became declared targets (run configuration, not ground truth). Second run: 13 of 13
covered, 5 by an attack path matching the walkthrough, 8 by a yes/no question (3 in the first six). Tier 1 gold
labels and Tier 2 results unchanged.

## 2026-09-30: the talk as an implementation package (`principle.md`)

The repository adopted `principle.md` as the standard for every talk: the product is a change an organization can
adopt, measure and keep. Applying it here changed the tool as well as the deck.

| What | Why | Where |
|---|---|---|
| `tapm gate --level observe\|recommend\|validate\|prevent` | Adoption one level at a time: nothing fails CI until the false-path rate is known | `src/tapm/gate.py` |
| Accepted risks in `attack-path-exceptions.yaml` (owner, reason, expiry ≤ 90 days; at prevent a compensating control and a second approver, ≤ 30 days), matched by entry, target and `via`, never by PATH number | A blocking check needs an exception process, or it gets bypassed; path numbers shift with the ranking | same; threat model T11 |
| `tapm gate --draft` | Paths already on the default branch become owned debt instead of blocking every PR | same |
| `tapm measure` (counts only) and `kit/baseline-worksheet.csv` | Metrics fixed before implementation; reports that can be shared without plan data | `src/tapm/measure.py`, `kit/metrics.md` |
| `tapm canary` | Level 5: prove nightly that the check still blocks what it should. 21/21 fixtures agree with their gold labels (`evaluations/results/canary.json`) | `src/tapm/gate.py`; threat model T12 |
| `make gate`, `make replay-fix` | The demo's replay: the PR is blocked at validate, and the same PR with the verified fix passes the same check | `Makefile`, `scripts/replay-fixed.sh` |
| The kit, `CHALLENGE.md`, four issue forms | The take-home and the 30/90/180-day loop | `kit/`, `.github/ISSUE_TEMPLATE/` |

On the demo PR, the new measure definitions give M1 = 162 review items before (40 findings + 122 generic threats)
and M2 = 9 on the first screen after (1 path, 6 questions, 2 data questions). 269 tests pass.

## Still to do before the evidence freeze (Oct 3; deck done Oct 5, due to OWASP Oct 10)

- Record live LLM runs (`make record`) and replace simulated AI numbers; measure text variability over 10 runs.
- Second reviewer for every gold label (Tier 1 and Tier 2); resolve `tier2/ADJUDICATION.md`.
- Add a held-out Tier-2 set (repositories not used during development) and run it once.
