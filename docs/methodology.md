# Methodology

> **Public snapshot scope:** historical Git-order statements below describe the original research process.
> Its private commit objects are not distributed here; local hashes can be checked, while ancestry cannot be
> independently established from this snapshot. See [PUBLIC-RELEASE.md](../PUBLIC-RELEASE.md).
> Original labels/scores remain frozen, with one human labeler plus automated blind review and eight disputed
> label proposals disclosed in [the adjudication](../evaluations/blind-review-2026-10-19/README.md).

This page defines what the tool claims, how it scores what it finds, and how those claims are measured. Code
references point at the implementation, so every definition here can be checked against what actually runs.

## Attack path

> **An attack path is a sequence of typed graph relationships connecting an attacker-controlled entry condition
> to a security-relevant asset, where every edge is supported by deterministic evidence and any non-deterministic
> assumption is explicitly labeled.**

Implementation: `src/tapm/paths/engine.py`.

### Entry conditions

| Entry | When | Precondition recorded |
|---|---|---|
| `internet` | always | none; its reach is given by `EXPOSES` edges |
| an IAM user | `--user-entries` (or `user_entries: true` in `fixture.yaml`) | `credential_compromise` |

`EXPOSES` edges come from internet-facing load balancers, instances with a public address and an internet-admitting
security group, publicly accessible databases, Lambda function URLs without auth, and API Gateway REST / HTTP APIs
that are not PRIVATE and have a route without authorization.

### Assets (targets)

| Asset | Basis |
|---|---|
| S3 bucket, RDS instance, DynamoDB table, SSM parameter, KMS key tagged `confidential` or `restricted` | tag key `DataClassification` / `data_classification` / `Classification` / `Sensitivity`; values `confidential`, `sensitive`, `pii` map to confidential and `restricted`, `secret`, `highly-confidential` map to restricted |
| Secrets Manager secret; SSM `SecureString` | resource type (always confidential) |
| `aws:account-admin` | a principal that is admin-equivalent (`*:*` without a matching Deny) |
| anything named with `--target` | explicit |
| name-based guess (`customer`, `pii`, `payment`...) | only with `--heuristic-sensitivity`; such paths get status `review` |

Classification is an input. The engine cannot know that an untagged bucket holds customer data, and a path to an
`internal` bucket is not reported. Level 2 of the lab shows what happens when a tag changes.

### Traversal

Breadth-first from each entry over `EXPOSES`, `ROUTES_TO`, `ASSUMES`, `ESCALATES`, with `ALLOWS` only as the final
hop into an asset. Default limits are depth 8, 3 paths per entry–target pair, and 200 paths overall. No node repeats
within a path.

### Hops: FACT or ASSUMPTION

A hop is a **FACT** when the edge alone is enough to cross it: an ingress rule admits `0.0.0.0/0`, a listener forwards
to a target group, a policy grants `s3:GetObject` on the bucket.

A hop is an **ASSUMPTION** when the edge exists but crossing it needs something the configuration cannot prove:

| Precondition | Meaning | Where it arises |
|---|---|---|
| `workload_ssrf` | attacker can make the workload issue HTTP requests (SSRF) or run code; IMDSv1 is allowed | `ASSUMES` from an EC2 instance with `http_tokens = "optional"` |
| `workload_rce` | attacker can execute code in the workload; SSRF alone is not enough | `ASSUMES` from IMDSv2 instances, Lambda functions, ECS task roles |
| `container_escape` | attacker can execute code in a container **and** break out to its host | `ASSUMES` from an ECS service to its container instance's role when the host blocks containers from IMDS (iptables drop of 169.254.169.254, `ECS_AWSVPC_BLOCK_IMDS`, or IMDSv2 with hop limit 1) |
| `credential_compromise` | attacker holds this IAM user's credentials | user entries |
| `condition_satisfied` | an IAM `Condition` evaluates true for the attacker | any conditional grant or trust |
| `source_ip_allowed` | attacker's traffic comes from a public range the security group admits (not `0.0.0.0/0`) | `EXPOSES` via a non-wildcard public CIDR |
| `unresolved_value` | a value unknown at plan time resolves in the attacker's favour | reserved; unknown policy values are recovered symbolically instead |

### Path status

| Status | Meaning |
|---|---|
| `direct` | every hop is a FACT |
| `plausible` | at least one ASSUMPTION; no IAM `Condition` involved |
| `review` | an edge is conditional (IAM `Condition`) or the target was classified by name heuristic; a human decides |

### Priority

Priority is a deterministic score (`_priority` in `engine.py`), not a model judgement:

```
score = base(target) + entry - penalties

base      restricted 3, confidential 2, other 1
entry     internet 2, anything else 1
penalty   +1 each for workload_rce, condition_satisfied, source_ip_allowed, unresolved_value
          +2 for container_escape (code execution and an escape)
          +0 for workload_ssrf and credential_compromise (common, cheap for an attacker)
          +1 if the target was classified by name heuristic

high >= 4 · medium = 3 · low <= 2
```

The demo path: confidential (2) + internet (2) − 0 (`workload_ssrf`) = 4, **high**. With `http_tokens = "required"`
the `ASSUMES` hop needs `workload_rce` instead: 2 + 2 − 1 = 3, **medium**. Both numbers are checked against a real
re-plan in lab Level 2.

### Path identity

`key` is a digest of the node sequence and hop edges. `PATH-###` IDs are assigned in sorted key order after the
ledger is finalized, so the same plan always yields the same IDs.

### Remediation what-if

For each hop, the fix is applied to a copy of the graph and the engine is re-run (`paths/whatif.py`):

| Hop | Modeled fix |
|---|---|
| `EXPOSES` | remove internet reachability |
| `ASSUMES` with `workload_ssrf` | require IMDSv2 (the precondition becomes `workload_rce`) |
| `ASSUMES` (other) | remove the credential route |
| `ALLOWS` | remove the grant on this asset |
| `ESCALATES` | remove the primitive |

Effect: `breaks_path`, `downgrades_path` (with before/after priority), `breaks_path_but_alternative_exists`, or
`no_effect`.

### Verified remediation

A proposed patch (from the `patch_author` agent) counts as a fix only after it is applied to a copy, re-planned
offline and run through the whole pipeline again:

| Verdict | Condition |
|---|---|
| `PROVEN_BREAK` | the path (same node sequence) is gone and no other path reaches its target |
| `PROVEN_DOWNGRADE` | the path remains at a lower priority (for example IMDSv2: `workload_ssrf` → `workload_rce`) |
| `ROUTE_BROKEN` | the path is gone but other paths still reach the target |
| `REJECTED` | edit policy violation, no effect, a new path, a removed resource, a new or wider grant/exposure/route/trust, or a new pytm threat decided by the plan |
| `UNVERIFIED` | no plan for the patched sources (no cache entry, no Terraform); never accepted |

The static what-if predicts the same effect without planning. The benchmark reports how often the two agree.

## PyTM findings, classified

pytm evaluates each threat's condition against element attributes that default to `False`. For each (threat,
element) pair, `pytm_gen/classify.py` separates the attributes the condition reads into *decided* (set from plan
evidence, or structural) and *undecided*, and enumerates every assignment of the undecided booleans (at most 2^12):

| Class | Meaning |
|---|---|
| decided by the plan: confirmed | fires for every assignment: the evidence alone establishes it |
| decided by the plan: mitigated | an evidence-backed override (`Finding(response='mitigated')`), e.g. S3 Block Public Access |
| question for the app team | fires with pytm's defaults, but some value of an undecided control would clear it |
| ruled out | the architecture-only model (every evidence-fed fact reset to pytm's default) reports it; the evidence-fed model does not |

A finding is linked to a path hop when it is on a flow of that hop (by GRAPH ID, or the READS/WRITES flow standing
for a role's grant) or on the element the hop enters; cloud-pack threats name the hop they speak about (EC2-01 →
the ASSUMES hop). Non-boolean undecided attributes (data classifications on flows, TLS versions of unknown clients)
make a finding "question for the app team", never "confirmed". A pair with more than 12 undecided booleans is not
enumerated and stays a question.

## Questions for the app team

`pytm_gen/questions.py` turns the open findings into yes/no questions. Each open finding needs a set of
(element, control) keys: its undecided attributes, asked of the element that can answer them (a flow's copied
attributes of its sink, data attributes of the store). A finding is **settled** once all of its keys are answered,
whatever the answers. Selection is greedy: repeatedly ask the key that settles the most findings together with the
keys already asked, counting a finding on an attack-path hop twice; stop when no single key settles anything more.
This objective is not submodular (a finding needing two new keys is never credited by one step), so there is no
approximation guarantee; the report shows how many findings each question settles. Data questions ("does this bucket
hold personal data?") are listed separately. Answers go in `threat-answers.yaml`, become `APP-` evidence with trust
`attested`, only fill attributes the plan leaves undecided, and never change a path.

## Path cards (plain words)

`report/story.py` renders each path as one screen: a headline (asset, class, precondition in words), one sentence per
hop with the file and line to change, the fix the what-if (or the verified remediation) proved, and the first
questions on the path's elements. The `everyone` audience drops addresses, file names and evidence IDs and adds a
glossary; `story.md` holds that version, `report.md` the developer one. Every sentence is built from evidence records;
the optional `plain_explainer` agent re-tells a path through the same validator as every other annotation.

## Scanner join

A scanner finding is **on** a path if it targets a path node or a resource cited by the path's evidence. It is
**causal** if it speaks to the same concern as a hop's evidence, per the `CONCERNS` table in
`scanners/normalize.py` (internet-wide ingress, internet-facing LB, public IP/DB/bucket/function URL, IMDSv1, IAM
wildcard, IAM trust). Unlisted rules count as causal only on a narrow line overlap (3 lines or fewer) with hop
evidence. On the demo PR, 7 of 40 findings are causal.

## Ground truth

### Tier 1: synthetic fixtures (`fixtures/*/gold.yaml`)

* 21 fixtures, each isolating one behaviour (open ingress, wildcard IAM, instance profile, trust, resource policy,
  explicit Deny, Condition, `for_each`, `count`, modules, dynamic blocks, unknown values, cross-module references,
  noisy false positives, injection comments, benign comments, PassRole escalation).
* Labels were **written and committed before the engine ran on each fixture**; the git history shows the order.
* Each gold file lists expected edges (for a declared set of edge types), IAM access, VALID / PARTIALLY VALID paths
  with preconditions and priority, and **false paths** that must *not* be reported.
* The same author wrote the fixtures and the engine. Tier-1 scores demonstrate internal consistency and regression
  coverage, not real-world accuracy. Every gold file records `reviewer_2: pending` until a second person labels it.

### Tier 2: real repositories (`evaluations/tier2/`)

* TerraGoat, IAM-Vulnerable and 8 CloudGoat scenarios at pinned commits (`manifest.yaml`).
* Labels are **reachability** claims (entry X can reach target Y) written from each project's own documentation
  (README walkthroughs, scenario cheat sheets) before the engine ran. Labels are `VALID`, `INVALID` or
  `OUT_OF_SCOPE` (something the engine does not model, for example conditions or Lambda-invoke chains).
* Every disagreement is adjudicated in `ADJUDICATION.md`. Labels are never changed to match output; where a label
  was later judged wrong, both the original and the disputed status are recorded.
* The **blind first run** is the headline number. The second run was measured on the same corpus the fixes were
  made against, and is reported only next to the first.

### Labeling protocol for a second reviewer

1. Read the fixture's Terraform (or the project's documentation for Tier 2), not the engine's output.
2. For each entry–asset pair, decide VALID / PARTIALLY VALID / INVALID and write the preconditions an attacker
   needs.
3. Record disagreements with reviewer 1 in the gold file's `review` block. Adjudicate by discussion; record the
   outcome and reason.
4. Only then run `make benchmark`.

## Metrics

Implementation: `src/tapm/eval/metrics.py`, `runner.py`, `tier2.py`.

| Metric | Definition |
|---|---|
| Path precision | TP / (TP + FP). A predicted path is TP when its node sequence equals a VALID or PARTIALLY VALID gold path. FP: any other predicted path, and listing a gold *false path* also counts. |
| Path recall | TP / (TP + FN) over VALID / PARTIALLY VALID gold paths |
| Priority / precondition agreement | share of matched paths whose priority and precondition set equal the gold values |
| Edge precision / recall | over `(type, src, dst)` triples of the gold file's `labeled_edge_types` only |
| IAM mapping accuracy | share of gold `(principal, resource)` pairs whose derived access set (`list/read/write/delete/admin`) matches exactly |
| Tier-2 reachability | per labeled pair: does any reported path connect entry to target? Scored TP / FN / FP / TN |
| Scanner hop coverage | for each hop of each matched gold path, whether a tool reported a causal finding for that hop's concern. Generous: a finding on each hop is not the same as connecting them |
| Replay consistency | N runs per fixture (default 10); an artifact is consistent when all N SHA-256 hashes match |
| AI outcome | per annotation: accepted, rejected (validator), or held for human review (Jev / reviewer) |
| AI evidence precision | share of accepted annotations whose every cited ID exists and was in the agent's bundle (100% by construction; the validator enforces it) |
| Runtime | wall-clock per stage (`run-manifest.json`); median and p95 over fixtures |
| Cost | tokens × `ai/pricing.json`; recorded per call |

## What is not measured (yet)

* Whether an AI annotation is *useful* to a developer. That needs a user study; the talk shows examples, not a
  number.
* Live-model variability at scale. `tapm replay` measures it for the backends you record (`make record`); the
  committed numbers use the `simulated` backend and say so.
* A second human reviewer for the gold labels (tracked in each gold file).
