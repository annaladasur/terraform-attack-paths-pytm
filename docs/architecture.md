# Architecture

> Graph construction, path discovery, priority and the path gate are deterministic. AI annotations remain reviewable supporting material.

The pipeline turns a Terraform plan into a typed security graph, an executable PyTM model and a small set of
evidence-backed attack paths. AI runs last: it can explain, map and narrate what the code already decided, and
outputs require valid ledger references and schema/heuristic checks before publication. These checks do not establish semantic entailment or universal injection resistance. The annotation router influences publication/review, while path verdicts remain separate.

```
terraform show -json          HCL source (locations, comments)          scanner JSON (Checkov / tfsec / Trivy)
        │                               │                                          │
        ▼                               ▼                                          │
 ┌─────────────────────────── TRUTH PLANE ───────────────────────────┐            │
 │ plan.py      planned values, unknowns, references, modules        │            │
 │ source.py    block/line index, comments -> untrusted CMT records  │            │
 │ symbolic.py  unknown jsonencode() policies recovered from source  │            │
 └───────────────────────────────┬───────────────────────────────────┘            │
                                 ▼                                                 │
 ┌──────────────────────── SECURITY MODEL PLANE ─────────────────────┐            │
 │ graph/build.py    typed nodes, DEPENDS_ON/CONTAINS/ATTACHES edges │            │
 │ graph/network.py  EXPOSES, ROUTES_TO (SGs, LBs, routes, IGW)      │            │
 │ iam/evaluator.py  TRUSTS, ASSUMES, ALLOWS, ESCALATES              │            │
 │ paths/engine.py   entry -> asset BFS, FACT/ASSUMPTION hops        │◄───────────┘
 │ paths/whatif.py   remediation effect, computed on a graph copy    │  scanners/normalize.py
 │ pytm_gen/         evidence-fed threat-model.py, cloud threat pack, │  (joined, never trusted
 │                   classify: decided / app team / ruled out, DFD   │
 └───────────────────────────────┬───────────────────────────────────┘   for path existence)
                                 ▼
 ┌──────────────────────────── EVIDENCE PLANE ───────────────────────┐
 │ evidence/ledger.py  TF / NET / IAM / GRAPH / SCAN / PATH / CMT IDs │
 │ report/             report.md, SARIF, attack-paths.json            │
 └───────────────────────────────┬───────────────────────────────────┘
                                 ▼  read-only EvidenceBundle per path
 ┌────────────────────────── AI ENRICHMENT PLANE ─────────────────────┐
 │ ai/jev.py        typed decisions: route, sufficiency, escalation   │
 │ ai/agents.py     7 agent roles, JSON schema out, no tools          │
 │ ai/validator.py  deterministic validation: the leash                │
 │ ai/harness.py    route -> agent -> validate -> review -> publish?  │
 │ ai/remediate.py  patch author -> edit policy -> re-plan -> prove   │
 │ ai/self_model.py pytm model of this AI layer (LLM01-LLM09)        │
 └────────────────────────────────────────────────────────────────────┘
```

## The four planes

| Plane | Question it answers | Deterministic? | May a model influence it? |
|---|---|---|---|
| Truth | What will Terraform create, and where is it written? | yes | no |
| Security model | What can reach what, and with which permission? | yes | no |
| Evidence | What is the proof, by stable ID? | yes | no |
| AI enrichment | How do we explain, map and fix it for a human? | no (bounded) | this plane only |

The AI plane is downstream of everything else and has no write path back. `tests/test_ai_boundary.py::test_ai_stage_cannot_mutate_security_truth`
hashes the graph and path list before and after a full AI run with comments included.

## Truth plane

**Input is the plan, not the HCL.** `terraform show -json` resolves `count`, `for_each`, modules, variables and
defaults; the HCL is parsed only to locate blocks and comments. Three plan sections are used:

* `planned_values` / `resource_changes`: resource attributes, including `after_unknown` (known-after-apply) and
  `after_sensitive` (redacted before anything is written out);
* `configuration`: expressions and references, which give `DEPENDS_ON` edges and let the engine resolve
  `aws_s3_bucket.x.arn` inside an IAM policy to a graph node even when the ARN is unknown at plan time;
* `prior_state`: read-only data sources only.

**Unknown values stay unknown.** When a policy document is `jsonencode()`d from values that are unknown at plan time,
`symbolic.py` re-parses the policy from source and substitutes `tf:<address>.<attr>` tokens. Such grants carry
`provenance: symbolic` in their IAM evidence. They are exact about *which resource* is referenced, and they are not
treated as an attacker precondition.

**Comments are data, never input.** Terraform plans contain no comments, so nothing that reads the plan can be
steered by one. Comments are indexed as `CMT-###` records with `trust: untrusted` and a detector flags instruction-like
text (see [prompt-injection.md](prompt-injection.md)).

**Offline planning.** `terraform/offline_plan.py` plans in a temp copy with an override file that disables credential
lookups, strips real `AWS_*` variables from the child environment and optionally points the provider at moto
for data sources. Plans are cached in `plan-cache/` by a hash of the normalised sources (no comments, no formatting
whitespace), which is what makes the audience lab work without Terraform.

## Security model plane

### Typed graph

Nodes are Terraform resources (plus a few synthetic nodes: `internet`, `principal:any`, `aws:account-admin`, AWS
services). Types in `graph/kinds.py` are *modeled*; every other resource is still a node, marked `modeled: false`, so
coverage metrics stay honest.

| Edge | Meaning | Source |
|---|---|---|
| `DEPENDS_ON` | configuration reference | plan `configuration` |
| `CONTAINS` | VPC contains subnet, subnet contains instance | attributes |
| `ATTACHES` | policy attached to principal; instance profile holds role | attributes |
| `EXPOSES` | entry reaches a listener/port | SG rules + public subnet/IGW route, internet-facing LB, function URL without auth, public API Gateway route without authorization |
| `ROUTES_TO` | LB or API forwards to a target | listener -> target group -> attachment or ECS service + SG admits LB; API integration -> Lambda / instance / LB |
| `TRUSTS` | role trust policy admits a principal | trust policy |
| `ASSUMES` | a workload or principal can obtain a role's credentials | instance profile / Lambda role / ECS task role / ECS container-instance role (`graph/ecs.py`) / trust + `sts:AssumeRole` / escalation primitives |
| `ALLOWS` | a principal may perform actions on an asset | identity + resource policies, minus explicit Deny |
| `READS` / `WRITES` | data flow for the DFD | derived from `ALLOWS` |
| `ESCALATES` | a principal can make itself more powerful | escalation primitives (`iam/data/escalation.json`) |

### IAM evaluation (the relationships Terraform never states)

Terraform says "this role has this JSON document". It never says "this instance can read that bucket". The evaluator
(`iam/evaluator.py`) derives that from identity, resource, trust and permission-boundary policies:

* `Action` / `NotAction`, `Resource` / `NotResource`, wildcards, explicit `Deny` wins;
* AWS-managed policies are summarised from a pinned table (`iam/data/managed_policies.json`);
* a statement with a `Condition` still produces an edge, flagged `conditional` (conditions are not evaluated);
* ARNs in the `aws` account namespace never match customer resources;
* escalation primitives: self-admin, `iam:PassRole` + compute (EC2, Lambda, Glue dev endpoints and jobs,
  CloudFormation, ...), takeover of users/roles/workloads, `ec2:ModifyInstanceAttribute` user-data, and a policy
  written onto a role the principal can also act as (`PE-POLICY-ON-ASSUMABLE-ROLE`);
* policies unknown at plan time are recovered symbolically from source (`terraform/symbolic.py`), including
  `jsonencode({ "Statement" : ... })` with quoted keys.

Out of scope, and said so in every output artifact (`report.md`, `attack-paths.json`, `attack-paths.sarif`, `story.md`, `iam-relationships.json`, `threat-model.py`): SCPs, RCPs, session policies, and condition
evaluation. See [threat-model.md](threat-model.md#limitations).

### Attack paths

Defined in [methodology.md](methodology.md#attack-path). BFS from entry conditions (`internet`, optionally
compromised IAM users) to assets (confidential/restricted data, secrets, account admin). Each hop is a `FACT` or an
`ASSUMPTION` with a named precondition. Priority is a documented integer score, not a model output.

### What-if

For each hop, `paths/whatif.py` applies the corresponding fix to a *copy* of the graph and re-runs the engine. The
report therefore says "setting `http_tokens = "required"` downgrades PATH-001 from high to medium" because the engine
computed it, not because a model suggested it. The audience lab (Level 2) checks this prediction against a real
re-plan.

### PyTM, fed with evidence

`pytm_gen/generator.py` writes a standalone `threat-model.py` (pytm 1.4.0): boundaries from VPC/subnets, `Actor`
for the internet and principals, `Server`/`Lambda`/`Datastore` for compute and data, `Dataflow` for network and
IAM-derived flows. Every element carries its Terraform address, evidence ID and source location. UUIDs are derived
from addresses, so the file is byte-stable across runs. It is plain pytm: `python threat-model.py --dfd` works
without this project installed.

pytm's 114 threats are conditions over element attributes, and every attribute defaults to `False`. A model that
sets nothing therefore reports *unknowns* as weaknesses. So:

* **Evidence-fed controls** (`pytm_gen/facts.py`). The generator sets only what the plan decides, each line with the
  evidence behind it, for example `n_aws_instance_app.imdsV1Allowed = True  # TF-004: http_tokens = optional`.
  Listener TLS policy → `minTLSVersion`, `isEncrypted`; `drop_invalid_header_fields` → `validatesHeaders`; SSE and
  service defaults → `isEncryptedAtRest`; IAM authorisation and public grants → `hasAccessControl`,
  `authorizesSource`; wildcard-resource grants → `implementsPOLP`. Application-layer controls (input validation,
  output encoding, sessions) are never set: Terraform cannot see them. All facts are also written to
  `pytm-controls.json`. pytm copies `protocol`, `port` and `isEncrypted` from a flow's sink element onto the flow,
  so those facts are set on elements.
* **Cloud threat pack** (`pytm_gen/cloud_threats.json`, 7 threats in pytm's own format). IMDSv1 with an instance
  role, internet-reachable workloads holding credentials, workload identities that reach classified data, wildcard
  grants on classified stores, public bucket policies, internet-wide ingress, unauthenticated function URLs. The
  model loads `threat-library.json` (pytm's library plus the pack, pinned next to the model).
* **Assumptions and overrides.** Scope assumptions go into `tm.assumptions`; a public grant neutralised by S3 Block
  Public Access becomes `Finding(threat_id='TAPM-S3-01', response='mitigated', references='NET-001: ...')`.
* **Path order.** Attack-path flows are defined first, so pytm numbers them (1), (2), (3) in the DFD and in `--seq`
  (`seq.puml`); the report draws the same sequence per path.
* **Classification** (`pytm_gen/classify.py`, run in its own interpreter). For every (threat, element) pair it
  enumerates the undecided boolean attributes the condition reads: *decided by the plan* (fires whatever they are,
  or mitigated by an override), *question for the app team* (some value would clear it), *ruled out* (the
  architecture-only model reports it and the evidence disproves it). Findings are linked to path hops.
  `pytm-findings.json` holds every finding with the facts that decided it.

On the demo: the architecture-only model reports 122 threats; fed with the plan, 8 are decided by the plan (one on
every hop of PATH-001), 110 are questions for the app team (input validation, sanitisation, output encoding...) and
12 are ruled out. `pytm_gen/questions.py` turns the 110 into yes/no questions, path-first (six settle 34), and
`report/story.py` tells each path in plain words (see [methodology.md](methodology.md#path-cards-plain-words)).

**pytm version and agent skills.** The model targets pytm 1.4.0, the latest release, and runs byte-identically on
pytm's unreleased main branch (`make test-pytm-main`). It avoids two 1.4.0 bugs that main fixes: out-of-scope
elements (the IMDS processes) are defined first, because `resolve()` otherwise copies every earlier finding onto them
(#338); and the Block Public Access override carries the threat's own fields, because an override otherwise blanks
them (#339). The model also follows the conventions of the `tm_skills` agent skills (linked from pytm's README):
every element and flow records its Terraform origin in `sourceFiles`, the open questions appear as
`# TODO - find the real value for this attribute` lines above the main guard, and `python threat-model.py --json`
gives the findings file those skills read. CI produces the baseline; an agent session or a person refines it.

### Scanners

Checkov, tfsec and Trivy run (or are replayed from saved baselines) on a clean copy of the `.tf` files.
`scanners/normalize.py` attaches each finding to a graph node and records it as `SCAN-###`. A finding is *causal*
for a path when it speaks to the same concern as a hop's evidence (the `0.0.0.0/0` rule on an `EXPOSES` hop,
IMDSv1 on an `ASSUMES` hop, a wildcard grant on an `ALLOWS` hop). Scanners never create or remove paths.

## Evidence plane

Every fact the engine relies on gets a stable ID in `evidence.json`:

| Kind | Example |
|---|---|
| `TF-###` | `aws_instance.app: IMDSv1 allowed (http_tokens = optional)` (app.tf:10-13) |
| `NET-###` | `aws_security_group.alb ingress tcp/443 from 0.0.0.0/0` (network.tf:72-78) |
| `IAM-###` | `aws_iam_role_policy.app_s3 statement 0 (ReadReports): Allow s3:GetObject, s3:ListBucket on arn:aws:s3:::*` (iam.tf:25-35) |
| `GRAPH-###` | `aws_iam_role.app --ALLOWS(list,read)--> aws_s3_bucket.customer_data` |
| `SCAN-###` | `tfsec aws-ec2-no-public-ingress-sgr (critical) on aws_security_group.alb` (network.tf:77) |
| `PATH-###` | the path itself, referencing its edges and causal findings |
| `CMT-###` | a source comment, always `trust: untrusted` |

IDs are assigned after sorting records canonically, so the same plan always produces the same IDs. Replay tests
run the pipeline N times (in-process and across `PYTHONHASHSEED` values) and compare artifact hashes.

## AI enrichment plane

```
EvidenceBundle ──► Jev: route? evidence sufficient? which agents? ──► agent (LLM, JSON schema, no tools)
                                                                           │
                        human review ◄── Jev: publish? ◄── adversarial reviewer ◄── validator (schema/reference/heuristic checks)
                                                                                         │
                                                                                      rejected
```

* **EvidenceBundle** (`ai/bundle.py`): per path, the hop list and a minimal view of each cited ledger record. The
  only thing an agent sees. No raw plan, no repository, no comments (unless the stress test asks for them, fenced
  as untrusted data).
* **Jev** (`ai/jev.py`): typed decisions (`choice` / `noul`), never facts. `LocalJev` is the offline rule-based
  stand-in (its probabilities are rule outputs, not calibrated); `TypeSafeJev` calls TypeSafe's API; `RecordingJev`
  records and replays.
* **Seven agent roles** (`ai/agents.py`, `ai/prompts/*.md`): single-shot, stateless model roles with zero tools (`run-manifest.json` records `tools_offered_to_models: []`). Each gets one bundle, returns one JSON object against a strict schema, and is governed by an explicit "may never" contract:
  1. `path_narrator`: path bundle → statement, evidence refs, severity, relationships; may never change priority or name non-edges.
  2. `plain_explainer`: path bundle → statement, evidence refs for a non-specialist; may never drop preconditions or alter severity.
  3. `finding_explainer`: bundle with SCAN records → what is wrong, why it matters, affected nodes; may never downplay a finding.
  4. `remediation`: path bundle + what-if → recommended change, HCL example, expected effect; may never introduce new resources.
  5. `framework_mapper`: path bundle → mappings to ATT&CK, CWE, NIST; may never use IDs outside the controlled vocabulary.
  6. `adversarial_reviewer`: bundle + annotation → verdict (`accept` / `reject` / `needs_review`), issues; may never approve or publish on its own.
  7. `patch_author`: bundle + cited blocks + earlier attempts (≤3) → one find/replace in a cited block; may never edit outside cited blocks or apply its own fix (proven by re-planning).
* **LLM backends** (`ai/llm.py`): Anthropic, OpenAI, Ollama, recorded cassettes, and a deterministic `simulated`
  backend used offline and in CI. The backend that produced each annotation is recorded on the annotation.
* **Validator** (`ai/validator.py`): deterministic validation checks. See [prompt-injection.md](prompt-injection.md#the-validator)
  for the control families and `make security-tests` for scripted negative cases (the command reports the current case count).
* **Asynchronous enrichment & cache** (`ai/enrich.py`, `ai/cache.py`, `tapm enrich`): the required check path runs
  model-free (`tapm run --llm off`). Asynchronous enrichment rebuilds evidence bundles from `evidence.json` and
  `attack-paths.json` (never the raw plan), enforces a per-PR path cap (default 3), and caches results by
  `bundle_hash + prompt_version + model`. Re-evaluating the same artifacts makes zero model calls, and gate output
  remains 100% identical with and without enrichment.

## Verified remediation (AI proposes, the pipeline proves)

`ai/remediate.py`, `tapm remediate`, `tapm run --remediate`. For each path (at most three):

```
patch bundle ──► patch_author (LLM, no tools) ──► edit policy ──► apply to a copy ──► offline plan ──► whole pipeline + pytm ──► compare
     ▲                     one find/replace          (code)        (never the repo)   (cache/Terraform)                           │
     └──────────────────────────────── rejection reasons, up to 3 attempts ◄────────────────────────────────────────────────────┘
```

* The **patch bundle** is the path's evidence bundle plus the source blocks its hop evidence cites (comments masked,
  instruction-like lines withheld), the non-sensitive resources the path's grants also reach, and the previous
  attempts with their verdicts.
* The **edit policy** is code: `find` must occur once, inside a cited block whose ID the patch cites; no new
  resource/data/provider/module/provisioner blocks, no external data or command execution, no `file()` or path
  reads, no comments or scanner suppressions, no classification tags, no `count`/`for_each`/`lifecycle`, no
  instruction-like text, at most 12 changed lines; the patched file must parse.
* **Verification** applies the patch to a temporary copy, plans it offline (plan cache, else Terraform with no
  credentials), runs the whole deterministic pipeline and pytm, and compares with the original run. Accepted only as
  `PROVEN_BREAK` (the path is gone and nothing else reaches the target) or `PROVEN_DOWNGRADE`, and only if no path
  is new, no resource is removed, no grant, exposure, route or trust is added or widened, and pytm has no new
  threat decided by the plan. No plan → `UNVERIFIED`, never accepted.
* Output: `remediations.json` (every attempt, why it was accepted or rejected, what the static what-if predicted,
  which pytm threats it resolves) and `remediation-PATH-###.diff`. Nothing is applied. The model is a proposer, the
  pipeline is the verifier, and the human who applies the diff is the only actuator.

`tapm remediate --cheat` runs a patch author that first tries to game the verifier (declassify the bucket, add a
suppression comment, add a `data "external"` shell-out). All three are rejected by the edit policy before anything
runs.

## pytm models its own AI layer

`ai/self_model.py`, `tapm ai-model`. pytm 1.4 ships `LLM` and `Agent` elements and nine threats for them
(LLM01-LLM09). The command writes two plain pytm models: this pipeline's AI layer, with every attribute citing the
code or test that enforces it (no tools: `tools_offered_to_models = []`; filtered input: `bundle.py`; validated
output: validation checks), and a *hypothetical* unsafe PR-reviewer design (raw diff in the prompt, tools, repository
credentials). For each threat the classifier says whether it fires, depends on undecided attributes, or cannot
fire, and which attribute decides it. This pipeline: 0 fire, 1 depends on the decision provider (LLM04, training
data), 8 cannot fire; the unsafe design: 8 fire. A regression that offers the model a tool shows up as a pytm
threat as well as a failing test (`tests/test_ai_self_model.py`).

## Artifacts

| File | Plane | Content |
|---|---|---|
| `terraform-plan.json` | truth | sanitised plan (sensitive values redacted, `prior_state` and provider config dropped) |
| `resource-graph.json` | model | nodes, edges, notes, unresolved policies |
| `iam-relationships.json` | model | IAM edges and the statements behind them, with scope statement |
| `threat-model.py`, `dfd.*`, `seq.puml`, `pytm-threats.json` | model | executable PyTM model, DFD, sequence diagram, pytm's findings |
| `pytm-controls.json`, `threat-library.json`, `pytm-findings.json` | model | evidence-fed facts, the pinned threat library, classified findings linked to hops |
| `remediations.json`, `remediation-PATH-###.diff` | AI + model | verified remediation attempts and the accepted patch (never applied) |
| `ai-threat-model/` | AI | `tapm ai-model`: pytm models of this AI layer and of an unsafe design, `ai-threats.json` |
| `attack-paths.json`, `attack-paths.sarif` | model | paths, hops, preconditions, what-if |
| `scanner-findings.json`, `baseline-*.json` | evidence | normalised and raw scanner output |
| `evidence.json` | evidence | the ledger |
| `ai-annotations.json`, `jev-decisions.json`, `validation.json`, `ai-metrics.json` | AI | every annotation with its verdict, every decision, cost and latency |
| `questions.json` | model | the open threats as yes/no questions, and the status of every answer |
| `dfd-overview.*`, `dfd-risk.*` | model | pytm `levels={0}` (path elements only) and `--colormap` by what the plan decides |
| `report.md` | output | the PR comment, opening with each path in plain words |
| `story.md` | output | every path in plain words for anyone (no addresses, file names or evidence IDs) |
| `run-manifest.json` | output | versions, hashes, timings |

## Module map (Plan §23 names → this repository)

| Plan | Here |
|---|---|
| `src/terraform/` | `src/tapm/terraform/` |
| `src/graph/` | `src/tapm/graph/` |
| `src/iam/` | `src/tapm/iam/` |
| `src/pytm/` | `src/tapm/pytm_gen/` (named to avoid shadowing the `pytm` package) |
| `src/attack_paths/` | `src/tapm/paths/` |
| `src/evidence/` | `src/tapm/evidence/` |
| `src/reporting/` | `src/tapm/report/` |
| `agents/*` | `src/tapm/ai/agents.py` + `src/tapm/ai/prompts/*.md` |
| `harness/router`, `validators`, `policies`, `adapters` | `ai/jev.py`, `ai/validator.py`, `ai/harness.py`, `ai/llm.py` |
| `evaluations/gold`, `runners`, `metrics`, `results` | `fixtures/*/gold.yaml`, `evaluations/tier2/gold/`, `src/tapm/eval/`, `evaluations/results/` |
| `scripts/demo.sh`, `benchmark.sh`, `replay.sh` | `make demo`, `make benchmark`, `make replay` |
| `.github/workflows/pr-security.yml` | `examples/github-actions/pr-security.yml`; the standalone CI is `.github/workflows/ci.yml` plus `.github/workflows/critic.yml` |

## Trigger matrix and CI integration

CI workflows (`examples/github-actions/pr-security.yml`, `examples/gitlab/.gitlab-ci.yml`) enforce this trigger matrix:

| Event | Runs | Can block? |
|---|---|---|
| PR changes `*.tf`, `*.tfvars`, `*.tfvars.json`, `.terraform.lock.hcl` or a consumed module | plan, scanners, deterministic engine, AI explanations, verified remediation (`--remediate`), gate | At `validate` and above |
| PR changes only `attack-path-exceptions.yaml` or `threat-answers.yaml` | gate re-evaluation from cached artifacts (no new plan needed) | At `validate` and above |
| Re-push with no change to any evidence bundle | cache hit | No |
| Paths exist | asynchronous AI enrichment | Never |
| Nightly on the default branch | sharded sweep, canaries, expiries (`examples/github-actions/nightly-canary.yml`) | Opens an issue |
| Model, prompt, engine, pytm, scanner or provider version changes | replay, negative tests, canaries, AI regression subset | Blocks the upgrade, not PRs |
| Weekly | false-path sample (M8) | No |

### Multi-root module scaling and sharded nightly sweep (`tapm matrix`, W1.5)

For monorepos or repositories with dozens to hundreds of root modules (Critic B M4):
- **Dependency mapping:** `tapm matrix` automatically discovers root modules and local shared modules (e.g. `modules/*`), resolving local `module "name" { source = "..." }` references transitively.
- **Affected root detection:** Changed files (`*.tf`, `*.tfvars`, lock file, exceptions, answers) are mapped to their containing module. Changes to a shared module automatically propagate to all consuming root modules.
- **CI matrix output:** `tapm matrix --changed ... --format github` emits a `matrix.include` JSON object for GitHub Actions / Gitea Actions (or `--format gitlab`), allowing dynamic CI fan-out so runners only plan and evaluate affected root modules.
- **Sharded nightly sweep:** `tapm matrix --all --shards N --shard-index I` partitions all root modules deterministically across $N$ parallel runners, sweeping default branch attack paths and canaries efficiently.

### False-path disputes (`disposition: not_reachable`, W0.4)

When developers identify a reported attack path that is not reachable in reality (e.g. out-of-band network controls, environment barriers, or modeling limitations), they can dispute it in `attack-path-exceptions.yaml` (Critic B M5):
- **Syntax:** `disposition: not_reachable`, with `id`, `entry`, `target`, `owner`, and `reason` (explaining why the path is not reachable). `expires` is optional; compensating controls are not required.
- **Review:** Reviewed by AppSec through `CODEOWNERS` (`kit/CODEOWNERS.example`).
- **Gate:** Treated as decided: does not block the PR at `validate` or `prevent` (`tapm gate` reports `disputed as not reachable`).
- **Metrics (M8):** Counted into metric M8 (false-path rate) by `tapm measure`. Unlike accepted risks, disputes do not count into M6 (accepted-risk coverage) or M12 (accepted-risk hygiene), preventing false-positive inflation of risk acceptance metrics.

