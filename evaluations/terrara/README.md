# Head-to-head on TerrARA's benchmark

TerrARA (Tran, Sion, Yskout, Joosen; ACM CODASPY 2025) is the closest published work: Terraform in, enriched DFD, 72 cloud threat types through the SPARTA engine. Its relevance evaluation (Table 4) asks one question: **does the output cover each known vulnerability?** It covered 26 of 28 with 715 elicited threats.

We ask the same question, on the same nine samples, of what this pipeline hands a developer. That output has three parts:

- attack paths;
- pytm threats that the plan confirms;
- yes/no questions for the app team.

We also count how much there is to read.

Results: [RESULTS.md](RESULTS.md) (generated), `../results/terrara.json`, and the first run in `../results/terrara-first-run.json`.

## Samples and ground truth

[manifest.yaml](manifest.yaml) pins every sample at a commit.

| Group | Samples | Ground truth |
|---|---|---|
| TerrARA hand-crafted | isolated_process, isolated_datastore, simple_dataflow, cross_trust_boundary, nested_subnet | **none published**: "one vulnerability each", never named. Counts only. |
| Public | CloudGoat glue_privesc | README walkthrough: 2 vulnerabilities |
| Public | KaiMonkey | **none published**: TerrARA counts 9 without naming them. Counts only. |
| Public | AWSGoat module 1, module 2 | attack manuals: 7 + 4 vulnerabilities |

TerrARA's workbook gives only per-sample counts, so we wrote our own list from each sample's walkthrough: [known-vulns.yaml](known-vulns.yaml), 13 vulnerabilities. For each one it records:

- the resources involved;
- the threat kinds that count as covering it;
- the pytm controls whose question points at it.

The list was **committed before the pipeline ran on the samples** (`57e3e8f`) and has not changed since. Our 13 overlap TerrARA's 28 on these three samples, where TerrARA reports 13 of 13 covered with 488 threats.

## What counts as covered

Coverage is listed from strongest to weakest:

| Category | Meaning |
|---|---|
| `path` | An attack path runs through the vulnerability's resources, reaching its target if one is named. Only vulnerabilities marked as paths in the ground truth can be covered this way. |
| `confirmed` | A pytm threat of the right kind that the plan **confirms** on one of the resources. |
| `asked` | A yes/no question to the app team, on one of the resources, about a control the vulnerability names. |
| `generic` | Only a generic pytm threat of the right kind on those resources. This is TerrARA's own criterion ("a threat exists"). |

We also report which covered vulnerabilities fit on the **first screen**. That screen holds every path, every plan-confirmed threat, and the first 6 questions, which is what `tapm ask` shows by default.

**Items to read** means paths, plus plan-confirmed threats, plus all questions. They are not the same kind of thing as a TerrARA threat:
- a path is a chain with evidence;
- a question needs one yes or no.

Compare the counts with that in mind.

## First run, then the engine changes it caused

**First run** (`terrara-first-run.json`): **zero attack paths on all nine samples**. 6 of 13 vulnerabilities were covered (5 asked, 1 confirmed) and 7 were not. The benchmark had found real gaps, all of them general AWS semantics rather than anything specific to a sample:

| Gap | Seen in | Change |
|---|---|---|
| API Gateway was not an internet entry | AWSGoat m1, 4 hand-crafted samples | REST and HTTP APIs that are not PRIVATE, with a route that has no authorization, `EXPOSE` the API. The API `ROUTES_TO` its Lambda, instance or load balancer. The edge to a Lambda is conditional unless an `aws_lambda_permission` lets API Gateway invoke it. |
| ECS services were not modelled | AWSGoat m2, KaiMonkey | A service registered in a target group gets `ROUTES_TO` from the load balancer. Its task role (`task_role_arn`, trusted by `ecs-tasks`) is reachable with `workload_rce`. On EC2 capacity it can also reach the **host's** instance role; see the next row. The execution role is never handed to the container, so it is not an edge. |
| Container to host role | AWSGoat m2 | The host is found through `ECS_CLUSTER=<name>` in its user data, which is the ECS agent's own configuration. The precondition follows the host's IMDS settings. A host that drops container traffic to 169.254.169.254, or sets `ECS_AWSVPC_BLOCK_IMDS`, needs a new precondition, **`container_escape`**. Settings that make escape easy (`pid_mode = host`, `SYS_PTRACE`, privileged) are reported in the evidence but do not change the score. |
| Glue job PassRole | glue_privesc | New rules `PE-PASSROLE-GLUE-JOB` (`glue:CreateJob` + `glue:StartJobRun`) and `PE-PASSROLE-GLUE-UPDATE-JOB`. The dev-endpoint variant already existed. |
| A policy written onto a role you can act as | AWSGoat m1 and m2 | A principal that can `iam:AttachRolePolicy` or `iam:PutRolePolicy` on a role, and can also take that role over (for example with `lambda:UpdateFunctionCode` on the function that runs as it), is admin in effect: `PE-POLICY-ON-ASSUMABLE-ROLE`. |
| Quoted keys in `jsonencode({ "Statement" : [...] })` | AWSGoat m1 | python-hcl2 keeps the quotes on keys. The recovered policy therefore had no `Statement` and was silently empty. Keys are now unquoted. |
| `AmazonSSMFullAccess` unresolved | glue_privesc | Added to the managed-policy summaries and marked approximate, like the others. |

Separately, two samples' **documented goals** became declared targets, as Tier 2 already does for CloudGoat:
- glue_privesc: the SSM parameter `flag`.
- AWSGoat module 1: the users table, which manual 04 shows holds emails, password hashes and addresses.

Neither is tagged, so neither was classified. This is run configuration, not ground truth.

After the changes:
- The Tier 1 corpus still matches its gold labels, and the full test suite passes.
- Tier 2 is unchanged: 33 TP / 3 FN / 1 FP / 4 TN, with the same paths per case.
- New tests: `tests/test_engine_coverage.py`, plus the small authored fixture `tests/data/glue-job-passrole`.

**Second run**: **13 of 13** covered:
- 5 by an attack path that matches the walkthrough;
- 8 by a yes/no question on the right resource, 3 of them on the first screen.

The 5 remaining questions rank 7 (2) and 20 (3). We did not retune the question ranking to this benchmark.

TerrARA's paper reports the same kind of loop: 14 detection rules were added after its dataset exposed gaps, each taking 5 minutes to an hour to write.

## Caveats (threats to validity)

- **We did not re-run TerrARA.** Its numbers are quoted from the paper and workbook. It needs Memgraph and its own Docker image; a re-run is future work.
- **Our ground truth is ours.** It was written from the walkthroughs and pre-registered, but by the same people who built the pipeline. The per-vulnerability matching rules are public in `known-vulns.yaml` so anyone can dispute them.
- **"Asked" is weaker than "path".** A question points the app team at the right control on the right resource. It does not show that the bug exists. SQL injection, XSS and IDOR are invisible in Terraform; every tool that reads only IaC can at most point at where they would live.
- **All five paths came after engine changes the benchmark prompted.** The first-run numbers are the blind result. The second run shows the rules generalise across Tier 1 and Tier 2 without regressions; it is not a blind test.
- **Six of nine samples have no ground truth.** They contribute counts only. They are TerrARA's hand-crafted samples and KaiMonkey.
- **Plans.**
  - The public samples' plans are committed; their licenses are BSD-3, Apache-2.0 and MIT.
  - TerrARA's hand-crafted samples have no license. They are cloned at the pinned commit and planned locally into `artifacts/terrara/` (not committed); nothing from them is redistributed.
  - TerrARA's samples, KaiMonkey and AWSGoat m2 are planned with `hashicorp/aws` 3.76.1 or 5.24.0, the providers of their time, because aws 6 removed arguments they use.

## Reproduce

```bash
make tools && bash scripts/fetch-tools.sh --terrara   # Terraform + aws 3.76.1 / 5.24.0 mirror (checksums verified)
bash scripts/start-moto.sh &                           # AWS API mock for data sources (no AWS account)
export TAPM_PROVIDER_MIRROR_TERRARA=$PWD/.tools/terrara-mirror
python -m tapm.eval.terrara                            # writes RESULTS.md and ../results/terrara.json
```

Committed plans are reused, so the public samples need no Terraform. The hand-crafted samples are planned on first use.
