# Level 1: Run

**Goal:** see 40 isolated scanner findings turn into one attack path, and check that every hop and every AI
sentence points to evidence.

```bash
make setup      # once
make lab-1
```

## 1. The pull request

```bash
bash scripts/pr-diff.sh
```

PR #42 changes three lines in three files: the ALB's ingress opens from `10.0.0.0/8` to `0.0.0.0/0`, the instance
allows IMDSv1, and the app role's S3 read widens from the reports bucket to `arn:aws:s3:::*`. Each change looks
medium on its own.

## 2. What the scanners say

```bash
.venv/bin/tapm scan labs/workspace
```

Checkov 17, tfsec 13, Trivy 10: 40 findings across the resources, each reported in isolation.

## 3. What the pipeline says

`make lab-1` runs three steps.

**Model.** The plan becomes a typed graph. Look for the `ALLOWS` line:

```
  permissions    2 ALLOWS · 0 ESCALATES   <- inferred from IAM policy JSON; Terraform never states these
  GRAPH-001  aws_iam_role.app --ALLOWS--> aws_s3_bucket.customer_data ['s3:GetObject', 's3:ListBucket']
```

Terraform never says "the app can read the customer bucket". The IAM evaluator derived it from the policy JSON and
the bucket ARN.

**Paths.**

```
PATH-001  HIGH  plausible   key e67244a5e4f5

  Internet
    FACT       --EXPOSES(HTTPS/443)-->  aws_lb.web
               GRAPH-017: NET-001 alb.tf:3, NET-003 network.tf:72-78
    FACT       --ROUTES_TO(HTTP/8080)-->  aws_instance.app
               GRAPH-020: NET-005 network.tf:94-100
    ASSUMPTION --ASSUMES(instance_profile)-->  aws_iam_role.app  requires workload_ssrf
               GRAPH-003: IAM-002 iam.tf:4-13, TF-004 app.tf:10-13
    FACT       --ALLOWS(list,read)-->  aws_s3_bucket.customer_data
               GRAPH-001: IAM-001 iam.tf:25-35

  40 isolated scanner findings  ->  1 coherent path
  (7 of the findings sit on causal hops: SCAN-016, SCAN-018, SCAN-020, SCAN-022, SCAN-023, SCAN-031, SCAN-032)
  fix hop 1: Remove internet reachability of aws_lb.web: restrict the 0.0.0.0/0 ingress rule to known  => breaks the path
  fix hop 3: Require IMDSv2 on aws_instance.app: metadata_options { http_tokens = "required" }  => downgrades high->medium
  fix hop 4: Scope aws_iam_role.app's policy so it no longer grants list,read on aws_s3_bucket.custom  => breaks the path
```

**AI enrichment.** Jev (the local stand-in) routes the path to four agents. Each annotation is checked by the
validator before it is shown.

## 4. Look inside

Everything is in `artifacts/lab-1/`:

| Open | To see |
|---|---|
| `report.md` | the PR comment a developer would get |
| `dfd.png` | the generated data-flow diagram |
| `threat-model.py` | the PyTM model; run it yourself: `.venv/bin/python artifacts/lab-1/threat-model.py --dfd \| dot -Tpng -o my.png` |
| `evidence.json` | the ledger; find `NET-003` and check its `source` against `labs/workspace/network.tf` |
| `ai-annotations.json` | each annotation's `evidence_refs`, `validation` and backend |

## Questions

1. Which hop is an ASSUMPTION, and what would an attacker need?
2. Three findings sit on hop 3 (Checkov, tfsec and Trivy each flag IMDSv1). Which tool flags hop 4?
3. The `reports` bucket is also readable through the same path. Why is there no PATH-002?
4. Pick any sentence in ANN-001. Which ledger record backs it?

<details><summary>Answers</summary>

1. Hop 3, `ASSUMES`, requires `workload_ssrf`: the attacker must make the instance send an HTTP request to the
   metadata service (SSRF), which works because IMDSv1 is allowed (`TF-004`, `app.tf:10-13`).
2. Only tfsec (`aws-iam-no-policy-wildcards`). Checkov and Trivy do not flag the wildcard resource on this inline
   policy.
3. `reports` is tagged `DataClassification = internal`. Paths are reported only to confidential or restricted
   assets, secrets and account admin (`docs/methodology.md#assets-targets`). Its `ALLOWS` edge is still in the graph.
4. Each bracketed ID (for example `[GRAPH-017, NET-001, NET-003]`) is a record in `evidence.json`. The validator
   rejects an annotation that cites an ID that doesn't exist, that wasn't in the agent's bundle, or that doesn't
   support the resource, action or edge named in the sentence.

</details>

Next: [Level 2](level-2.md).
