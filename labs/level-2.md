# Level 2: Modify

**Goal:** change the Terraform, re-plan it, and check that the path responds the way the deterministic what-if
said it would. This shows the model is computed from configuration, not described.

## 1. Make one change

Edit a file in `labs/workspace/` with any editor, or use a named edit. Start with the change from the Plan:

```hcl
# labs/workspace/network.tf, the "HTTPS from clients" ingress rule (line 77)
    cidr_blocks = ["0.0.0.0/0"]      # before
    cidr_blocks = ["10.0.0.0/8"]     # after
```

or `bash labs/lab.sh apply cidr=10.0.0.0/8`. Then:

```bash
make lab-2
```

```
== Level 2.1  Re-plan the edited Terraform
plan: pre-computed variant (plan-cache/)   scanner baselines: pre-computed scanner run (plan-cache/baselines/)

== Level 2.2  Attack paths after your change
No attack path from the internet to a classified asset.

  39 isolated scanner findings  ->  0 coherent paths

Level 2 checks
  PASS     Terraform edited and re-planned   network.tf
  PASS     attack path changed   PATH-001 no longer exists
  PASS     what-if prediction for hop 1 matches the re-plan   predicted broken, observed broken
  note     scanner findings 40 -> 39; resolved: tfsec aws-ec2-no-public-ingress-sgr

  Level 2 complete.
```

The what-if ran in Level 1 on a copy of the graph. Level 2 re-plans the Terraform for real. The two agree.

## 2. Try the others

Reset between experiments (`make lab-reset`) or stack edits. Every row below is a real re-plan (Terraform 1.16.4,
aws 6.66.0) with real scanner runs:

| Edit | Path after re-plan | Scanner findings | On the path |
|---|---|---|---|
| (none) | high (workload_ssrf) | 40 | 7 |
| `cidr=10.0.0.0/8` | none | 39 | 0 |
| `cidr=10.20.0.0/16` (the VPC) | none | 39 | 0 |
| `cidr=203.0.113.0/24` (public, but narrower) | medium (source_ip_allowed, workload_ssrf) | 40 | 7 |
| `cidr-all=10.0.0.0/8` (editor "replace all") | none | 37 | 0 |
| `imds=required` | medium (workload_rce) | 37 | 4 |
| `policy=narrow` | none | 40 | 0 |
| `policy=narrow-literal` | none | 39 | 0 |
| `alb=internal` | none | 37 | 0 |
| `classification=internal` | none | 40 | 0 |
| `cidr=203.0.113.0/24 imds=required` | low (source_ip_allowed, workload_rce) | 37 | 4 |

## 3. Things to notice

**IMDSv2 downgrades, it does not fix.** With `http_tokens = "required"`, SSRF alone can no longer fetch role
credentials. An attacker needs code execution (`workload_rce`), so the score drops by one (high to medium). The
role still reads every bucket. Three scanner findings disappear, but the path remains.

**The fix that breaks the path can be invisible to scanners.** `policy=narrow` scopes the role to the reports bucket
and breaks the path, yet the scanner count stays at 40: tfsec still flags the `"${...arn}/*"` object wildcard.
Scanner counts are not a measure of risk removed.

**A narrower public range is still public.** `203.0.113.0/24` keeps the path. The `EXPOSES` hop becomes an
ASSUMPTION (`source_ip_allowed`: the attacker must come from that range). The Level 2 check notes that the what-if
modeled a different change (removing internet reachability).

**Classification is an input.** `classification=internal` makes the path disappear because the target is no longer
a target, not because anything was fixed. Who is allowed to change that tag is a governance question the tool
cannot answer.

**Comments and formatting don't count.** Reformat a file or add a comment and Level 2 says
`NOT YET  Terraform edited`. The plan is the same, so the paths are the same. Level 3 builds on this.

## 4. Edits that are not pre-computed

Anything outside `bash labs/lab.sh variants` needs Terraform:

```bash
make tools        # pinned Terraform 1.16.4 + AWS provider mirror, checksums verified (~300 MB download)
make lab-2        # now plans any edit offline, with no credentials
```

Without it you'll see which files you changed and how to undo the edit.

Next: [Level 3](level-3.md).
