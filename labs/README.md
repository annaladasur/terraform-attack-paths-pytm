# Audience lab

Three self-paced levels. No cloud account, no API key, and no Terraform needed for the edits the lab
suggests. Everything runs against `labs/workspace/`, a scratch copy of the demo fixture (the orders service after
PR #42). Your edits never touch the committed fixtures.

```bash
make setup          # once: Python 3.11+, downloads dependencies and creates .venv
make lab-1          # Run: find the path, read its evidence
make lab-2          # Modify: fix one hop in Terraform, re-plan, compare with the what-if
make lab-3          # Attack the AI: hide an instruction in a comment
make lab-reset      # start over
```

Each level ends with a check block:

```
Level 1 checks
  PASS     typed graph built from the plan   25 nodes, 50 edges, 2 ALLOWS inferred from IAM JSON
  PASS     PyTM model generated and executed   threat-model.py, 118 PyTM threats from the evidence-fed model
  PASS     attack path found   PATH-001 high plausible
  PASS     every hop cites ledger evidence   95 evidence records
  PASS     AI annotations validated against the evidence   5 accepted, 0 rejected, 0 human review

  Level 1 complete.
```

| Level | Guide | You will see |
|---|---|---|
| 1. Run | [level-1.md](level-1.md) | Connect scanner findings into a modeled path; inspect bounded annotations and their evidence references |
| 2. Modify | [level-2.md](level-2.md) | your Terraform change is re-planned and the path breaks or is downgraded, as the what-if predicted |
| 3. Attack the AI | [level-3.md](level-3.md) | Inspect simulated comment-injection examples and unchanged paths; live-model outcomes may differ |

`make lab-1` and `make lab-3` use `LLM=simulated` by default through Make. Direct `bash labs/lab.sh` defaults to recorded replay with a labeled offline stand-in. Neither default makes a live model call. Example outputs are illustrative; reference checks do not establish semantic truth or universal injection resistance.

## How it works offline

`bash labs/lab.sh` wraps `tapm` commands. Before each level, `tapm lab sync` makes `plan.json` and the scanner
baselines match your sources:

1. **Plan.** The source is hashed after removing comments, formatting whitespace and trailing commas. If the hash
   matches a pre-computed plan in `plan-cache/`, that plan is used. Otherwise `terraform plan` runs offline (no
   credentials; see `docs/architecture.md`), if Terraform is installed.
2. **Scanner baselines.** They come from the exact source hash in `plan-cache/baselines/`. If there is no match,
   live Checkov/tfsec/Trivy runs are used when installed, and otherwise the closest pre-computed run with the same
   configuration.

`bash labs/lab.sh variants` lists the 49 pre-computed edits. All of them are real `terraform plan` and scanner runs
made with the pinned tools (`tapm lab precompute`). Any other edit needs Terraform, which you can get with
`make tools` (pinned, checksum-verified) or the Docker image (`make docker-build`, then `docker run --rm -it
terraform-attack-paths-pytm bash`).

## Named edits (no editor needed)

```bash
bash labs/lab.sh apply                                  # list them
bash labs/lab.sh apply cidr=10.0.0.0/8                  # ALB ingress only
bash labs/lab.sh apply imds=required policy=narrow      # several at once
```

| Edit | Changes |
|---|---|
| `cidr=<cidr>` | ALB ingress range (`network.tf:77`). Pre-computed: `10.0.0.0/8`, `10.20.0.0/16`, `172.16.0.0/12`, `192.168.0.0/16`, `203.0.113.0/24` |
| `cidr-sg=<cidr>` | both security-group rules (ingress and the app's egress) |
| `cidr-all=<cidr>` | what an editor's "replace all `0.0.0.0/0`" does: ingress, egress and the internet-gateway route |
| `imds=required\|optional` | `http_tokens` on the instance (`app.tf:12`) |
| `policy=wide\|narrow\|narrow-literal` | the `ReadReports` statement's `Resource` (`iam.tf:32`) |
| `classification=internal\|confidential` | the customer bucket's `DataClassification` tag |
| `alb=internal\|public` | `internal` on the load balancer |
| `suppress` | scanner-native suppression comments for the seven causal findings |
| `inject` | the prompt-injection comments from fixture 019 |

`cidr`, `imds` and `policy` combinations are all pre-computed.

## Using a live model

```bash
export ANTHROPIC_API_KEY=...        # or OPENAI_API_KEY, or a local Ollama
make lab-1 LLM=anthropic
make lab-3 LLM=anthropic            # does a real model follow your comment? the validator decides either way
```

The default `LLM=recorded` replays recorded responses where they exist and otherwise uses the deterministic
stand-in. The stand-in is labelled `simulated` in every artifact. In Level 3 it is `simulated-naive`, a stand-in
that follows instructions it can see. That makes injection reproducible without a model. It is not a claim about
any particular model.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `No cached plan for these sources and no terraform binary found` | Your edit isn't pre-computed. Undo it, use a named edit, or install Terraform (`make tools`). The message lists what you changed. |
| `scanner baselines: STALE` | Harmless for paths. Install the scanners (`make setup-scanners tools`) for exact counts. |
| `scanner line numbers may be off` | You added comments or re-formatted; findings are from the same configuration without your comments. |
| Level 2 says `NOT YET  Terraform edited` | Comment and formatting changes don't change the plan. That's by design, and it's Level 3's point. |
| Anything else | `make lab-reset` |
