# Local use

```bash
cd your-terraform-dir
terraform plan -out=tfplan && terraform show -json tfplan > /tmp/plan.json && rm tfplan   # treat plan.json as a secret
tapm run . --plan /tmp/plan.json --out /tmp/attack-paths
open /tmp/attack-paths/report.md
```

The check at an adoption level (`kit/adoption-ladder.md`); exit 3 means blocked:

```bash
tapm gate /tmp/attack-paths --tf-dir . --level validate      # a path at or above high needs a fix or an accepted risk
tapm gate /tmp/attack-paths --tf-dir . --draft               # draft attack-path-exceptions.yaml entries to fill in
tapm measure /tmp/attack-paths                               # counts for kit/metrics.md; no plan data
```

`tapm run . --plan /tmp/plan.json --fail-on high` still works: it exits 3 on any high path and ignores accepted risks.

No cloud access needed to try it: `make demo` in this repository replays committed plans.
