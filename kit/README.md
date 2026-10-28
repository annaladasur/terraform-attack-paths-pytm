# Attack paths on every Terraform change: the kit

This kit lets you add an attack-path check to the Terraform pull requests you already run. You keep your scanners and
your CI. You start by observing, and you enforce only when your own numbers say you're ready. It works without the
talk it came from (OWASP Global AppSec US 2026).

**The transformation it targets:**
> **Before:** each Terraform change gets a pile of per-resource scanner findings, and our threat model is a diagram
> someone drew once.
> **After:** each Terraform change shows the attack paths it opens, from entry to data, with a file and line for
> every hop. The author answers a few yes/no questions. Before merge, every path above our threshold is either fixed,
> with the fix proven by re-planning, or accepted by a named owner with an expiry.

| File | Use it for |
|---|---|
| [`executive-one-pager.md`](executive-one-pager.md) | The page for your AppSec lead or engineering leadership |
| [`architecture.md`](architecture.md) | What to build, where it runs, and what to use if you already have X |
| [`adoption-ladder.md`](adoption-ladder.md) | Five levels, from observe to continuously validate. Start at 1 |
| [`30-60-90.md`](30-60-90.md) | Readiness checklist: scope, observe, verify, decide and reassess (legacy filename) |
| [`decision-matrix.md`](decision-matrix.md) | Merge or not, which findings first, is the fix real, can the AI sentence stay, does the accepted risk stay |
| [`metrics.md`](metrics.md) | M1-M16: definitions, sources, targets |
| [`baseline-worksheet.csv`](baseline-worksheet.csv) | Your local baseline and later comparison points (`tapm measure` fills most of it; legacy column names) |
| [`failure-modes.md`](failure-modes.md) | What not to do, when not to use this, and the known limits |
| [`prerequisites.md`](prerequisites.md) | Data, permissions, infrastructure, skills, integrations, ownership, and answers to the usual objections |
| [`attack-path-exceptions.example.yaml`](attack-path-exceptions.example.yaml) | The accepted-risk file, with comments |
| [`CODEOWNERS.example`](CODEOWNERS.example) | Who reviews answers and accepted risks |
| [`../examples/`](../examples/) | GitHub Actions (PR check and nightly canary), GitLab CI, local use |
| [`../CHALLENGE.md`](../CHALLENGE.md) | Self-directed method guide; no enrollment or report-back requirement |

**Optional ways to inspect the method:**
1. `make setup && make demo` in this repository: offline, no cloud account, no API key.
2. Read `executive-one-pager.md`.
3. Run `tapm run` on one of your own root modules (`../examples/local/README.md`), then `tapm gate --level observe` and
   `tapm measure`. That's your first baseline row.
