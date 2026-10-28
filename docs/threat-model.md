# Threat model of this tool

A security tool that reads attacker-controlled input and publishes to a PR is itself an attack surface. This is the
threat model for running `tapm` in CI on pull requests, followed by what the prototype does not solve.

## System and trust boundaries

```
 PR author (untrusted)                     CI runner (trusted, ephemeral)                     External services
 ─────────────────────                     ──────────────────────────────                     ─────────────────
 *.tf, comments, tags,   ──► checkout ──►  terraform plan (read-only creds, OIDC)
 IAM Sids, module refs                        │  plan.json  ◄── SENSITIVE: may hold secrets in cleartext
                                              ▼
                                           sanitizer ─► deterministic engine ─► evidence ledger
                                              │                                     │
                                              │                    EvidenceBundle (minimal, scrubbed)
                                              │                                     │ ───────────────►  LLM provider
                                              │                                     │ ◄─ JSON only ───  (no tools)
                                              │                                     │ ───────────────►  Jev (TypeSafe)
                                              ▼                                     ▼ ◄─ typed choice ─
                                           validator (deterministic) ──► report.md / SARIF ──► PR comment
```

Boundaries: **(B1)** PR content → CI; **(B2)** CI → model and decision providers; **(B3)** model output → published
report.

## Assets

| Asset | Why it matters |
|---|---|
| Plan JSON | Terraform documents that plans can contain sensitive values in cleartext, including through machine-readable output. |
| Cloud credentials used for `plan` | read access to the real account |
| LLM / Jev API keys | cost and quota; identity with the provider |
| Integrity of the security result | a wrong "no path" is worse than no tool |
| The PR comment / code-scanning alert | developers act on it |

## Threats and mitigations (STRIDE)

| # | Threat | Boundary | Mitigation | Status |
|---|---|---|---|---|
| S1 | A PR modifies the workflow, Makefile or tool version to exfiltrate secrets | B1 | Run on `pull_request`, never `pull_request_target`, for fork PRs. Use read-only `permissions:`. Pin the tool by commit SHA. Keep secrets out of fork runs. | documented (`examples/github-actions/pr-security.yml`) |
| S2 | A compromised GitHub Action or scanner binary (for example the March 2026 trivy-action compromise, CVE-2026-33634) | B1 | Pin actions by full SHA. Tools are fetched with verified checksums (`scripts/fetch-tools.sh`). Scanners run from saved baselines by default. | tools pinned; actions: **pin by SHA before use** |
| T1 | Prompt injection through comments steers the AI summary | B1→B2 | Comments never enter the plan. Excluded from bundles. Tainted `CMT-###`. Validator check 14. | tested (`make inject`, lab 3) |
| T2 | Prompt injection through plan values (IAM `Sid`, `Condition` values, ARNs) | B1→B2 | Instruction-like strings are withheld from the bundle; the ledger keeps the original | tested; 0 false positives on 2,985 records |
| T3 | Model output invents resources, permissions, edges or paths, or downplays severity | B3 | schema/reference/heuristic validator; adversarial reviewer; Jev escalation to human review | tested with scripted negatives (`make security-tests` reports current cases) |
| T4 | The AI stage mutates the security result | B3 | No write path from the harness to graph, paths or ledger | tested (`test_ai_stage_cannot_mutate_security_truth`) |
| T5 | A PR hides a path by removing a classification tag | B1 | Out of scope for the engine: classification is an input. Protect classification tags with policy (CODEOWNERS, OPA). The report shows each target's `sensitivity_basis`. | documented (lab Level 2) |
| T6 | A PR silences scanners with `#tfsec:ignore` / `#checkov:skip` | B1 | Paths don't depend on scanners. Suppressions remove findings, never paths (lab Level 3 bonus). | tested (`test_suppression_comments_silence_scanners_not_paths`) |
| R1 | Nobody can reconstruct why an annotation was published | B3 | Every annotation records backend, model, prompt version, bundle hash, validation verdict, reviewer verdict and Jev decision. `run-manifest.json` records versions and hashes. | implemented |
| I1 | Plan secrets are sent to an LLM provider | B2 | The raw plan never goes to a model. The sanitizer drops `prior_state` and provider config and redacts `after_sensitive` and sensitive variables. Bundles carry a minimal allowlisted view per record kind (`_DATA_KEYS`). | tested (`test_sanitizer_redacts_sensitive_values`) |
| I2 | Plan artifacts leak through CI artifacts or logs | B1 | Artifacts contain the sanitised plan only. Upload `plan.json` nowhere. Never commit plans of real infrastructure (`.gitignore`, `make fresh-plan` warning). | documented |
| I3 | Real cloud credentials are used by the offline planner | B1 | The planner strips `AWS_*` from the child environment, injects fake keys and disables credential and metadata lookups | implemented |
| D1 | A huge or adversarial plan exhausts CI (path explosion) | B1 | BFS limits: depth 8, 3 paths per pair, 200 paths overall | implemented |
| D2 | LLM cost blow-up | B2 | Jev routes low-priority paths to `NO_AI`. One call per agent per path. Cost is recorded per call (`ai-metrics.json`). | implemented |
| E1 | An agent gains capabilities (shell, git, cloud) | B2 | No tools are offered, ever. The request carries a single message and a schema. `tapm ai-model` threat-models the AI layer with pytm's LLM/Agent threats; a tool shows up there too. | tested (manifest `tools_offered_to_models: []`; `test_offering_the_model_a_tool_shows_up_as_a_threat`) |
| T7 | A proposed patch is itself an attack: it declassifies the target, suppresses a scanner, adds a `data "external"` shell-out, reads files, or moves the grant elsewhere | B3 | The patch is untrusted model output. Deterministic edit policy (one find/replace inside a cited block, forbidden constructs); applied only to a temporary copy; planned offline with no credentials; accepted only when re-planning proves the effect and adds no path, resource removal, grant, exposure, route, trust or pytm threat. Never applied to the repository. | tested (`tests/test_remediate.py`, `tapm remediate --cheat`) |
| T9 | A PR edits `threat-answers.yaml` to claim a control exists ("yes, we validate input") and so rules out threats | B1 | Answers are attested, not proven: they become `APP-` evidence with trust `attested` and the author's name, only fill attributes the plan leaves undecided (the plan wins), and never add, remove or change an attack path (paths are computed without them). Protect the file with `CODEOWNERS` (app owners plus security) and review it like code. | tested (`tests/test_questions.py`: answers never change a path; the plan wins) |
| T10 | A plain-language card oversimplifies and a reader draws the wrong conclusion | B3 | Cards are generated deterministically from evidence records (no model). The precondition stays in the headline ("if they find a way to…"). The developer card cites file and line for every step. The `plain_explainer` agent's retelling goes through the same validator as every annotation. | tested (`tests/test_story.py`) |
| T8 | A "verified" patch still breaks the service or fails at apply | B3 | Offline plans skip AWS-side validation, and the verifier checks security relationships, not function. The report says "for a human to review and apply"; CI re-runs on the real provider when the human pushes it. | documented |
| T11 | A PR author accepts their own path in `attack-path-exceptions.yaml` or gives it a far-off expiry, to get past the check | B1 | At `validate` the team may accept its own risks by design, and the entry is visible in the diff with an owner and a reason. `tapm gate` caps expiry at 90 days (30 at `prevent`), rejects `TODO` values, and reports expired and unused entries every night. At `prevent` an entry needs a compensating control and `approved_by` other than the owner. `approved_by` is a name typed into a file, so the real control is CODEOWNERS plus branch protection requiring AppSec's review of the file (`kit/CODEOWNERS.example`). | tested (`tests/test_gate.py`); CODEOWNERS is your configuration |
| T12 | The check stops blocking and nobody notices (a dependency upgrade, a changed default, a broken classification tag) | B1 | `tapm canary` nightly: known-bad plans must block and known-good plans must pass, with no accepted risks. Add your own canaries (`canary.yaml`). A failure opens an issue (`examples/github-actions/nightly-canary.yml`). | tested (21/21 fixtures agree with their gold labels) |

## Operating guidance

1. Plan with a **read-only** role via OIDC. The pipeline needs `plan`, never `apply`.
2. Treat `plan.json` as a secret. Delete it at the end of the job and upload only `artifacts/` (sanitised).
3. For fork PRs, run the deterministic pipeline only (`--llm off`), or use recorded mode with no keys.
4. Gate on paths (`tapm gate`, or `--fail-on high`), not on AI annotations. The gate is deterministic.
5. Keep `CODEOWNERS` on classification tags, on `threat-answers.yaml` and on the workflow file.

## What this prototype does not solve

| Limitation | Consequence | Where it shows |
|---|---|---|
| Complete AWS IAM semantics | Conditions are flagged, not evaluated. SCPs, RCPs and session policies are not modeled. Managed policies come from a pinned table. | `review` status; Tier-2 FP on `fp5` (condition not evaluated) |
| Runtime cloud state | Only what the plan describes. Resources created outside Terraform, or by other stacks, are invisible. | cross-stack paths are missed |
| Unknown Terraform values | Known-after-apply values stay unknown. Policies are recovered symbolically from source where possible. | `unresolved_policies` in `resource-graph.json` |
| Provider-specific dynamic behaviour | Default VPCs, implicit ENIs and service-linked roles are not modeled | |
| Application-layer vulnerabilities | SSRF and RCE are **preconditions**, not findings. The tool never claims the app is vulnerable. | `workload_ssrf` / `workload_rce` |
| Actual exploitability | Paths are *plausible*, not proven. The report says so. | status `plausible` |
| Business impact | Only the classification tag. No data volumes or blast radius. | |
| Cross-account complexity | Cross-account trusts are nodes, not followed into the other account | |
| Terraform version drift | Code that current Terraform cannot plan (TerraGoat's 0.11 syntax) needs a legacy toolchain | `evaluations/tier2/README.md` |
| Gold labels | One human labeler plus automated blind review; eight disputed label proposals disclosed. Original-label scores remain frozen by owner decision; no two-human agreement or kappa claim. | `evaluations/blind-review-2026-10-19/`; `docs/methodology.md#ground-truth` |
| Application-layer pytm controls | Input validation, output encoding and session handling are invisible to Terraform, so most of pytm's threats stay "questions for the app team" | `pytm-findings.json` |
| Verified remediation | Only edits inside cited blocks; fixes that need a new resource (a public access block) or a design change are left to a human. Offline plans skip AWS-side validation. | `remediations.json` (`GAVE_UP`) |

> The purpose is to prove that deterministic infrastructure evidence can be transformed into an executable security
> model and safely enriched with AI. It is not a replacement for a cloud security posture tool or a penetration test.
