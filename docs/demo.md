# The demo

After networked dependency installation, `make demo` replays the canonical fixture offline with `LLM=simulated`, no cloud credentials and no model API key. Runtime depends on the machine. Each beat is
also its own `make` target, so it can be run one at a time on stage.

```bash
make setup
make demo           # = pr scan · paths model story ask · explain tamper inject · gate remediate replay-fix (the talk's four live parts)
```

The table below shows illustrative simulated/cached outputs, not live-model measurements. Schema/reference validation does not prove statement truth or general injection resistance.

| # | Target | Shows | Key line |
|---|---|---|---|
| 0 | `make pr` | PR #42: three small diffs in three files | `+ cidr_blocks = ["0.0.0.0/0"]`, `+ http_tokens = "optional"`, `+ Resource = ["arn:aws:s3:::*"]` |
| 1 | `make scan` | Checkov / tfsec / Trivy on the PR (saved baselines, pinned versions) | `40 findings across 9 resources, each reported in isolation.` |
| 2 | `make model` | plan → typed graph → IAM → PyTM fed with evidence | `2 ALLOWS … <- inferred from IAM policy JSON`; `122 threats → 8 decided by the plan · 110 questions for the app team · 12 ruled out` |
| 3 | `make paths` | the attack path, hop by hop, with source locations and what-if | `40 isolated scanner findings -> 1 coherent path` |
| 3b | `make story` | the same path in plain words, for anyone on the team, with a glossary | `HIGH: Someone on the internet could list and read the customer-data bucket …` |
| 4 | `make explain` | Jev decisions and five AI annotations (one re-tells the path in plain words), each validated | `5 generated · 5 evidence-backed · 0 rejected` |
| 5 | `make remediate` | the model proposes a patch; the pipeline re-plans it and proves the effect | `attempt 1 … PROVEN_DOWNGRADE high -> medium` / `attempt 2 … PROVEN_BREAK … no new paths` |
| 6 | `make tamper` | strip the evidence from an accepted annotation and re-validate | `ANN-001 (tampered): REJECTED … evidence_present: annotation cites no evidence` |
| 7 | `make inject` | fixture 019: unsafe vs. safe pipeline, paths with comments stripped | `INFLUENCED` / `REJECTED` / `attack paths … identical` |

Extra beats: `make canary` (Level 5: known-bad plans must block, known-good must pass), `make security-tests` (scripted negative cases; current output lists the count), `make replay` (10/10 byte-identical), `make ai-model` (pytm
threat-models this AI layer: LLM01-LLM09), `tapm remediate --cheat` (three attempts to game the verifier, all
rejected by the edit policy), `make experiment` (v1 vs v2, needs a model).

## The scenario

The orders service goes live. Before PR #42 (`demo/base/`), the ALB admitted only `10.0.0.0/8`, the instance
required IMDSv2, and the app role could read only the reports bucket: 36 scanner findings and no path. The PR opens
the ALB to the internet, relaxes IMDS "for a legacy agent" and widens the report export to `arn:aws:s3:::*`. That
adds 4 findings (36 → 40) and one HIGH path:

```
Internet ─EXPOSES(443)→ aws_lb.web ─ROUTES_TO(8080)→ aws_instance.app ─ASSUMES[workload_ssrf]→ aws_iam_role.app ─ALLOWS(read)→ aws_s3_bucket.customer_data
           FACT                      FACT                               ASSUMPTION                                 FACT            (confidential)
```

Each change looks medium on its own. The path runs through all three.

## Artifacts

`artifacts/006-public-workload-iam-sensitive-bucket/` holds `report.md` (the PR comment), `dfd.png`, `seq.puml`,
`threat-model.py` with `pytm-controls.json` and `pytm-findings.json`, `attack-paths.json` / `.sarif`,
`evidence.json`, `ai-annotations.json`, and after `make remediate`, `remediations.json` and
`remediation-PATH-001.diff`. See [architecture.md](architecture.md#artifacts).

`make conference` writes the same set, plus `prompt-injection.json` and `ai-threat-model/`, to
`artifacts/conference/`.
`conference-snapshot/` is the committed copy, byte-identical apart from timings in `run-manifest.json`.

## AI backends

| `LLM=` | What runs | Needs |
|---|---|---|
| `recorded` | recorded model responses from `cassettes/`, otherwise the labelled offline stand-in | nothing |
| `simulated` (default) | deterministic templates (`simulated`) and the instruction-following stand-in for injection (`simulated-naive`) | nothing |
| `anthropic` | Default model set in `src/tapm/ai/llm.py` (override with `TAPM_ANTHROPIC_MODEL`), JSON-schema output, no tools | `ANTHROPIC_API_KEY`, `pip install '.[anthropic]'` |
| `openai` | OpenAI chat completions with a strict JSON schema | `OPENAI_API_KEY`, `TAPM_OPENAI_MODEL`, `pip install '.[openai]'` |
| `ollama` | local model | `TAPM_OLLAMA_MODEL`, a running Ollama |

| `JEV=` | What decides routing and escalation |
|---|---|
| `local` (default) | deterministic rules with the same question and answer shapes as Jev; probabilities are rule outputs, not calibrated |
| `typesafe` | TypeSafe Jev (`POST https://api.typesafe.ai/v1/systemone`, `TYPESAFE_API_KEY`) |
| `recorded` | recorded Jev answers from `cassettes/jev/` |

Record once, replay offline: `RECORD_LLM=anthropic RECORD_JEV=typesafe make record`, then
`make demo LLM=recorded JEV=recorded`. Explicit `LLM=recorded` picks up the model cassettes (with a labeled offline stand-in when absent); recorded Jev answers must be
asked for explicitly because a missing Jev cassette is an error, not a fallback. Every annotation records which
backend produced it.

## Recovery

| If this fails on stage | Do this |
|---|---|
| Wi-Fi, API, DNS | nothing: the default demo is offline |
| a live model is slow or down | `make demo LLM=simulated` for explicit offline replay; recorded replay is optional |
| the laptop's venv breaks | Use `make docker-demo` only after building and testing the image while dependencies are available |
| the terminal itself | `conference-snapshot/`: open `report.md` and `dfd.png` |
| terminal and container unavailable | Walk through the committed `conference-snapshot/report.md` and `dfd.png`; speaker recordings are not part of this standalone lab |

Don't debug on stage. Move to the next layer and keep talking.
