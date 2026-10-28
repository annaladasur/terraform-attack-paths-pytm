# Terraform attack paths with PyTM

**From Terraform plan to attack paths: PyTM threat modeling in CI/CD, with LLMs on a leash.**

A working research prototype for connecting cloud configuration findings into evidence-linked attack paths.
Start with a synthetic AWS workload, inspect the trust boundaries and IAM relationships, then change one hop
and check whether the modeled path remains. The default lab needs no cloud account or model API key.

```text
Terraform plan → typed graph → IAM + network relationships → executable PyTM model
                             → attack paths + evidence → bounded AI annotations
```

## Start here

Requires **Python 3.11+**, Git, Make and Bash. Run from the repository root on macOS or Linux;
on Windows, use WSL. Initial installation downloads Python dependencies. Graphviz is optional for rendering
new DFD images; committed examples are in [conference-snapshot/](conference-snapshot/).

```bash
git clone https://github.com/annaladasur/terraform-attack-paths-pytm.git
cd terraform-attack-paths-pytm
make setup
make demo
```

After installation, `make demo` replays committed plans and scanner baselines offline with
`LLM=simulated` and `JEV=local`. It makes no live model call, applies no infrastructure and needs no AWS credentials.
Installation and runtime depend on the machine; no setup-time promise is implied.

Open `artifacts/006-public-workload-iam-sensitive-bucket/report.md`, `story.md`, `attack-paths.json`
and `threat-model.py`. Read the generated path as four connected steps:

```text
Internet → public load balancer → application workload → IAM role → customer-data bucket
                                ↑ application compromise is an explicit assumption
```

The configuration supports network exposure and permissions. It does **not** demonstrate an exploited application,
actual data access, or deployed enforcement. A removed modeled path is evidence about the model under its assumptions.

## What to try

| Command | What to inspect |
|---|---|
| `make paths` | Entry points, assets, FACT / ASSUMPTION hops and source locations |
| `make model` | Executable PyTM model, generated DFD and classified threats |
| `make ask` | Application questions that Terraform cannot settle |
| `make tamper` | Rejection when an annotation loses its evidence references |
| `make inject` | Bounded prompt-injection examples, using the simulated backend by default |
| `make remediate` | Simulated patch proposals, policy checks and replayed model effects |
| `make gate` | The vulnerable fixture blocked by the local deterministic check |
| `make replay-fix` | The prepared fixed fixture passing the same check |
| `make replay` | Repeated artifact-hash comparisons |
| `make security-tests` | Negative checks for the annotation boundary |

`make remediate` replays matching cached plans for supported edits. A fresh plan needs the optional pinned toolchain;
the default does not download Terraform or run an AWS deployment. Generated patches require review before use.
`make gate` intentionally prints the vulnerable example's blocked exit; it is an instructional wrapper.
Use `tapm gate` directly when CI needs the actual nonzero exit status.

## Guided labs

Work in a scratch copy, leaving committed fixtures unchanged:

```bash
make lab-1      # Run: follow the path and its evidence
make lab-2      # Modify: change a supported hop and compare the result
make lab-3      # Attack the AI: inspect comment-injection boundaries
make lab-reset  # Reset only the lab scratch workspace
```

Follow [labs/README.md](labs/README.md). The labs use precomputed edits and cached plans; they do not provision cloud resources.

## The method and its limits

The workflow follows threat modeling's four questions: what are we building, what can go wrong, what will we do,
and did we do enough? The typed graph and DFD make processes, assets, flows and trust boundaries visible;
PyTM evaluates threats against evidence-backed attributes. Application assumptions remain questions for people.
Read [the architecture](docs/architecture.md), [methodology](docs/methodology.md),
[security contract](docs/contract.md) and [the tool's threat model](docs/threat-model.md).

Graph construction, path discovery, priority and the path gate are deterministic. Models provide bounded annotations
and patch proposals in a host-controlled workflow. The annotation router can affect publication/review routing;
that is distinct from changing a path verdict. Seven role prompts are not a deployed autonomous multi-agent system.

“On a leash” means constrained inputs, defined roles/output schemas, reference checks, no model-exposed tools,
and verification of proposed changes. Valid references and schema checks do **not** prove semantic correctness.
No-tool access does not by itself prevent disclosure or provide a sandbox. Local examples illustrate controls;
enterprise identity, approval routing, classifier promotion and runtime attestation need additional implementation.

## Evaluation: read the qualifications with the numbers

The frozen first-run real-world reachability scores are **28/32 precision (87.5%)** and **28/36 recall (77.8%)**.
They use the original labels. One human labeler plus automated blind review produced **eight disputed label proposals**;
the owner retained the frozen results with those disputes disclosed. There is no second-human agreement or kappa claim.
Synthetic fixtures authored alongside the engine provide regression coverage, not independent accuracy validation.

Start with [evaluation scope](docs/evaluation.md), [generated results](evaluations/RESULTS.md),
[blind-review/adjudication](evaluations/blind-review-2026-10-19/README.md), and
[ground-truth methodology](docs/methodology.md#ground-truth).

This standalone release is a snapshot. It preserves frozen gold/result bytes and source hashes, but carries no private
Git history. Historical “labels committed before engine runs” statements refer to the original research repository;
public replay cannot independently establish that chronology. `tapm verify-precommit` deliberately fails when those
historical objects are unavailable. [PUBLIC-RELEASE.md](PUBLIC-RELEASE.md) explains verification and excluded presentation tests.

AWS only. IAM Conditions are flagged rather than evaluated; SCPs, RCPs and session policies are outside scope.
Reachability depends on modeled permissions, network rules and explicit application assumptions. Simulated AI figures
measure the controlled harness rather than live-model reliability or safety. Citation checks are not an injection-proof guarantee.

## Optional environments

### Local stack

For a local PR/CI demonstration with Docker Compose, Gitea, a runner and the review service:

```bash
make local-up
make local-pr
make local-status
make local-down
```

Read [examples/local-stack/README.md](examples/local-stack/README.md) first. Image/dependency downloads and local ports
are required. This separate environment uses documented demo credentials; isolate it from production networks.
An Ollama-backed live run is optional and requires its model prepared separately: see [docs/demo.md](docs/demo.md).

### Enhanced lab

The optional Kubernetes exercise creates local namespaces/services and needs `k3d` or `kind` plus its documented images:

```bash
make lab-cluster
make lab-cluster-pr
make lab-cluster-down
```

See [examples/local-cluster/README.md](examples/local-cluster/README.md). Neither environment is needed for the CLI lab.

## Apply the concept at your own pace

Use [the take-home kit](kit/README.md) and [CHALLENGE.md](CHALLENGE.md) to select a small, representative workload,
write down entry points/assets/trust boundaries, replay a plausible path, and compare one proposed control.
Choose observe/recommend before considering enforcement; validate assumptions and establish accountable exceptions.
There is no scheduled reporting commitment or required adoption deadline.

```bash
.venv/bin/tapm --help
make test
make report-check
```

`make report-check` regenerates the frozen report and checks for a diff. `make benchmark report` is an explicit
benchmark rerun that can update evaluation outputs; it is not required for the attendee lab.
Optional live backends: `LLM=ollama`, `anthropic` or `openai` (additional model/SDK/configuration needed).
`LLM=recorded` replays saved outputs. `LLM=simulated` is the default.

## Safety, provenance and contributions

Treat raw Terraform plans and state as sensitive. The prototype supplies a minimal evidence bundle to the model;
self-hosted or enterprise hosting alone does not authorize disclosure. See [SECURITY.md](SECURITY.md).
Use synthetic inputs first and review cloud-facing integration examples before adapting them.

[Contributing](CONTRIBUTING.md) · [Apache-2.0 license](LICENSE) ·
[Third-party notices](THIRD-PARTY-NOTICES.md) · [Release provenance](PUBLIC-RELEASE.md).
