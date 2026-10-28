# Contributing

Thanks for looking. This is a research prototype that accompanies an OWASP Global AppSec US 2026 talk. Issues and
pull requests are welcome, especially the kinds below.

## Useful contributions

* **A fixture that breaks the engine.** Add `fixtures/NNN-name/` with `*.tf`, a `gold.yaml` written *before* you run
  the engine (commit it first), and a one-line `README` of the intent. Plans are generated with `make tools` and
  `.venv/bin/tapm plan NNN`.
* **A second review of gold labels.** Each `gold.yaml` has `reviewer_2: pending`. Follow
  [docs/methodology.md](docs/methodology.md#labeling-protocol-for-a-second-reviewer) and record disagreements.
* **A bad AI output the validator accepts.** Add it to `src/tapm/ai/negative.py` with the check that should catch
  it.
* **Real-world Terraform** for a held-out Tier-2 set: public, permissively licensed, with documented attack paths.

## Rules of the house

1. **Security decisions stay deterministic.** No model call may create, remove or re-prioritise a node, edge, path
   or evidence record. If a feature needs a model to decide something, open an issue first.
2. **Every AI claim cites evidence.** A new agent needs a JSON schema, a prompt in `src/tapm/ai/prompts/`, validator
   coverage and a negative test.
3. **No fabricated numbers.** `evaluations/RESULTS.md` is generated (`make benchmark report`). Don't edit it by hand.
   A changed gold label needs an entry in the adjudication log saying why.
4. **Offline by default.** After networked dependency installation (`make setup`), `make demo` must work offline with no cloud credentials or model API keys.
5. **Deterministic output.** `make replay` must stay 10/10 identical. Sort before you serialise and never write
   timestamps into artifacts.
6. **Never commit** real plans, state, credentials, or customer infrastructure.

## Development

```bash
make setup                 # .venv with dev extras
make test                  # pytest: unit, golden, replay, schema, AI-boundary, lab
make benchmark report      # Tier-1 metrics -> evaluations/
make tools setup-scanners  # optional: pinned Terraform, tfsec, Trivy, Checkov for regenerating inputs
```

Commit messages should say *why*. Pull requests should say what you ran.
