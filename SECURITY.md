# Security

## Trust model

* The default CLI demo and audience labs do not provision cloud infrastructure or run `terraform apply`. Optional local-stack/cluster targets create local services; cloud integration examples require a separate deployment review.
* All attack-path examples are synthetic (`fixtures/`) or based on frozen public artifacts at pinned commits
  (`evaluations/tier2/`: TerraGoat, IAM-Vulnerable, CloudGoat, planned against a local AWS mock).
* No credentials are required for the default demo, the lab or the benchmark. The offline planner removes any real
  `AWS_*` variables from Terraform's environment and injects fake keys.
* **Terraform plan artifacts must be treated as sensitive.** Terraform documents that plan files and
  `terraform show -json` output can contain sensitive values in cleartext. Never commit plans of real
  infrastructure, do not publish raw plans as CI artifacts. This prototype does not send raw plans to a model. The pipeline writes only a
  sanitised plan (`artifacts/*/terraform-plan.json`: sensitive values redacted, `prior_state` and provider
  configuration dropped). Models receive only a minimal evidence bundle.
  A different deployment may authorize a sanitized, richer context after reviewing classification, purpose,
  access, logging, retention and output destinations. Self-hosting or an enterprise agreement does not replace
  that decision; sanitization must cover free text and inferred sensitive context as well as marked secrets.

The committed `plan.json` files describe synthetic fixtures with fake account IDs (`111122223333`) and fake ARNs.

## Running it on your own pull requests

See [docs/threat-model.md](docs/threat-model.md#operating-guidance). In short:

1. Plan with a read-only role via OIDC. The tool never needs write access.
2. Trigger on `pull_request`, never `pull_request_target`, and keep secrets away from fork PRs.
3. Pin every GitHub Action to a full commit SHA,
   and pin this tool to a commit.
4. Gate on deterministic paths (`tapm gate --level validate`, or `--fail-on high`), not on AI annotations.

## Reporting a vulnerability

Please report security issues privately through GitHub's **Report a vulnerability** (Security → Advisories) on this
repository rather than in a public issue. Include the fixture or plan shape that triggers it, if any. Reports about
the AI boundary are especially welcome: an annotation that should have been rejected but was accepted, or a way for
PR content to reach a model unmarked.

## Supply chain

Tool versions are pinned and release checksums are verified by `scripts/fetch-tools.sh` (Terraform 1.16.4,
hashicorp/aws 6.66.0, tfsec 1.28.14, Trivy 0.74.0). Python dependencies use exact pins or bounded version ranges in `pyproject.toml`, and Checkov
3.3.20 runs in its own virtualenv.
