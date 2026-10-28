# Evaluation

> **Scope of this page.** The tables describe frozen historical measurements, including the original
> 14-case scripted AI check. The current `make security-tests` command lists additional regression cases;
> it is not a new live-model accuracy estimate. Small n: synthetic/scripted results measure regression coverage.
> Ground truth remains one human labeler plus automated blind review, with eight disputed proposals disclosed;
> see [blind adjudication](../evaluations/blind-review-2026-10-19/README.md).
> The public snapshot preserves hashes but cannot independently prove private Git chronology:
> [release scope](../PUBLIC-RELEASE.md). Existing held-out results are in
> [tier2-heldout.json](../evaluations/results/tier2-heldout.json); proposed additional independent corpora remain future work.

What was measured, how to reproduce it, and how much weight each number can bear. Definitions are in
[methodology.md](methodology.md#metrics). The generated results are in
[`evaluations/RESULTS.md`](../evaluations/RESULTS.md).

## Headline numbers

| Claim | Number | Weight |
|---|---|---|
| Real-world reachability, **blind first run** (Tier 2) | precision 87.5%, recall 77.8% (TP 28, FN 8, FP 4, TN 1) | the number to quote |
| Real-world, second run after general fixes | precision 97.1%, recall 91.7% (TP 33, FN 3, FP 1, TN 4) | measured on the corpus the fixes were made against; quote only next to the blind run |
| Synthetic fixtures (Tier 1) | 14/14 paths, 0 false paths, 100% edge and IAM accuracy | internal consistency and regression coverage, not accuracy: same author as the engine |
| Determinism | 21/21 fixtures byte-identical over 10 runs, and across `PYTHONHASHSEED` values | strong: this is a property, not an estimate |
| Scanner coverage of gold-path hops | Checkov 28.6%, tfsec 59.2%, Trivy 34.7% | generous to scanners: a finding *on* a hop is not a connection *between* hops |
| PyTM on the architecture alone | 1,682 threats over Tier 1, 0 paths | every control pytm cannot see counts as missing |
| PyTM fed with plan evidence | 94 decided by the plan, 1,515 questions for the app team, 176 ruled out (61 of the decided come from the 7-threat cloud pack) | the classification is exact given the facts; the facts are only as good as the engine |
| TerrARA's benchmark (13 documented vulnerabilities, [evaluations/terrara](../evaluations/terrara/README.md)) | blind first run: 6/13 covered, no paths; after the general fixes it prompted: 13/13 (5 attack paths, 8 yes/no questions, 3 of those on the first screen), 171 items to read vs. TerrARA's 488 threats | ground truth pre-registered by the same authors; a question points at the right control, it does not show the bug; TerrARA's numbers are quoted, not re-run |
| Verified remediation (simulated author) | 10 of 14 Tier-1 paths broken by a patch proven by re-planning; 1 downgraded; 3 need a new resource or a design change. What-if agreed with the re-plan 17/17 | measures the verifier and the plan cache, **not a model** |
| AI (simulated backend) | 70 generated, 65 accepted, 0 rejected, 5 held for human review | a property of the templates, validator and routing, **not of any LLM** |
| AI boundary | 14/14 deliberately bad outputs refused by the intended check | tests the validator, not a model |

## Reproduce

Everything replays from committed inputs. There is no cloud account, API key, Terraform or scanner in the loop:

```bash
make setup
make benchmark      # Tier 1: 21 fixtures, 10 replays each  -> evaluations/results/
make report         # regenerates evaluations/RESULTS.md
.venv/bin/tapm tier2 --tag rerun    # Tier 2 from frozen plans and baselines (replays saved plans/baselines and vendored source; upstream clones are needed only when regenerating inputs)
```

To regenerate the *inputs* too (plans and scanner output), you need the pinned toolchain:

```bash
make tools setup-scanners           # Terraform 1.16.4, aws 6.66.0 mirror, tfsec 1.28.14, Trivy 0.74.0, Checkov 3.3.20
.venv/bin/tapm bench --live-scanners
bash scripts/start-moto.sh          # Tier 2 plans answer data sources from a local AWS mock (see evaluations/tier2/README.md)
```

`evaluations/results/manifest.json` records tool versions, the prompt version, the LLM and decision backends, and
artifact hashes for every run.

## Corpus

**Tier 1** (`fixtures/`): 21 small configurations, each isolating one behaviour. Gold labels were committed before
the engine first ran on each fixture (`git log -- fixtures/*/gold.yaml`). Fixture 006 is the development fixture and
is not a blind test. 019 is 006 with injection comments, and 020 has benign security comments.

**Tier 2** (`evaluations/tier2/`): TerraGoat (`terraform/aws`), IAM-Vulnerable (default free modules) and 8 CloudGoat
scenarios, at pinned commits. Labels are reachability claims written from each project's documentation. See
`ADJUDICATION.md` for the three disputed labels and the accepted limitation.

## Where each layer helped, and where it did not

This is from `evaluations/DEVELOPMENT-LOG.md`, which the talk draws on.

**Deterministic engine**
* The first Tier-1 run matched 19/21 fixtures. Both misses were engine bugs, and the gold labels were right: a
  synthetic node was never created, and a `startswith` check broke on module-prefixed addresses.
* The blind Tier-2 run missed 8 and falsely reported 4. Fixes were general (customer-managed policy references,
  Deny-aware admin equivalence, the `aws` account namespace, conditional escalation, public non-wildcard CIDRs, the
  EC2 user-data primitive), not per-case.
* Remaining misses: 3 labels are disputed (users that hold a permission but no way to use the role it affects). 1
  false positive is a Condition the engine flags but cannot evaluate.

**Scanners**
* Checkov, tfsec and Trivy each report every hop's misconfiguration somewhere. None connects them. On the demo PR,
  7 of 40 findings are causal.
* The fix that breaks the demo path (scoping the IAM policy) leaves the scanner count at 40 (lab Level 2).
* Scanner suppressions remove all seven causal findings while the path stays HIGH (lab Level 3).

**AI**
* The validator caught real template errors: S3 examples on non-S3 targets named permissions no evidence granted.
* It also had false positives that had to be fixed (quoted scanner severities read as escalation, and "not a
  proven exploit" read as an exploit claim).
* Routing was too conservative at first (symbolic policy recovery sent 25 annotations to humans).
* With a naive, instruction-following model, comments included in the prompt flip the summary to "secure". The
  validator rejects it.

**PyTM, fed with evidence**
* An unfed pytm model reported the unknowns as weaknesses: 122 threats on the demo, none of them tied to the path.
  Fed with plan facts, 8 are decided by the plan (one on every hop of PATH-001) and 110 are questions for the app
  team; six yes/no questions settle 34 of them.
* Feeding pytm exposed two pytm 1.4 behaviours worth knowing: `check()` copies `protocol`, `port` and
  `isEncrypted` from a flow's sink element (so flow-level settings are overwritten), and a flow with no
  `tlsVersion` is below any listener's minimum.

**Verified remediation**
* The loop found an engine over-approximation (grants on one `for_each` instance matched every instance) and a
  verifier gap (a patch that moved a public grant to another bucket was accepted because the path disappeared).
  Both were fixed; see the development log.
* The static what-if and the offline re-plan agreed in every attempt they both judged (17/17), including the one
  where IMDSv2 changes nothing because the instance itself is internet-exposed.

**Where AI was worse than deterministic**
* Priority, reachability and "is this a path" are never asked of a model, by design. The early LLM-generated threat
  model (the abandoned v1, see the talk) could not be replayed, and it disagreed with itself across runs.
* Framework mapping from a controlled vocabulary is mostly lookup. The model's value is the rationale sentence, not
  the ID.

## Not yet measured

| Gap | How to close it |
|---|---|
| Live-model accuracy and variability | `make record RECORD_LLM=anthropic`, then `make experiment` with its recorded-model configuration; report per-backend acceptance and variability |
| Live patch author | `tapm remediate <fixture> --llm anthropic --record`; report proposals, policy rejections and verified-fix rate per backend (needs Terraform for plans not in the cache) |
| Whether "questions for the app team" help | ask an app team to answer them for one service and count how many pytm threats that resolves |
| Usefulness of annotations to developers | a small user study (time to triage, fix correctness) |
| Second reviewer on gold labels | `docs/methodology.md#labeling-protocol-for-a-second-reviewer` |
| Additional independently labeled held-out corpus | Extend beyond the existing held-out set; commit labels before running the engine and disclose reviewer independence |
| Cost at scale | `ai-metrics.json` records tokens and cost per call; multiply by paths per PR |
