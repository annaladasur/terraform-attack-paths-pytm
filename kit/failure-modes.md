# Failure modes: what not to do

1. **Don't block on day one.** Enforcing before you've measured false paths (M8) produces overrides, then a check
   everyone ignores. Two weeks of observe, then recommend.
2. **Don't let a model write the threat model or decide severity.** This project started that way. The same plan gave
   a different model on every run, so nothing could be diffed, replayed or audited. Paths and priorities stay in
   deterministic code.
3. **Don't send `plan.json` to a model, and don't upload it as an artifact.** A plan can hold secrets in cleartext.
   `tapm` sanitizes what it writes. The AI layer sees evidence records, never the raw plan.
4. **Don't read "no path" as "secure".** The check only knows what the plan says:
   - AWS resources only.
   - Terraform-visible IAM only: SCPs, RCPs and session policies are out of scope.
   - IAM `Condition`s are flagged, not evaluated.
   - App-layer bugs become questions, not findings.
   - Resources created outside Terraform don't exist for it.
5. **Don't accept a risk without an owner and an expiry, and don't accept by PATH number.** Path numbers follow the
   ranking. Accept by entry, target and `via`, which `tapm gate --draft` writes for you.
6. **Don't count threats.** A longer threat list isn't more security. Measure paths merged without a decision (M5),
   verified fixes (M7) and time to a decision (M9).
7. **Don't drop your scanners.** They find per-resource problems (encryption, logging, tagging) that aren't on any
   path. Paths decide which findings go first.
8. **Don't trust a fix you haven't re-planned.** A quiet scanner doesn't prove the path is gone. Use the
   remediation loop's verdicts.
9. **Don't let the questions become a click-through form.** A "yes" rules threats out. Put `threat-answers.yaml` under
   CODEOWNERS and review it like code.
10. **Don't give the plan job write access or long-lived keys.** Use a read-only role through OIDC, pin every action to
    a full commit SHA, and run on `pull_request`, never `pull_request_target`, for forks.
11. **Don't start at `--fail-on medium`.** Start at `high`, and lower the threshold at Level 4 if M8 stays low.
12. **Don't let AI annotations gate anything.** They explain; the gate reads paths only. If you turn a model off, the
    check behaves the same.

## When not to use this (yet)

- **No Terraform plan in CI.** Click-ops, CloudFormation or Pulumi are not supported. Fix plan generation first, or
  use your cloud platform's runtime view.
- **Not AWS.** Other providers' resources are in the graph but no paths are computed through them.
- **No IAM or network surface.** A static site with one public bucket gets little beyond what a scanner already says.
- **You can't classify data.** Paths end at sensitive data. Without tags or naming, every path is `review`, and the
  review load won't drop.

## Known limits of the reference implementation

| Limit | Measured where |
|---|---|
| Tier 1 fixtures were written by the same author as the engine; perfect scores there show consistency, not accuracy | `evaluations/RESULTS.md` |
| Real repositories, blind first run: precision 87.5%, recall 77.8% (TP 28, FN 8, FP 4, TN 1) | `evaluations/tier2/` |
| Gold labels have one labeler; a second reviewer is pending | `docs/methodology.md#ground-truth` |
| Benchmark AI numbers use a simulated backend, which tests the validator, not a model | `evaluations/RESULTS.md` |
| TerrARA comparison: 6/13 known vulnerabilities on the blind run; 13/13 after the engine changes that run prompted | `evaluations/terrara/` |
| Offline plans skip AWS-side validation, so a verified fix can still fail at apply time | `docs/methodology.md#verified-remediation` |
