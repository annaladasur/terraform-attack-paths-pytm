# Standalone release scope and verification

This is the research/lab package accompanying *From Terraform Plan to Attack Paths*. It contains the engine,
synthetic fixtures, replay inputs, guided labs, optional local environments and research evidence. Speaker slides,
private planning documents, local runtime state, model weights and the original private Git history are excluded.

## Start with the local lab

Follow [README.md](README.md): install Python dependencies with network access, then run `make demo` offline.
The default backend is simulated. Docker, Kubernetes, a model service, cloud credentials and scanner downloads
are optional. Review [SECURITY.md](SECURITY.md) before using any real infrastructure input.

The take-home is a repeatable method: identify entry points/assets/trust boundaries; connect permissions and flows;
state application assumptions; propose a control; check the modeled effect; decide what further operational evidence
is needed. Adopt at your own pace. No enrollment, deadline or reporting commitment is required.

## What a snapshot proves

`release-manifest.json` inventories each exported path, mode and SHA256 plus the source revision.
It provides a byte-comparison baseline, **not** a signature, independent label validation or historical chronology.

Before installation, verify exact inventory (including unexpected files):

```bash
python3 scripts/verify-public.py
```

After installation/runtime output, verify tracked and nonignored source files, or just frozen research material:

```bash
python3 scripts/verify-public.py --tracked
python3 scripts/verify-public.py --frozen
make report-check
```

The manifest is intended for the initial reviewed snapshot. Future source changes require their own review and a
new manifest/release. It does not authorize self-updating accepted inputs or silently absorbing new files.

## Historical limits

Frozen result JSON retains original source and label commit IDs. Those objects belong to the original private
research history and are not distributed. `tapm verify-precommit` therefore returns a failure for unavailable
ancestry/label-commit purity; it must not be described as passing on this snapshot. Gold-file hashes can still be
checked locally. Historical “pre-registered” or “labels committed first” statements in research documents report
that earlier process; they cannot be independently established from this public snapshot alone.

`make critic` reports historical C8 and private talk-only C12/C14 as **N/A** with reasons. Its C8 branch additionally
requires frozen snapshot hashes to match; failure is a failure. Runtime, report, replay, tool-pin and secret checks
remain enabled. N/A is not a passed historical test.

One human labeler plus automated blind review, with eight disputed label proposals disclosed; original-label
scores remain frozen. No two-human agreement/kappa claim. Read the linked adjudication before citing accuracy.

## Provenance correction, 2026-10-28

Two benign-corpus manifest references contained incorrect full expansions of documented short commit IDs:

| Module | Original unresolved full ID | Verified source ID |
|---|---|---|
| terraform-aws-s3-bucket | `8a0b69784e27f09a3fc3d2d9ad0c1032df3f487e` | `8a0b697adfbc673e6135c70246cff7f8052ad95a` |
| terraform-aws-rds | `7c839958ad3d8d6411516e87b7a1a08ea2257904` | `7c83995e3898fff639c74ce4cc7a72e61e7952c6` |

Each recovered commit resolves upstream. All four vendored Terraform files per module match it byte-for-byte.
Only the two full references in the current manifest/source notice were corrected. Labels, source bytes, plans,
baselines and result bytes were retained. This establishes a current source match; it is not retrospective proof
of which Git object a historical run read. Original result metadata remains unchanged. Exact file hashes and
upstream license retrievals are in [third-party/upstream-verification.json](third-party/upstream-verification.json).

## Test scope

The standalone suite exercises the engine, modeled IAM/network behavior, path/evidence contracts, annotation
boundary, security negatives, simulated remediation, services and local-lab scripts. It also confirms historical
verification fails closed when its objects are absent, while frozen label hashes still match.

Two integration modules are excluded from the export: `tests/test_recordings.py` and
`tests/test_deck_determinism.py`. They require private speaker media/build assets.
Six slide-comparison tests in `test_false_path_story.py`, `test_m1_parity.py` and `test_roster.py` are explicitly
skipped with the reason that the speaker deck is outside this release. No runtime/security test is skipped for
that reason. Test reports must retain these counts; do not call this the complete monorepo presentation suite.

## Release preparation

From the reviewed source checkout, `scripts/export-public.py DESTINATION --revision COMMIT` reads committed
package blobs into a **new** directory. It refuses an existing destination, links, private Git metadata, environment
state and selected runtime paths. It never imports branches or tags. Review its inventory, run secret checks and
a clean installation/demo/test pass, then create a new standalone Git history. The legacy history-publishing
`split-repo.sh` path is disabled; `--verify` still checks required package files.

Check repository visibility separately. A private repository is suitable for review but cannot serve as an
anonymous attendee destination. Add the deck's attendee URL/QR only after anonymous public access and a clean
clone have been verified. Do not infer native slide playback, spoken rehearsal or venue readiness from code tests.
