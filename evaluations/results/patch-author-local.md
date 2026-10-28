# Automated Patch Author Evaluation (Local Model)

- **Backend:** `ollama`, model `qwen3-coder:30b`
- **Canonical Fixtures Evaluated (3):** `006-public-workload-iam-sensitive-bucket`, `002-public-s3`, `013-count`
- **Paths Attempted:** 4
- **Verified Fix (Breaks Path):** 1 (25.0% (1/4, 95% CI [4.6%, 69.9%]))
- **Verified Downgrade Only:** 0 (0.0% (0/4, 95% CI [0.0%, 49.0%]))
- **No Verified Fix:** 3 (75.0% (3/4, 95% CI [30.1%, 95.4%]))
- **Proposals Attempted:** 11
- **Proposals Re-planned Offline:** 7 (63.6% (7/11, 95% CI [35.4%, 84.8%]))
- **Proposals Accepted (Proven):** 1 (9.1% (1/11, 95% CI [1.6%, 37.7%]))
- **Rejections by Edit Policy:** 4
- **Rejections by Verifier:** 6
- **Unverified Proposals:** 0
- **Re-planning Progressions:** 1 paths successfully adapted across attempts
- **Per-Proposal Latency:** p50 `12564.0 ms`, p95 `19198.0 ms` (mean `11802.3 ms`)
- **Cost:** `$0.00` (local model)

## Evaluated Paths and Proposed Patches

| Fixture | Path | Target Resource | Result | Recommended Attempt | Attempts |
|---|---|---|---|---|---|
| `006-public-workload-iam-sensitive-bucket` | `PATH-001` | `aws_s3_bucket.customer_data` | `PROVEN_BREAK` | Attempt 2 | 2 |
| `002-public-s3` | `PATH-001` | `aws_s3_bucket.exports` | `NO_VERIFIED_FIX` | — | 3 |
| `013-count` | `PATH-001` | `aws_s3_bucket.customer_data` | `NO_VERIFIED_FIX` | — | 3 |
| `013-count` | `PATH-002` | `aws_s3_bucket.customer_data` | `NO_VERIFIED_FIX` | — | 3 |

### Attempt Details & Re-Planning

#### `006-public-workload-iam-sensitive-bucket` — `PATH-001` (HIGH)
- **Attempt 1 (hop 4, `iam.tf`):** status `REJECTED` (edit policy) · reasons: find appears 2 times in iam.tf (must be exactly once)
- **Attempt 2 (hop 4, `iam.tf`):** status `PROVEN_BREAK` (verification) · reasons: none
  - Verified effect: `breaks_path` (re-planned offline: `plan-cache`)

#### `002-public-s3` — `PATH-001` (HIGH)
- **Attempt 1 (hop 2, `main.tf`):** status `REJECTED` (edit policy) · reasons: find appears 3 times in main.tf (must be exactly once)
- **Attempt 2 (hop 2, `main.tf`):** status `REJECTED` (edit policy) · reasons: find appears 3 times in main.tf (must be exactly once)
- **Attempt 3 (hop 2, `main.tf`):** status `REJECTED` (edit policy) · reasons: find appears 3 times in main.tf (must be exactly once)

#### `013-count` — `PATH-001` (MEDIUM)
- **Attempt 1 (hop 4, `iam.tf`):** status `REJECTED` (verification) · reasons: no effect on PATH-001: still medium
  - Verified effect: `no_effect` (re-planned offline: `plan-cache`)
- **Attempt 2 (hop 4, `iam.tf`):** status `REJECTED` (verification) · reasons: no effect on PATH-001: still medium
  - Verified effect: `no_effect` (re-planned offline: `plan-cache`)
- **Attempt 3 (hop 4, `iam.tf`):** status `REJECTED` (verification) · reasons: no effect on PATH-001: still medium
  - Verified effect: `no_effect` (re-planned offline: `plan-cache`)

#### `013-count` — `PATH-002` (MEDIUM)
- **Attempt 1 (hop 4, `iam.tf`):** status `REJECTED` (verification) · reasons: no effect on PATH-002: still medium
  - Verified effect: `no_effect` (re-planned offline: `plan-cache`)
- **Attempt 2 (hop 4, `iam.tf`):** status `REJECTED` (verification) · reasons: no effect on PATH-002: still medium
  - Verified effect: `no_effect` (re-planned offline: `plan-cache`)
- **Attempt 3 (hop 4, `iam.tf`):** status `REJECTED` (verification) · reasons: no effect on PATH-002: still medium
  - Verified effect: `no_effect` (re-planned offline: `plan-cache`)

> Addresses Slide 13 claim (Claims audit #38): The model proposes patch candidates; the deterministic edit policy bounds the syntax, and offline re-planning deterministically proves the security effect. No proposed patch is ever automatically applied to the repository without human review.
