# Developer comprehension study: protocol

**Question (RQ6).** Given the same Terraform change, can developers with and without security training find the way
in, point at the line to change, and pick a fix that works? We compare this with the two representations they get
today.

This is the paper's claim that most needs people rather than benchmarks: "developers don't know threat modeling" is
the gap the tool is built for. Run a pilot before the main study, and get ethics approval (or your institution's
exemption) first. Participants see only synthetic infrastructure.

## Design

Within-subjects, three conditions × three tasks, counterbalanced.

| Condition | What the participant gets with the Terraform files |
|---|---|
| **A. Scanner findings** | Checkov, tfsec and Trivy findings for the plan, merged into one table (tool, rule, severity, resource, file:line, message) |
| **B. Threat list** | the threats pytm reports for an architecture-only model of the same plan (threat ID, title, element, severity), the way an IaC threat modeling tool presents them |
| **C. Path cards** | the tool's developer cards (`tapm story`) and its first six yes/no questions |

| Task | Plan (fixture) | Shape of the way in |
|---|---|---|
| Practice | 002-public-s3 | one hop: a bucket policy lets anyone read |
| T1 | 006-public-workload-iam-sensitive-bucket | internet → load balancer → server (IMDSv1) → role → bucket via a wildcard grant |
| T2 | 009-resource-policy | internet → server (IMDSv2) → role → bucket via the *bucket's* policy |
| T3 | 015-dynamic-blocks | internet → load balancer → server → role → table |

The fixture names are never shown. Materials call the tasks "Plan 1–3" (`make_materials.py`).

**Assignment.** Condition order follows a balanced Latin square for three conditions (six sequences). Task order is
rotated independently, so every condition meets every task equally often. `assignments.csv` lists the order for
participants 1–24. Repeat it in blocks of six for larger *n*.

**Practice.** One practice task in each participant's first condition, untimed, with the answer shown afterwards.

## Participants

- **Target.** *n* ≥ 24 professional developers who write or review Terraform at least monthly. Stratify: at least
  half with no formal security training or threat-modeling experience (pre-questionnaire Q3–Q4).
- **Power.** 24 participants in a paired design detect roughly a medium-to-large effect (d ≈ 0.6 for a paired test at
  α = 0.05, power 0.8). Smaller effects need more participants; decide *n* before the study, not after. The tests,
  stated before running:
  - C vs A and C vs B on the per-participant task score;
  - Holm correction for the two comparisons.
- **Recruitment and compensation.** Per the institution's rules. Recruit outside the authors' teams.

## Procedure (about 45 minutes, remote or in person)

1. Consent and pre-questionnaire, 5 minutes.
2. Five minutes on reading Terraform in the provided editor. There is no security training: the point is what the
   representations teach on their own.
3. Practice task, untimed.
4. Three tasks, one per condition, **at most 10 minutes each**. The timer starts when the materials open and stops
   when the answers are submitted.
5. Post-questionnaire, 5 minutes:
   - SUS for condition C;
   - a ranking of the three representations;
   - two open questions.

Participants may use the editor's search. They may not use the internet or AI assistants. The screen is recorded
only with consent, and only to check timing disputes.

## Measures

For each task (see [questionnaire.md](questionnaire.md)):

| Measure | Item | Scored by |
|---|---|---|
| **Found** | "Can someone outside the company reach sensitive data with this configuration?" yes/no, and which data | key: yes, and the right target |
| **Located** | "Which one line (file:line) would you change first?" | key: inside the source range of a hop's evidence whose fix breaks or downgrades the path |
| **Fixed** | "What would you change there?" (free text) | two coders, blind to condition, code *breaks* / *downgrades* / *does not help*; report Cohen's κ, adjudicate disagreements |
| **Time** | seconds to submit | log |
| **Confidence** | 1–5 | self-report |

**Task score.** Found + Located + Fixed (*breaks* = 1, *downgrades* = 0.5), from 0 to 3.

## Analysis (`score.py`)

- Per condition: the rate for each measure; median and IQR of time; median confidence.
- Paired comparisons on the task score, C vs A and C vs B:
  - exact sign test;
  - Wilcoxon signed-rank (normal approximation with continuity correction);
  - Holm-adjusted *p*.
- The same, split by security training (exploratory).
- SUS score (0–100) for C.
- Coder agreement (κ) for Fixed.

**Report everything, including null results.** A null result on "Found" together with a gain on "Located" and
"Fixed" would itself be informative.

## Threats to validity (to state in the paper)

- **Tasks are synthetic, and the authors built the tool.** The fixtures were not designed for this study, and all
  three conditions describe the same plans.
- **Learning effects across tasks.** Handled by counterbalancing, not eliminated.
- **Condition B is built with pytm, not TerrARA.** TerrARA's output format may differ; say so.
- **Condition C also carries the tool's prioritisation.** Any benefit is the package's, not the plain language
  alone. An ablation (cards without questions, or questions without cards) is future work.

## Pilot

Run with 3 participants who are not in the main study. Fix confusing wording and check the 10-minute cap. Do not
change the tasks or the key after the main study starts.
