# Paper: CODASPY 2027 draft

Working title: *From Terraform Plans to Attack Paths: Evidence-Fed Threat Modeling that Developers Can Answer*.

The OWASP talk and the paper share one codebase but make different claims:

| | OWASP Global AppSec (Nov 5–6, 2026) | CODASPY 2027 |
|---|---|---|
| Claim | "you can run this in CI tomorrow" | "evidence-fed classification + question selection reduce what developers must read without losing known vulnerabilities, and developers can act on the result" |
| Evidence | live demo, Tier 1/2, AI boundary | formalization (§4–5), TerrARA head-to-head with a pre-registered ground truth, **developer study** |
| Novelty that must carry the paper | – | three-valued classification of an unmodified threat library under plan evidence; path-first question selection; attested answers that cannot change a path |

## Dates

These come from the call as found by search on 2026-09-29; codaspy.org was blocked from the build environment. **Check them on the CFP.**

| | |
|---|---|
| Abstract registration | Nov 16, 2026 |
| Paper submission | Nov 23, 2026 (research papers; also Dataset / Tool / Bluesky / SoK tracks) |
| Rebuttal | Jan 18–22, 2027 |
| Notification | Jan 25, 2027 |
| Camera-ready | Mar 26, 2027 |
| Conference | Jun 14–17, 2027, Fort Collins, CO (HotCRP: codaspy27.hotcrp.com) |

**Track.** Submit as a research paper only if the developer study (RQ6) has run. Without it, the fit is the Tool track.
Check that track's page limit and artifact requirements.

## Build

```bash
python paper/make_numbers.py      # numbers.tex from evaluations/results and conference-snapshot ("??" if an input is missing)
cd paper && latexmk -pdf main.tex # TeX Live with acmart (Debian/Ubuntu: texlive-publishers texlive-fonts-extra texlive-plain-generic)
```

No number in `main.tex` is typed by hand: every result is a `\Num...` macro from `numbers.tex`. Re-run
`make_numbers.py` after `make benchmark`, `tapm tier2`, `python -m tapm.eval.terrara` and `make snapshot`.

## Double-blind: what to do before submitting

The talk and this repository are public **before** the deadline, so the submission must not point at them.

- **Tool name.** Use `\sys` (PlanPath) in the paper, not `tapm` or the talk title.
- **Artifact.** Submit an anonymized copy (e.g. anonymous.4open.science) made from a scrubbed export. It must contain:
  - no `talk/`, `deck/`, `labs/` or conference snapshot;
  - no git history;
  - no author, employer or session links;
  - no OWASP references.
- **Talk.** Do not cite it. Check the CFP's rules on prior non-archival presentations and preprints, and follow them. If the rules require it, declare the talk to the PC chairs rather than in the paper.
- **Self-citation.** Anything the authors published must be cited in the third person.
- **Metadata.** Remove PDF metadata (`\hypersetup{pdfauthor={}}`; acmart `anonymous` already hides the author block).

## What the paper still needs (the `\todo`s)

| Item | Why reviewers will ask | Where it lives |
|---|---|---|
| Developer study (RQ6), *n* ≥ 24, half without security training | the paper's central claim is about developers | [study/](study/) (protocol, materials, key, scoring) |
| Second labeler for Tier 2 and the TerrARA ground truth, with κ | the authors wrote both | `evaluations/tier2/ADJUDICATION.md`, `evaluations/terrara/known-vulns.yaml` |
| Live-model runs (two providers, recorded cassettes) for RQ4/RQ5 | the simulated backend proves the validator, not the models | `tapm explain --llm anthropic --record`, `tapm remediate --llm ...` |
| \|U\| statistics and cap hits; share of open findings with \|Q\| = 1; exact ILP vs greedy on small plans | the formalization needs its numbers | `pytm_gen/classify.py`, `pytm_gen/questions.py` |
| Re-run TerrARA itself on the pinned samples | like-for-like counts instead of quoted ones | TerrARA repo (Memgraph + Docker), `evaluations/terrara/` |
| Related-work survey 2025–26 (LLM-assisted threat modeling), every citation verified | several `refs.bib` entries carry a `verify` field | `refs.bib` |

## Novelty, ranked (for the introduction and the rebuttal)

1. **Evidence-fed classification of an unmodified threat library.** Plan evidence partitions pytm's findings into confirmed, ruled out and open. It is formalized over partial assignments, and it needs no fork of pytm.
2. **Path-first question selection.** The open threats become a handful of yes/no questions. The answers are attested evidence, reviewed like code, and they cannot change an attack path.
3. **Attack paths from the plan with a source-located evidence ledger.** Symbolic recovery of unknown policies, and named preconditions instead of silent assumptions.
4. **Bounded AI.** The model only re-tells evidence (validator) or proposes patches that are re-planned and proved.

TerrARA's own limitations section names implicit policy relationships and threat prioritization as open problems. Items 1–3 address both, and the head-to-head measures it.
