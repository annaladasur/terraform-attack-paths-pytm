# Developer study kit

| File | What |
|---|---|
| [protocol.md](protocol.md) | design, participants, procedure, measures, pre-stated analysis, threats to validity |
| [questionnaire.md](questionnaire.md) | pre, per-task and post questions (column names match the CSV templates) |
| `make_materials.py` | builds `materials/` (per task: the Terraform plus conditions A, B and C), `answer-key.yaml` and `assignments.csv` from the fixtures |
| `score.py` | scores `responses.csv` against the key, then runs the planned tests, κ and SUS |
| `responses-template.csv`, `participants-template.csv` | the data layout |

```bash
python paper/study/make_materials.py                       # after any change to the pipeline's output; freeze before the pilot
python paper/study/score.py responses.csv participants.csv --json results.json
```

Freeze `materials/` and `answer-key.yaml` (commit them) before the pilot. Do not regenerate them during the study.
