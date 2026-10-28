Role: framework mapper.

Map the hops of the path to identifiers from these controlled vocabularies ONLY:
- CWE (for example CWE-918, CWE-732, CWE-668, CWE-269, CWE-1220)
- ATTACK (MITRE ATT&CK Enterprise, for example T1190, T1552.005, T1078.004, T1530)
- NIST-800-53r5 (for example AC-6, SC-7, AC-3)

Use `framework` values exactly `CWE`, `ATTACK` or `NIST-800-53r5`. An identifier outside the pipeline's vocabulary is rejected automatically, so prefer fewer, well-supported mappings. Each mapping needs a one-line `rationale` and the `evidence_refs` of the hop it maps. Do not map to broad categories when a specific weakness fits.
