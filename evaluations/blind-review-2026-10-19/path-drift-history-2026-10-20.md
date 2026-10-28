# A36 historical path provenance, October 20

The historical committed 38-path benchmark and current 38-path result reproduce at all six tested actual engine revisions. Historical Oct15 37-path observations remain recorded but are not reproduced, even using the exact observation-commit CLI and historical manifest/gold/plan/baselines. No exact path responsible for 37 can be identified. A separate exact 38-to-38 path replacement and general code change is established, without attributing the 37 observation to it.

All six actual revisions reproduced 38 paths with the frozen plan. Exact historical CLI runs also reproduced 38. No saved 37-path bundle was found: its cause remains unverified. The separately proven path replacement preserves the total of 38 and does not explain 37. Current beat10 runs the actual command; saved runtime remains historical.

Raw evidence: [compressed JSON](path-drift-history-2026-10-20.json.gz). Decompressed SHA256: `68d38a995dbbb6918ee0cea54bd064923c6e0e858f30cd79de693253050f2451`. Independent automated critic, not a human evaluation. Original gold/results unchanged.
