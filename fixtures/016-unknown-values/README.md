# 016-unknown-values

Unknown values. The policy document is `(known after apply)`; the evaluator recovers its structure from source, binds `.arn` references to graph nodes, and recovers `local.report_objects` (locals are not in the plan) from the HCL. The reports grant covers objects only, so it is read without list.
