# 011-iam-condition

IAM Condition keys are not evaluated (runtime context is not in the plan). The grant becomes a conditional edge and the path is reported with status `review` and an explicit `condition_satisfied` precondition. Note that an SSRF on the instance itself would originate inside the VPC, so the condition may well hold.
