# 017-cross-module-references

Cross-module references: `module.web` gets the instance profile name from `module.iam`, which gets the bucket ARN from `module.data`. The evaluator follows var -> module call -> output -> resource to bind the policy to the bucket.
