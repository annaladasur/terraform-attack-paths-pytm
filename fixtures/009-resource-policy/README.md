# 009-resource-policy

A grant that exists only in a resource-based policy. Identity-policy-only analysis misses it. IMDSv2 is required, so the precondition is code execution in the workload (RCE), not SSRF.
