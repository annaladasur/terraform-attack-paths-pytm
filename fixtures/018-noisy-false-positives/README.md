# 018-noisy-false-positives

Scanner noise without a path. The 0.0.0.0/0 rule sits on an internal load balancer's security group, and the instance metadata endpoint is disabled, so the role's credentials are not obtainable from the workload.
