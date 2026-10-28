# Fix Branch (`fix`)

This branch applies the verified least-invasive remediation (`remediation-PATH-001.diff`) to PR #42:
- `iam.tf`: Restricts the wildcard `Resource = ["arn:aws:s3:::*"]` back to `Resource = [aws_s3_bucket.reports.arn, "${aws_s3_bucket.reports.arn}/*"]`.

The attack path is broken; no path reaches the confidential bucket `aws_s3_bucket.customer_data`.
The gate check passes cleanly (exit code 0).
Plan reproduces the proven fix plan byte for byte.
