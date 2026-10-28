# PR #42 Branch (`pr-42`)

This branch contains the changes for pull request #42 ("go-live"):
- `network.tf`: Opened ALB ingress to `0.0.0.0/0` (HTTPS/443).
- `app.tf`: Relaxed IMDS `http_tokens` to `"optional"`.
- `iam.tf`: Widened S3 permission `Resource` to `["arn:aws:s3:::*"]`.

These three changes introduce **PATH-001** (HIGH):
`internet -> aws_lb.web -> aws_instance.app -> aws_iam_role.app -> aws_s3_bucket.customer_data`

The gate check at Level 3 (validate) BLOCKS this pull request (exit code 3).
Plan reproduces fixture 006 byte for byte.
