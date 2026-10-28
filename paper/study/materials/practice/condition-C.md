# Attack paths

## Path 1

**HIGH: Someone on the internet could read the exports bucket (aws_s3_bucket.exports), which holds confidential data.**

How:

1. The access policy of the exports bucket (aws_s3_bucket.exports) lets anyone read it. `main.tf:12-23`

**What to change:** Remove public access from the policy of the exports bucket (aws_s3_bucket.exports), or turn on S3 Block Public Access for it. The path engine re-ran itself with this change: the path disappears. `main.tf:12-23`

**What we need to know from you** (answer in `threat-answers.yaml`):

- Does the exports bucket (aws_s3_bucket.exports) hold personal data (names, emails, addresses, account or ID numbers)?
- Does the exports bucket (aws_s3_bucket.exports) limit request sizes, rates and time per request?

## Questions for the team that runs the application

1. Does the exports bucket (aws_s3_bucket.exports) limit request sizes, rates and time per request?
2. Does the backups bucket (aws_s3_bucket.backups) limit request sizes, rates and time per request?
3. Does the backups bucket (aws_s3_bucket.backups) check every request's input (type, length, format) before using it?
4. Does the site bucket (aws_s3_bucket.site) limit request sizes, rates and time per request?
