# Threat model

22 threats for the architecture described by this plan.

| Element | Threat | Title | Severity |
|---|---|---|---|
| aws_s3_bucket.backups | AC01 | Privilege Abuse | Medium |
| aws_s3_bucket.backups | CR05 | Encryption Brute Forcing | Low |
| aws_s3_bucket.backups | DE04 | Audit Log Manipulation | High |
| aws_s3_bucket.backups | DO02 | Excessive Allocation | Medium |
| aws_s3_bucket.exports | AC01 | Privilege Abuse | Medium |
| aws_s3_bucket.exports | CR05 | Encryption Brute Forcing | Low |
| aws_s3_bucket.exports | DE04 | Audit Log Manipulation | High |
| aws_s3_bucket.exports | DO02 | Excessive Allocation | Medium |
| aws_s3_bucket.site | AC01 | Privilege Abuse | Medium |
| aws_s3_bucket.site | CR05 | Encryption Brute Forcing | Low |
| aws_s3_bucket.site | DE04 | Audit Log Manipulation | High |
| aws_s3_bucket.site | DO02 | Excessive Allocation | Medium |
| Any AWS principal / anonymous → aws_s3_bucket.exports | AC05 | Content Spoofing | Medium |
| Any AWS principal / anonymous → aws_s3_bucket.exports | CR06 | Communication Channel Manipulation | High |
| Any AWS principal / anonymous → aws_s3_bucket.exports | CR08 | Client-Server Protocol Manipulation | Medium |
| Any AWS principal / anonymous → aws_s3_bucket.exports | DE01 | Interception | Medium |
| Any AWS principal / anonymous → aws_s3_bucket.exports | DE03 | Sniffing Attacks | Medium |
| Any AWS principal / anonymous → aws_s3_bucket.site | AC05 | Content Spoofing | Medium |
| Any AWS principal / anonymous → aws_s3_bucket.site | CR06 | Communication Channel Manipulation | High |
| Any AWS principal / anonymous → aws_s3_bucket.site | CR08 | Client-Server Protocol Manipulation | Medium |
| Any AWS principal / anonymous → aws_s3_bucket.site | DE01 | Interception | Medium |
| Any AWS principal / anonymous → aws_s3_bucket.site | DE03 | Sniffing Attacks | Medium |
