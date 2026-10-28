# Attack paths

## Path 1

**MEDIUM: Someone on the internet could read the ledger bucket (aws_s3_bucket.ledger), which holds confidential data, if they can run code on the api server (aws_instance.api).**

How:

1. Anyone on the internet can reach the api server (aws_instance.api) (tcp/443). `main.tf:68`
2. The api server (aws_instance.api) can fetch the cloud keys of the app role (aws_iam_role.app) from a local address (IMDS). *(needs the condition above)* `main.tf:70-73`
3. Those keys are allowed to read the ledger bucket (aws_s3_bucket.ledger), because the bucket's own access policy names the app role (aws_iam_role.app). `main.tf:95-106`

**What to change:** Remove the app role (aws_iam_role.app) from the access policy of the ledger bucket (aws_s3_bucket.ledger), or limit what that policy lets it do. The path engine re-ran itself with this change: the path disappears. `main.tf:95-106`

**What we need to know from you** (answer in `threat-answers.yaml`):

- Does the ledger bucket (aws_s3_bucket.ledger) hold personal data (names, emails, addresses, account or ID numbers)?
- Does the api server (aws_instance.api) check every request's input (type, length, format) before using it?
- Does the api server (aws_instance.api) clean or escape input before it reaches a database, a shell or a template?

## Questions for the team that runs the application

1. Does the api server (aws_instance.api) check every request's input (type, length, format) before using it?
2. Does the api server (aws_instance.api) clean or escape input before it reaches a database, a shell or a template?
3. Does the api server (aws_instance.api) encode what it sends back (HTML/JSON escaping), so user data can't become code in a browser?
4. Does the api server (aws_instance.api) check what the caller is allowed to do before every action?
5. Are the session IDs issued by the api server (aws_instance.api) long, random and replaced at login?
6. Does the api server (aws_instance.api) require callers to prove who they are (login, token, mTLS)?
