# Attack paths

## Path 1

**HIGH: Someone on the internet could read the customers table (aws_dynamodb_table.customers), which holds restricted data, if they find a way to make the api server (aws_instance.api) fetch a web address for them (an SSRF bug) or run code on it.**

How:

1. Anyone on the internet can reach the api server (aws_instance.api) (tcp/443,tcp/8443). `main.tf:93`
2. The api server (aws_instance.api) can fetch the cloud keys of the app role (aws_iam_role.app) from a local address (IMDS). Because the older IMDS setting is allowed, a request someone tricks the server into making can fetch them too. *(needs the condition above)* `main.tf:95-98`
3. Those keys are allowed to read the customers table (aws_dynamodb_table.customers) because the permission covers everything of that kind (a wildcard), not only what is needed. `main.tf:75-84`

**What to change:** Narrow the permission of the app role (aws_iam_role.app) to the resources it actually needs, so it no longer covers the customers table (aws_dynamodb_table.customers). The path engine re-ran itself with this change: the path disappears. `main.tf:75-84`

**What we need to know from you** (answer in `threat-answers.yaml`):

- Does the customers table (aws_dynamodb_table.customers) hold personal data (names, emails, addresses, account or ID numbers)?
- Does the api server (aws_instance.api) check every request's input (type, length, format) before using it?
- Does the api server (aws_instance.api) clean or escape input before it reaches a database, a shell or a template?

## Questions for the team that runs the application

1. Does the api server (aws_instance.api) check every request's input (type, length, format) before using it?
2. Does the api server (aws_instance.api) clean or escape input before it reaches a database, a shell or a template?
3. Does the api server (aws_instance.api) encode what it sends back (HTML/JSON escaping), so user data can't become code in a browser?
4. Does the api server (aws_instance.api) check what the caller is allowed to do before every action?
5. Are the session IDs issued by the api server (aws_instance.api) long, random and replaced at login?
6. Does the api server (aws_instance.api) require callers to prove who they are (login, token, mTLS)?
