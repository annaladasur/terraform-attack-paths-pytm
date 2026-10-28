# What could go wrong in 006-public-workload-iam-sensitive-bucket, in plain words

> Written for anyone on the team, whether or not they write Terraform. Each card is generated from the checked evidence in `report.md`; the developer version there has file and line numbers.

## Path 1

**HIGH: Someone on the internet could list and read the customer-data bucket, which holds confidential data, if they find a way to make the app server fetch a web address for them (an SSRF bug) or run code on it.**

How:

1. Anyone on the internet can reach the web load balancer.
2. The web load balancer passes those requests on to the app server.
3. The app server can fetch the cloud keys of the app role from a local address (IMDS). Because the older IMDS setting is allowed, a request someone tricks the server into making can fetch them too. *(needs the condition above)*
4. Those keys are allowed to list and read the customer-data bucket because the permission covers everything of that kind (a wildcard), not only what is needed.

**What to change:** Narrow the permission of the app role to the resources it actually needs, so it no longer covers the customer-data bucket. A patch for this was re-planned and re-checked: the path disappears.

**What we need to know from you** (answer in `threat-answers.yaml`):

- Does the customer-data bucket hold personal data?
- Does the app server check every request's input before using it?
- Does the web load balancer check every request's input before using it?

<details><summary>Words used here</summary>

- **IMDS**: a local address every cloud server can call to get its own cloud keys
- **SSRF**: a bug that lets an outsider make your server fetch a web address of their choosing
- **role**: the cloud identity a server or function runs as; its permissions decide what its keys can do
- **wildcard**: a permission written with *, covering everything of a kind instead of only what is needed
- **load balancer**: the front door that passes internet traffic on to your servers
- **bucket**: a cloud storage folder (Amazon S3)
- **condition**: something else that must also be true for the path to work, and that Terraform can't show

</details>
