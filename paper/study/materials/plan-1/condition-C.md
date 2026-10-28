# Attack paths

## Path 1

**HIGH: Someone on the internet could list and read the customer-data bucket (aws_s3_bucket.customer_data), which holds confidential data, if they find a way to make the app server (aws_instance.app) fetch a web address for them (an SSRF bug) or run code on it.**

How:

1. Anyone on the internet can reach the web load balancer (aws_lb.web) (HTTPS/443). `alb.tf:3`
2. The web load balancer (aws_lb.web) passes those requests on to the app server (aws_instance.app). `network.tf:94-100`
3. The app server (aws_instance.app) can fetch the cloud keys of the app role (aws_iam_role.app) from a local address (IMDS). Because the older IMDS setting is allowed, a request someone tricks the server into making can fetch them too. *(needs the condition above)* `app.tf:10-13`
4. Those keys are allowed to list and read the customer-data bucket (aws_s3_bucket.customer_data) because the permission covers everything of that kind (a wildcard), not only what is needed. `iam.tf:25-35`

**What to change:** Narrow the permission of the app role (aws_iam_role.app) to the resources it actually needs, so it no longer covers the customer-data bucket (aws_s3_bucket.customer_data). The path engine re-ran itself with this change: the path disappears. `iam.tf:25-35`

**What we need to know from you** (answer in `threat-answers.yaml`):

- Does the customer-data bucket (aws_s3_bucket.customer_data) hold personal data (names, emails, addresses, account or ID numbers)?
- Does the app server (aws_instance.app) check every request's input (type, length, format) before using it?
- Does the web load balancer (aws_lb.web) check every request's input (type, length, format) before using it? (For a load balancer: is a WAF rule doing this in front of the app?)

## Questions for the team that runs the application

1. Does the app server (aws_instance.app) check every request's input (type, length, format) before using it?
2. Does the web load balancer (aws_lb.web) check every request's input (type, length, format) before using it? (For a load balancer: is a WAF rule doing this in front of the app?)
3. Does the app server (aws_instance.app) clean or escape input before it reaches a database, a shell or a template?
4. Does the app server (aws_instance.app) encode what it sends back (HTML/JSON escaping), so user data can't become code in a browser?
5. Does the web load balancer (aws_lb.web) clean or escape input before it reaches a database, a shell or a template? (For a load balancer: is a WAF rule doing this in front of the app?)
6. Does the web load balancer (aws_lb.web) encode what it sends back (HTML/JSON escaping), so user data can't become code in a browser? (For a load balancer: is a WAF rule doing this in front of the app?)
