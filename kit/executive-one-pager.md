# Attack paths on every Terraform change

**The problem.** Our infrastructure changes go through IaC scanners that judge one resource at a time. A change that
opens a public load balancer, leaves instance metadata on version 1, and grants a role read access to every bucket
produces dozens of medium findings. None of them says these three lines together give the internet a way to reach
customer data. Our threat models are diagrams drawn once and not updated per change, so nobody checks the combination
before merge.

**What we'll do.** On every Terraform pull request, a check reads the plan and reports the attack paths the change
opens, with a file and line for every step. Every path above our threshold gets a decision before merge:
- It's fixed, and re-planning verifies the modeled relationship change; deployment tests remain necessary.
- Or a named owner accepts it, with a reason and an expiry.

The app team answers a few yes/no questions the plan can't answer. The modeled analysis is deterministic for the same inputs and pinned versions; reproducibility does not prove correctness. AI, if we use it, only explains the evidence.

**How we'll roll it out.** Five levels, starting with observation only. One repository first.

| Level | When | What |
|---|---|---|
| 1 | Scope ready | Observe and record a baseline |
| 2 | Baseline understood | Recommend: one PR comment with the paths and "would block" |
| 3 | Enforcement justified | Validate: paths above the threshold need a fix or an accepted risk to merge |
| 4 | Stricter acceptance justified | Prevent: accepted risks need a different declared approver and a compensating control; authenticate approval in repository controls |
| 5 | Ongoing | Canary tests check selected expected blocks and passes |

**What it costs.**
- A read-only role and one CI job per root module.
- Reviewers' time for a weekly false-path sample.
- Authors' time to answer a few questions per change.

We measure all three rather than estimate them.

**How we'll know it worked:**

| Measure | Target |
|---|---|
| Items a reviewer reads per Terraform change | Down from baseline, to one screen |
| Paths merged without a decision | 0 on new changes under the selected policy |
| Open paths on the default branch | Down each month |
| Time from PR to security decision | No slower than baseline |
| False paths in the weekly sample | Under 10% before anything blocks |

**Decision triggers:** review a representative sample before enforcing; revisit when scope, policy, operating effort or service consequences change. Continue, change or stop based on evidence. Your organization chooses its own pace. No audience reporting program is offered.

**Approval at scale:** preapproved routine work may automate under policy. Define protected review floors for authority outside that scope, exceptions, classifier/policy changes and material uncertainty. A classifier's judgment remains fallible. Adjudicated feedback, held-out evaluation, shadow/canary and independent promotion are recommended controls, not capabilities measured by this prototype.
