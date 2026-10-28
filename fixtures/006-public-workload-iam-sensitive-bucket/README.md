# 006-public-workload-iam-sensitive-bucket

The canonical demo and the lab's starting point: the orders service after PR #42 (`demo/base/` is the state before
it). An internet-facing ALB forwards to an EC2 instance that allows IMDSv1, and the instance's role can read every S3
bucket, including one tagged confidential. There are 40 scanner findings and one HIGH path, with the ASSUMPTION hop
`workload_ssrf`. This is the development fixture: the engine was built against it, so it is not a blind test.
