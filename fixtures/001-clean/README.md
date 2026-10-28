# 001-clean

Control fixture. A private EC2 worker (IMDSv2 required) reads one object prefix in an internal bucket. A confidential bucket exists but nothing is granted on it. Expected: no attack path.
