# 010-explicit-deny

Explicit Deny overrides Allow. A scanner sees `s3:*` on `*`; the evaluator sees that the confidential bucket is denied, so the only reachable bucket is internal and there is no attack path.
