"""Baseline scanners (Checkov, tfsec, Trivy): run, normalise, join to the graph.

Scanners answer "is this configuration risky?". The pipeline keeps their findings
as SCAN-### evidence and joins them to graph nodes and attack-path hops; it never
changes a scanner's verdict or severity.
"""
