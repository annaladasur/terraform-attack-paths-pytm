"""Read current demo PR state without relying on seeded PR numbers or SHAs."""
from __future__ import annotations

import argparse
import base64
import json
import os
import time
import urllib.parse
import urllib.request


def request(path: str):
    url = os.environ.get("GITEA_URL", "http://localhost:3000").rstrip("/")
    auth = base64.b64encode(
        f"{os.environ.get('GITEA_ADMIN_USER', 'tapm-admin')}:{os.environ.get('GITEA_ADMIN_PASS', 'tapm-admin-pass123')}".encode()
    ).decode()
    req = urllib.request.Request(
        f"{url}/api/v1/repos/demo-org/infra-demo/{path}",
        headers={"Authorization": f"Basic {auth}"},
    )
    with urllib.request.urlopen(req, timeout=10) as response:
        return json.load(response)


def newest_pr(branch: str):
    matches = []
    page = 1
    while True:
        prs = request(f"pulls?state=open&limit=50&page={page}")
        if not isinstance(prs, list):
            raise ValueError("Gitea returned an invalid PR list")
        matches.extend(p for p in prs if p["head"]["ref"] == branch
                       and p.get("base", {}).get("ref") == "main"
                       and p["head"].get("repo", {}).get("full_name") == "demo-org/infra-demo")
        if len(prs) < 50:
            break
        page += 1
    if not matches:
        raise ValueError(f"No open PR for branch {branch}")
    # Fetch the PR again so the head SHA is current even when a list was cached.
    pr = request(f"pulls/{max(matches, key=lambda p: p['number'])['number']}")
    if (pr["head"]["ref"] != branch or pr.get("base", {}).get("ref") != "main"
            or pr["head"].get("repo", {}).get("full_name") != "demo-org/infra-demo"):
        raise ValueError("Selected PR changed branch, repository or base during lookup")
    return pr


def latest_check(pr):
    combined = request(f"commits/{pr['head']['sha']}/status")
    statuses = combined["statuses"]
    checks = [s for s in statuses if s.get("context") == "attack-paths"]
    return max(checks, key=lambda s: (s.get("updated_at", ""), s.get("id", 0)), default=None)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["url", "comments", "status"])
    parser.add_argument("branch")
    parser.add_argument("--wait", type=float, default=0)
    parser.add_argument("--expect", choices=["success", "failure", "error"])
    args = parser.parse_args()
    deadline = time.monotonic() + args.wait
    while True:
        pr = newest_pr(args.branch)
        if args.action == "url":
            print(pr["html_url"])
            return
        if args.action == "comments":
            comments = []
            page = 1
            while True:
                batch = request(f"issues/{pr['number']}/comments?limit=50&page={page}")
                comments.extend(c for c in batch if "<!-- tapm:attack-paths -->" in c.get("body", ""))
                if len(batch) < 50:
                    break
                page += 1
            if not comments:
                raise ValueError(f"PR #{pr['number']} has no TAPM comment yet")
            comment = max(comments, key=lambda c: (c.get("updated_at", ""), c["id"]))
            print("\n".join(comment["body"].splitlines()[:16]))
            return
        check = latest_check(pr)
        if check and check["status"] in {"success", "failure", "error"}:
            print(f"PR #{pr['number']} @ {pr['head']['sha']}: attack-paths {check['status']} ({check.get('description', '')})")
            if args.expect and check["status"] != args.expect:
                raise ValueError(f"Expected {args.expect}; got {check['status']}")
            return
        if time.monotonic() >= deadline:
            raise TimeoutError(f"PR #{pr['number']} has no completed attack-paths check on its current head")
        time.sleep(min(2, max(0, deadline - time.monotonic())))


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        raise SystemExit(f"Gitea state error: {exc}") from exc
