"""Recorded HTTP fixture transport for Git server adapters (W1.2).

Allows testing and offline replay of Git server interactions against
recorded HTTP API fixtures without requiring a live Git server.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from ...util import PROJECT_ROOT
from .base import HttpTransport

FIXTURES_DIR = PROJECT_ROOT / "tests" / "fixtures" / "gitea_api"


class FixtureHttpTransport:
    """HTTP transport that replays responses from recorded JSON fixtures."""

    def __init__(self, fixtures_dir: Path | str | None = None) -> None:
        self.fixtures_dir = Path(fixtures_dir) if fixtures_dir else FIXTURES_DIR
        self.requests_log: list[dict[str, Any]] = []
        self._custom_responses: dict[tuple[str, str], tuple[int, Any]] = {}

    def register(self, method: str, pattern: str, status_code: int, data: Any) -> None:
        """Register a custom response for a specific method and path pattern."""
        self._custom_responses[(method.upper(), pattern)] = (status_code, data)

    def __call__(
        self,
        method: str,
        url: str,
        headers: dict[str, str],
        body: bytes | None,
    ) -> tuple[int, Any]:
        parsed_body: Any = None
        if body:
            try:
                parsed_body = json.loads(body.decode("utf-8"))
            except Exception:
                parsed_body = body.decode("utf-8", errors="replace")

        self.requests_log.append(
            {
                "method": method.upper(),
                "url": url,
                "headers": headers,
                "body": parsed_body,
            }
        )

        # 1. Check custom overrides
        for (m, pattern), (status, data) in self._custom_responses.items():
            if m == method.upper() and (pattern in url or re.search(pattern, url)):
                return status, data

        # 2. Check recorded Gitea fixtures by URL endpoint
        # Comments list
        if method.upper() == "GET" and "/issues/" in url and url.endswith("/comments"):
            fixture_file = self.fixtures_dir / "comments_list_existing.json"
            if fixture_file.exists():
                return 200, json.loads(fixture_file.read_text(encoding="utf-8"))
            return 200, []

        # Comment creation
        if method.upper() == "POST" and "/issues/" in url and url.endswith("/comments"):
            fixture_file = self.fixtures_dir / "comment_created.json"
            if fixture_file.exists():
                resp = json.loads(fixture_file.read_text(encoding="utf-8"))
                if isinstance(parsed_body, dict) and "body" in parsed_body:
                    resp["body"] = parsed_body["body"]
                return 201, resp
            return 201, {"id": 102, "body": parsed_body.get("body", "") if isinstance(parsed_body, dict) else ""}

        # Comment update (PATCH)
        if method.upper() == "PATCH" and "/issues/comments/" in url:
            fixture_file = self.fixtures_dir / "comment_updated.json"
            if fixture_file.exists():
                resp = json.loads(fixture_file.read_text(encoding="utf-8"))
                if isinstance(parsed_body, dict) and "body" in parsed_body:
                    resp["body"] = parsed_body["body"]
                return 200, resp
            return 200, {"id": 101, "body": parsed_body.get("body", "") if isinstance(parsed_body, dict) else ""}

        # Status creation
        if method.upper() == "POST" and "/statuses/" in url:
            state = parsed_body.get("state", "pending") if isinstance(parsed_body, dict) else "pending"
            fixture_name = f"status_created_{state}.json"
            fixture_file = self.fixtures_dir / fixture_name
            if fixture_file.exists():
                return 201, json.loads(fixture_file.read_text(encoding="utf-8"))
            return 201, {
                "id": 500,
                "status": state,
                "context": parsed_body.get("context", "attack-paths") if isinstance(parsed_body, dict) else "attack-paths",
                "description": parsed_body.get("description", "") if isinstance(parsed_body, dict) else "",
            }

        # GitHub endpoints
        if method.upper() == "POST" and "/statuses/" in url:
            return 201, {"id": 501, "state": "success"}

        return 200, {"status": "ok"}
