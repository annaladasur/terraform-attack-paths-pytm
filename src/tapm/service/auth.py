"""Token authentication for tapm serve (W1.1).

Validates Authorization: Bearer <token> headers with constant-time comparison.
When no token is configured, authentication is disabled and requests pass through.
"""

from __future__ import annotations

import os
import secrets


class TokenAuth:
    """Bearer token authentication validator."""

    def __init__(self, token: str | None = None) -> None:
        self.token = token or os.environ.get("TAPM_SERVER_TOKEN") or os.environ.get("TAPM_TOKEN") or None

    @property
    def enabled(self) -> bool:
        return bool(self.token)

    def is_authorized(self, auth_header: str | None) -> bool:
        """Return True if auth is disabled or header matches the configured Bearer token."""
        if not self.enabled:
            return True
        if not auth_header:
            return False
        parts = auth_header.strip().split(None, 1)
        if len(parts) != 2 or parts[0].lower() != "bearer":
            return False
        provided = parts[1].strip()
        return secrets.compare_digest(provided, self.token)
