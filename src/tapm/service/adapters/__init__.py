"""Git server adapters package (W1.2).

Provides unified adapters for Gitea and GitHub to post PR comments
and commit statuses for attack-path reviews.
"""

from __future__ import annotations

import os
from typing import Any

from .base import DEFAULT_MARKER, GitAdapterError, GitServerAdapter, HttpTransport
from .fixtures import FixtureHttpTransport
from .gitea import GiteaAdapter
from .github import GitHubAdapter

__all__ = [
    "DEFAULT_MARKER",
    "GitAdapterError",
    "GitServerAdapter",
    "GiteaAdapter",
    "GitHubAdapter",
    "FixtureHttpTransport",
    "get_adapter",
    "detect_adapter",
]


def get_adapter(
    server_type: str = "gitea",
    base_url: str | None = None,
    token: str | None = None,
    transport: HttpTransport | None = None,
) -> GitServerAdapter:
    """Instantiate a Git adapter for the requested platform type."""
    t = (server_type or "").strip().lower()
    if t in ("gitea", "forgejo"):
        return GiteaAdapter(base_url=base_url, token=token, transport=transport)
    elif t in ("github", "gh"):
        return GitHubAdapter(base_url=base_url, token=token, transport=transport)
    else:
        raise ValueError(f"Unsupported git adapter type '{server_type}'. Expected 'gitea' or 'github'.")


def detect_adapter(
    transport: HttpTransport | None = None,
) -> GitServerAdapter:
    """Auto-detect the appropriate Git server adapter from environment variables."""
    # Explicit adapter preference
    preferred = os.environ.get("TAPM_GIT_ADAPTER", "").lower()
    if preferred:
        return get_adapter(preferred, transport=transport)

    # Detect Gitea / Forgejo
    if os.environ.get("GITEA_URL") or os.environ.get("GITEA_TOKEN"):
        return GiteaAdapter(transport=transport)

    # Detect GitHub
    if os.environ.get("GITHUB_ACTIONS") or os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN"):
        return GitHubAdapter(transport=transport)

    # Default to Gitea for the demo environment
    return GiteaAdapter(transport=transport)
