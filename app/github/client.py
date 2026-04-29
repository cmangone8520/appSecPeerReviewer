"""Thin async GitHub REST client for PR diff retrieval and review posting.

All functions accept an optional ``httpx.AsyncClient`` so that tests can inject
a pre-configured mock client without monkey-patching module-level globals.
"""

from __future__ import annotations

import logging
import time
from typing import Any

import httpx

from ..exceptions import DiffFetchError, ReviewPostError
from ..models import Finding
from .github_settings import GitHubSettings

log = logging.getLogger("appsec_reviewer")


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _auth_headers(settings: GitHubSettings, token: str, *, accept: str = "application/vnd.github+json") -> dict[str, str]:
    """Build standard GitHub API request headers (token is never logged)."""
    return {
        "Authorization": f"Bearer {token}",
        "Accept": accept,
        "X-GitHub-Api-Version": settings.github_api_version,
        "User-Agent": settings.github_user_agent,
    }


def _format_comment_body(finding: Finding) -> str:
    """Format a :class:`~app.models.Finding` as a markdown PR comment body."""
    sev = finding.severity.upper()
    return (
        f"**[{sev}] {finding.title}** "
        f"— `{finding.vulnerability_class}` ({finding.source})\n\n"
        f"{finding.explanation}\n\n"
        f"**Suggested fix:** {finding.recommendation}"
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


async def get_pr_diff(
    settings: GitHubSettings,
    token: str,
    owner: str,
    repo: str,
    pr_number: int,
    *,
    client: httpx.AsyncClient | None = None,
) -> str:
    """Fetch the unified diff for a pull request.

    Parameters
    ----------
    settings:
        Application settings (used for ``github_api_base``).
    token:
        A valid per-installation GitHub access token.
    owner, repo, pr_number:
        Coordinates of the pull request.
    client:
        Optional pre-built client; useful for testing.

    Returns
    -------
    str
        The unified diff as plain text.

    Raises
    ------
    DiffFetchError
        When the GitHub API returns a non-success status.
    """
    started = time.perf_counter()
    url = f"{settings.github_api_base}/repos/{owner}/{repo}/pulls/{pr_number}"
    log.info("github get_pr_diff request target=%s/%s#%d", owner, repo, pr_number)

    owns_client = client is None
    client = client or httpx.AsyncClient(timeout=settings.github_http_timeout)
    try:
        resp = await client.get(
            url,
            headers=_auth_headers(settings, token, accept="application/vnd.github.v3.diff"),
        )
        elapsed_ms = int((time.perf_counter() - started) * 1000)
        log.info(
            "github get_pr_diff response target=%s/%s#%d status=%d elapsed_ms=%d",
            owner,
            repo,
            pr_number,
            resp.status_code,
            elapsed_ms,
        )
        if not resp.is_success:
            raise DiffFetchError(
                f"GitHub returned {resp.status_code} fetching diff for "
                f"{owner}/{repo}#{pr_number}: {resp.text[:200]}"
            )
        diff_text = resp.text
    finally:
        if owns_client:
            await client.aclose()

    log.info(
        "github get_pr_diff success target=%s/%s#%d diff_bytes=%d",
        owner,
        repo,
        pr_number,
        len(diff_text.encode()),
    )
    return diff_text


async def post_review(
    settings: GitHubSettings,
    token: str,
    owner: str,
    repo: str,
    pr_number: int,
    *,
    commit_id: str,
    body: str,
    findings: list[Finding],
    event: str = "COMMENT",
    client: httpx.AsyncClient | None = None,
) -> dict[str, Any]:
    """Post a consolidated PR review with one inline comment per finding.

    Parameters
    ----------
    event:
        One of ``"COMMENT"``, ``"APPROVE"``, or ``"REQUEST_CHANGES"``.
        Use ``"COMMENT"`` (default) to surface findings without blocking merge.

    Raises
    ------
    ReviewPostError
        When the GitHub Reviews API returns a non-success status.
    """
    started = time.perf_counter()
    url = f"{settings.github_api_base}/repos/{owner}/{repo}/pulls/{pr_number}/reviews"

    comments = [
        {
            "path": f.file,
            "line": f.line,
            "side": "RIGHT",
            "body": _format_comment_body(f),
        }
        for f in findings
    ]
    payload = {
        "commit_id": commit_id,
        "body": body,
        "event": event,
        "comments": comments,
    }
    log.info(
        "github post_review request target=%s/%s#%d event=%s comments=%d",
        owner,
        repo,
        pr_number,
        event,
        len(comments),
    )

    owns_client = client is None
    client = client or httpx.AsyncClient(timeout=settings.github_http_timeout)
    try:
        resp = await client.post(url, headers=_auth_headers(settings, token), json=payload)
        elapsed_ms = int((time.perf_counter() - started) * 1000)
        log.info(
            "github post_review response target=%s/%s#%d status=%d elapsed_ms=%d",
            owner,
            repo,
            pr_number,
            resp.status_code,
            elapsed_ms,
        )
        if not resp.is_success:
            raise ReviewPostError(
                f"GitHub returned {resp.status_code} posting review for "
                f"{owner}/{repo}#{pr_number}: {resp.text[:200]}"
            )
        body_json = resp.json()
    finally:
        if owns_client:
            await client.aclose()

    log.info(
        "github post_review success target=%s/%s#%d review_id=%s",
        owner,
        repo,
        pr_number,
        body_json.get("id"),
    )
    return body_json
