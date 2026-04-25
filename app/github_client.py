"""Thin async GitHub REST client for the bits we actually use.

Authenticated calls require an installation access token from `github_auth`.
"""

from __future__ import annotations

from typing import Any

import httpx

from .config import Settings
from .models import Finding


def _headers(token: str, *, accept: str = "application/vnd.github+json") -> dict[str, str]:
    return {
        "Authorization": f"Bearer {token}",
        "Accept": accept,
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "appsec-peer-reviewer",
    }


async def get_pr_diff(
    settings: Settings,
    token: str,
    owner: str,
    repo: str,
    pr_number: int,
    *,
    client: httpx.AsyncClient | None = None,
) -> str:
    """Fetch the unified diff for a PR (the `application/vnd.github.v3.diff` media type)."""
    url = f"{settings.github_api_base}/repos/{owner}/{repo}/pulls/{pr_number}"
    owns = client is None
    client = client or httpx.AsyncClient(timeout=30.0)
    try:
        resp = await client.get(
            url, headers=_headers(token, accept="application/vnd.github.v3.diff")
        )
        resp.raise_for_status()
        return resp.text
    finally:
        if owns:
            await client.aclose()


async def post_review(
    settings: Settings,
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
    """Post a single PR review with one inline comment per finding.

    `event="COMMENT"` posts the review without approving/requesting changes.
    Use `event="REQUEST_CHANGES"` if you want the bot to block merge.
    """
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
    owns = client is None
    client = client or httpx.AsyncClient(timeout=30.0)
    try:
        resp = await client.post(url, headers=_headers(token), json=payload)
        resp.raise_for_status()
        return resp.json()
    finally:
        if owns:
            await client.aclose()


def _format_comment_body(f: Finding) -> str:
    sev = f.severity.upper()
    return (
        f"**[{sev}] {f.title}** — `{f.vulnerability_class}` ({f.source})\n\n"
        f"{f.explanation}\n\n"
        f"**Suggested fix:** {f.recommendation}"
    )
