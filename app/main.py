"""FastAPI entrypoint for the appSec Peer Reviewer GitHub App.

Lifecycle of a PR review:
  1. GitHub delivers a `pull_request` webhook to /webhook.
  2. We verify HMAC-SHA256, then schedule the review on a background
     task and return 202 immediately. (GitHub gives webhooks a 10s
     budget; OpenAI calls take longer than that.)
  3. The background task mints an installation token, fetches the PR
     diff, runs the review pipeline, and posts findings as a single
     inline review on the PR.
"""

from __future__ import annotations

import logging

from fastapi import BackgroundTasks, FastAPI, Header, HTTPException, Request, status

from .config import Settings, get_settings
from .github_auth import get_installation_token
from .github_client import get_pr_diff, post_review
from .review.pipeline import run_review, summary_body
from .webhook import verify_signature

log = logging.getLogger("appsec_reviewer")

app = FastAPI(title="appSec Peer Reviewer", version="0.1.0")


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/webhook", status_code=status.HTTP_202_ACCEPTED)
async def webhook(
    request: Request,
    background: BackgroundTasks,
    x_github_event: str | None = Header(default=None, alias="X-GitHub-Event"),
    x_hub_signature_256: str | None = Header(default=None, alias="X-Hub-Signature-256"),
) -> dict[str, str]:
    settings = get_settings()
    body = await request.body()

    if not verify_signature(settings.github_webhook_secret, body, x_hub_signature_256):
        raise HTTPException(status_code=401, detail="Bad signature")

    if x_github_event == "ping":
        return {"status": "pong"}
    if x_github_event != "pull_request":
        return {"status": f"ignored event={x_github_event}"}

    payload = await request.json()
    action = payload.get("action")
    if action not in {"opened", "synchronize", "reopened", "ready_for_review"}:
        return {"status": f"ignored action={action}"}
    if payload.get("pull_request", {}).get("draft"):
        return {"status": "ignored draft PR"}

    pr = payload["pull_request"]
    repo = payload["repository"]
    installation_id = payload.get("installation", {}).get("id")
    if not installation_id:
        raise HTTPException(status_code=400, detail="missing installation.id")

    background.add_task(
        _review_pr_safe,
        settings=settings,
        installation_id=int(installation_id),
        owner=repo["owner"]["login"],
        repo_name=repo["name"],
        pr_number=int(pr["number"]),
        head_sha=pr["head"]["sha"],
    )
    return {"status": "scheduled"}


async def _review_pr_safe(
    *,
    settings: Settings,
    installation_id: int,
    owner: str,
    repo_name: str,
    pr_number: int,
    head_sha: str,
) -> None:
    try:
        await _review_pr(
            settings=settings,
            installation_id=installation_id,
            owner=owner,
            repo_name=repo_name,
            pr_number=pr_number,
            head_sha=head_sha,
        )
    except Exception:
        # Never let a webhook background task crash silently in a way
        # that would hide a real bug; log with a stack trace.
        log.exception(
            "review failed for %s/%s#%d", owner, repo_name, pr_number
        )


async def _review_pr(
    *,
    settings: Settings,
    installation_id: int,
    owner: str,
    repo_name: str,
    pr_number: int,
    head_sha: str,
) -> None:
    log.info("reviewing %s/%s#%d @ %s", owner, repo_name, pr_number, head_sha[:8])
    install_token = await get_installation_token(settings, installation_id)
    diff = await get_pr_diff(settings, install_token.token, owner, repo_name, pr_number)
    if len(diff.encode()) > settings.max_diff_bytes:
        log.warning(
            "diff too large (%d bytes) for %s/%s#%d; skipping",
            len(diff.encode()), owner, repo_name, pr_number,
        )
        return

    findings = await run_review(settings, diff)
    body = summary_body(findings)
    await post_review(
        settings,
        install_token.token,
        owner,
        repo_name,
        pr_number,
        commit_id=head_sha,
        body=body,
        findings=findings,
        event="COMMENT",
    )
    log.info(
        "posted %d findings on %s/%s#%d", len(findings), owner, repo_name, pr_number
    )
