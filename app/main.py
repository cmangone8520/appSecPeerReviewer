"""FastAPI application entrypoint for appSec Peer Reviewer.

Lifecycle of a PR review
------------------------
1. GitHub delivers a ``pull_request`` webhook to ``/webhook``.
2. The HMAC-SHA256 signature is verified; on failure a ``401`` is returned
   immediately — fast and cheap.
3. Non-actionable events/actions are rejected early (``ping``, draft PRs,
   non-PR event types, unsupported PR actions).
4. The review is scheduled as a ``BackgroundTask`` so GitHub receives ``202``
   well within its 10-second window.
5. The background task:
   a. Mints an installation access token.
   b. Fetches the unified diff.
   c. Runs all registered reviewers in parallel via :class:`ReviewPipeline`.
   d. Posts findings as a single consolidated inline PR review.
"""

from __future__ import annotations

import json
import logging
import time
from collections import OrderedDict
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import BackgroundTasks, FastAPI, Header, HTTPException, Request, status

from .config import get_settings
from .logging_utils import configure_logging, set_delivery_id
from .review.pipeline import ReviewPipeline
from .review.registry import build_default_registry
from .review.tasks import run_review_safe
from .webhook import verify_signature

log = logging.getLogger("appsec_reviewer")
_DELIVERY_CACHE: OrderedDict[str, float] = OrderedDict()


def _cleanup_delivery_cache(now: float) -> None:
    while _DELIVERY_CACHE:
        first_key = next(iter(_DELIVERY_CACHE))
        if _DELIVERY_CACHE[first_key] > now:
            break
        _DELIVERY_CACHE.pop(first_key, None)


def _mark_delivery_seen(
    delivery_id: str,
    *,
    now: float,
    ttl_seconds: int,
    max_entries: int,
) -> bool:
    _cleanup_delivery_cache(now)
    expiry = _DELIVERY_CACHE.get(delivery_id)
    if expiry and expiry > now:
        return True

    _DELIVERY_CACHE[delivery_id] = now + ttl_seconds
    _DELIVERY_CACHE.move_to_end(delivery_id)
    while len(_DELIVERY_CACHE) > max_entries:
        _DELIVERY_CACHE.popitem(last=False)
    return False

# ---------------------------------------------------------------------------
# Lifespan — startup / shutdown
# ---------------------------------------------------------------------------


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Configure logging and build the reviewer registry on startup."""
    settings = get_settings()
    configure_logging(settings.log_level)
    registry = build_default_registry(settings)
    app.state.pipeline = ReviewPipeline(registry)
    log.info(
        "appSec Peer Reviewer started reviewers=%s",
        registry.names(),
    )
    yield
    log.info("appSec Peer Reviewer shutting down")


# ---------------------------------------------------------------------------
# FastAPI application
# ---------------------------------------------------------------------------

app = FastAPI(
    title="appSec Peer Reviewer",
    version="1.0.0",
    description=(
        "GitHub App that performs LLM-driven application-security peer review "
        "on every pull request."
    ),
    lifespan=lifespan,
)

# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@app.get("/health", tags=["ops"])
async def health() -> dict[str, str]:
    """Health-check endpoint used by load balancers and Fly.io checks."""
    return {"status": "ok"}


@app.post("/webhook", status_code=status.HTTP_202_ACCEPTED, tags=["webhook"])
async def webhook(
    request: Request,
    background: BackgroundTasks,
    x_github_delivery: str | None = Header(default=None, alias="X-GitHub-Delivery"),
    x_github_event: str | None = Header(default=None, alias="X-GitHub-Event"),
    x_hub_signature_256: str | None = Header(default=None, alias="X-Hub-Signature-256"),
) -> dict[str, str]:
    """Receive, verify, and dispatch GitHub webhook events."""
    settings = get_settings()
    content_length_raw = request.headers.get("content-length")
    if content_length_raw:
        try:
            if int(content_length_raw) > settings.max_webhook_bytes:
                raise HTTPException(status_code=413, detail="payload too large")
        except ValueError:
            raise HTTPException(status_code=400, detail="invalid content-length") from None

    body = await request.body()
    if len(body) > settings.max_webhook_bytes:
        raise HTTPException(status_code=413, detail="payload too large")

    delivery_id = x_github_delivery or "unknown"
    set_delivery_id(delivery_id)
    if x_github_delivery and _mark_delivery_seen(
        x_github_delivery,
        now=time.monotonic(),
        ttl_seconds=settings.webhook_replay_ttl_seconds,
        max_entries=settings.webhook_replay_cache_size,
    ):
        log.info("webhook ignored: duplicate delivery_id=%s", x_github_delivery)
        return {"status": "ignored duplicate delivery"}

    log.info(
        "webhook received event=%s body_bytes=%d",
        x_github_event,
        len(body),
    )

    # --- Signature verification (fail-closed) ---
    if not settings.github.github_webhook_secret.strip():
        log.error("webhook rejected: GITHUB_WEBHOOK_SECRET is not configured")
        raise HTTPException(status_code=503, detail="server webhook secret not configured")
    if not verify_signature(settings.github.github_webhook_secret, body, x_hub_signature_256):
        log.warning("webhook rejected: bad signature event=%s", x_github_event)
        raise HTTPException(status_code=401, detail="Bad signature")

    # --- Event routing ---
    if x_github_event == "ping":
        log.info("webhook ping acknowledged")
        return {"status": "pong"}
    if x_github_event != "pull_request":
        log.info("webhook ignored: event=%s", x_github_event)
        return {"status": f"ignored event={x_github_event}"}

    try:
        payload = json.loads(body)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="invalid json payload") from None
    action = payload.get("action")

    _actionable = {"opened", "synchronize", "reopened", "ready_for_review"}
    if action not in _actionable:
        log.info("webhook ignored: action=%s", action)
        return {"status": f"ignored action={action}"}
    if payload.get("pull_request", {}).get("draft"):
        log.info("webhook ignored: draft pull request")
        return {"status": "ignored draft PR"}

    pr = payload["pull_request"]
    repo = payload["repository"]
    installation_id = payload.get("installation", {}).get("id")
    if not installation_id:
        log.warning("webhook rejected: missing installation.id")
        raise HTTPException(status_code=400, detail="missing installation.id")

    pipeline: ReviewPipeline = request.app.state.pipeline

    log.info(
        "webhook scheduled review target=%s/%s#%s action=%s installation_id=%s",
        repo["owner"]["login"],
        repo["name"],
        pr["number"],
        action,
        installation_id,
    )

    background.add_task(
        run_review_safe,
        pipeline=pipeline,
        settings=settings,
        installation_id=int(installation_id),
        delivery_id=delivery_id,
        owner=repo["owner"]["login"],
        repo_name=repo["name"],
        pr_number=int(pr["number"]),
        head_sha=pr["head"]["sha"],
    )
    return {"status": "scheduled"}
