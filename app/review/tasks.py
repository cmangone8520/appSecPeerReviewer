"""Background tasks for PR reviews."""

from __future__ import annotations

import logging
import time

from ..config import Settings
from ..exceptions import AppSecError
from ..github.auth import get_installation_token
from ..github.client import get_pr_diff, post_review
from ..logging_utils import reset_delivery_id, set_delivery_id
from .pipeline import ReviewPipeline
from .review_utils import summary_body

log = logging.getLogger("appsec_reviewer")


async def run_review_safe(**kwargs) -> None:  # noqa: ANN003
    """Wrapper that logs unhandled exceptions without crashing the event loop."""
    delivery_id = kwargs.get("delivery_id", "-")
    token = set_delivery_id(delivery_id)
    try:
        await _run_review(**kwargs)
    except AppSecError as exc:
        # Expected, typed failures — log at WARNING so alerts aren't noisy.
        log.warning(
            "review failed (expected) delivery=%s error=%s",
            delivery_id,
            exc,
        )
    except Exception:
        # Unexpected failures — log full traceback for investigation.
        log.exception("review failed (unexpected) delivery=%s", delivery_id)
    finally:
        reset_delivery_id(token)


async def _run_review(
    *,
    pipeline: ReviewPipeline,
    settings: Settings,
    installation_id: int,
    delivery_id: str,
    owner: str,
    repo_name: str,
    pr_number: int,
    head_sha: str,
) -> None:
    """Execute the full review lifecycle for a single PR."""
    t_start = time.perf_counter()
    log.info(
        "review started target=%s/%s#%d head=%s",
        owner,
        repo_name,
        pr_number,
        head_sha[:8],
    )

    # Step 1 — mint installation token
    install_token = await get_installation_token(settings.github, installation_id)

    # Step 2 — fetch PR diff
    diff = await get_pr_diff(settings.github, install_token.token, owner, repo_name, pr_number)
    diff_bytes = len(diff.encode())
    if diff_bytes > settings.review.max_diff_bytes:
        log.warning(
            "diff too large diff_bytes=%d max_diff_bytes=%d target=%s/%s#%d; skipping",
            diff_bytes,
            settings.review.max_diff_bytes,
            owner,
            repo_name,
            pr_number,
        )
        return

    # Step 3 — run review pipeline
    findings = await pipeline.run(settings, diff, delivery_id=delivery_id)
    log.info(
        "pipeline returned findings=%d target=%s/%s#%d",
        len(findings),
        owner,
        repo_name,
        pr_number,
    )

    # Step 4 — post review
    body = summary_body(findings)
    log.info(
        "posting review findings=%d target=%s/%s#%d",
        len(findings),
        owner,
        repo_name,
        pr_number,
    )
    await post_review(
        settings.github,
        install_token.token,
        owner,
        repo_name,
        pr_number,
        commit_id=head_sha,
        body=body,
        findings=findings,
        event=settings.github.github_review_event,
    )

    elapsed_ms = int((time.perf_counter() - t_start) * 1000)
    log.info(
        "review complete findings=%d target=%s/%s#%d total_elapsed_ms=%d",
        len(findings),
        owner,
        repo_name,
        pr_number,
        elapsed_ms,
    )
