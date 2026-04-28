"""Review pipeline orchestrator.

:class:`ReviewPipeline` fans out to all registered reviewer plugins in
parallel, collects their findings, deduplicates overlapping results, and
returns the final sorted list ready for posting as GitHub inline comments.
"""

from __future__ import annotations

import asyncio
import logging
import time

from ..config import Settings
from ..diff.parser import parse_diff
from ..models import Finding
from .base import ReviewContext
from .registry import ReviewerRegistry
from .review_utils import _SEVERITY_RANK, dedupe_findings, summary_body

log = logging.getLogger("appsec_reviewer")


# ---------------------------------------------------------------------------
# Pipeline class
# ---------------------------------------------------------------------------


class ReviewPipeline:
    """Orchestrates all registered :class:`~app.review.base.Reviewer` plugins.

    Parameters
    ----------
    registry:
        The :class:`~app.review.registry.ReviewerRegistry` whose reviewers will
        be invoked for every call to :meth:`run`.
    """

    def __init__(self, registry: ReviewerRegistry) -> None:
        self._registry = registry

    async def run(
        self,
        settings: Settings,
        diff_text: str,
        delivery_id: str = "-",
    ) -> list[Finding]:
        """Run all registered reviewers against *diff_text* and return findings.

        Reviewers are launched concurrently via :func:`asyncio.gather`.  If one
        reviewer raises, the error is logged and the other reviewers' results
        are still returned — a single reviewer failure is non-fatal.

        Parameters
        ----------
        settings:
            Runtime config forwarded to each reviewer via :class:`ReviewContext`.
        diff_text:
            The raw unified diff string.
        delivery_id:
            The GitHub delivery-id for log correlation.

        Returns
        -------
        list[Finding]
            Deduplicated, severity-sorted findings.
        """
        started = time.perf_counter()
        log.info(
            "pipeline start diff_bytes=%d reviewers=%d delivery=%s",
            len(diff_text.encode()),
            len(self._registry),
            delivery_id,
        )

        if not diff_text.strip():
            log.info("pipeline skip: empty diff delivery=%s", delivery_id)
            return []

        parsed = parse_diff(diff_text)
        if not parsed:
            log.info("pipeline skip: no parsed files delivery=%s", delivery_id)
            return []

        ctx = ReviewContext(
            diff_text=diff_text,
            parsed=parsed,
            settings=settings,
            delivery_id=delivery_id,
        )

        # Fan-out: run all reviewers concurrently.
        results = await asyncio.gather(
            *[reviewer.review(ctx) for reviewer in self._registry],
            return_exceptions=True,
        )

        all_findings: list[Finding] = []
        for reviewer, result in zip(self._registry, results, strict=True):
            if isinstance(result, Exception):
                log.warning(
                    "reviewer failed reviewer=%s delivery=%s error=%s",
                    reviewer.name,
                    delivery_id,
                    result,
                )
            else:
                log.info(
                    "reviewer complete reviewer=%s findings=%d delivery=%s",
                    reviewer.name,
                    len(result),
                    delivery_id,
                )
                all_findings.extend(result)

        deduped = dedupe_findings(all_findings)
        elapsed_ms = int((time.perf_counter() - started) * 1000)
        log.info(
            "pipeline complete before_dedupe=%d after_dedupe=%d "
            "elapsed_ms=%d delivery=%s",
            len(all_findings),
            len(deduped),
            elapsed_ms,
            delivery_id,
        )
        return deduped


# Backward-compatible exports used by tests/importers.
def _dedupe(findings: list[Finding]) -> list[Finding]:
    return dedupe_findings(findings)
