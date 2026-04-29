"""Review package.

Public surface::

    from app.review import ReviewPipeline, ReviewerRegistry, build_default_registry
    from app.review.base import ReviewContext, Reviewer
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .base import ReviewContext, Reviewer

if TYPE_CHECKING:
    from .pipeline import ReviewPipeline
    from .registry import ReviewerRegistry, build_default_registry
    from .review_utils import dedupe_findings as _dedupe
    from .review_utils import summary_body

__all__ = [
    "ReviewContext",
    "Reviewer",
    "ReviewPipeline",
    "ReviewerRegistry",
    "build_default_registry",
    "_dedupe",
    "summary_body",
]


def __getattr__(name: str):
    if name in {"ReviewPipeline"}:
        from .pipeline import ReviewPipeline

        return {
            "ReviewPipeline": ReviewPipeline,
        }[name]
    if name in {"_dedupe", "summary_body"}:
        from .review_utils import dedupe_findings, summary_body

        return {
            "_dedupe": dedupe_findings,
            "summary_body": summary_body,
        }[name]
    if name in {"ReviewerRegistry", "build_default_registry"}:
        from .registry import ReviewerRegistry, build_default_registry

        return {
            "ReviewerRegistry": ReviewerRegistry,
            "build_default_registry": build_default_registry,
        }[name]
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

