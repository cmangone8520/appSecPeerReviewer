"""Reviewer plugin contract.

Any class that satisfies the :class:`Reviewer` ``Protocol`` can be registered
with :class:`~app.review.registry.ReviewerRegistry` and will be automatically
included in every PR review run.

Implementing a new reviewer
---------------------------
1. Create a class with a ``name`` property and an ``async review(ctx)`` method.
2. Register it in ``app/review/registry.py::build_default_registry()``.

Example::

    class MyReviewer:
        name = "my-reviewer"

        async def review(self, ctx: ReviewContext) -> list[Finding]:
            ...
            return findings
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from ..diff.models import FileDiff
from ..models import Finding

if TYPE_CHECKING:
    from ..config import Settings

# ---------------------------------------------------------------------------
# ReviewContext — the single input object passed to every reviewer
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ReviewContext:
    """All information a reviewer needs to evaluate a pull-request diff.

    Attributes
    ----------
    diff_text:
        The raw unified diff string.
    parsed:
        Pre-parsed list of :class:`~app.diff.models.FileDiff` objects.
    settings:
        Application settings (API keys, model name, etc.).
    delivery_id:
        The GitHub ``X-GitHub-Delivery`` header value; used for log correlation.
    """

    diff_text: str
    parsed: list[FileDiff]
    settings: Settings
    delivery_id: str = "-"


# ---------------------------------------------------------------------------
# Reviewer Protocol
# ---------------------------------------------------------------------------


@runtime_checkable
class Reviewer(Protocol):
    """Pluggable reviewer interface.

    A class qualifies as a ``Reviewer`` if it exposes:

    - ``name: str``  — unique human-readable identifier (e.g. ``"llm"``).
    - ``review(ctx: ReviewContext) -> Awaitable[list[Finding]]`` — the analysis
      coroutine; must not raise (log and return ``[]`` on failure instead).
    """

    @property
    def name(self) -> str:
        """Unique, human-readable identifier for this reviewer."""
        ...

    async def review(self, ctx: ReviewContext) -> list[Finding]:
        """Analyse *ctx* and return zero or more security findings."""
        ...

