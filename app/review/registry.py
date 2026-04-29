"""Pluggable reviewer registry.

The :class:`ReviewerRegistry` is the single source-of-truth for which
reviewers are active in a given deployment.  Reviewers can be added,
removed, or replaced at runtime without changing the pipeline logic.

Usage
-----
    registry = ReviewerRegistry()
    registry.register(LLMReviewer(settings))
    registry.register(SecretScanner())
    registry.register(DependencyReviewer())

Factory
-------
Call :func:`build_default_registry` to get a registry pre-populated with
all built-in reviewers.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator

from ..config import Settings
from .base import Reviewer

log = logging.getLogger("appsec_reviewer")


class ReviewerRegistry:
    """Ordered registry of :class:`~app.review.base.Reviewer` plugins.

    Registration order is preserved; reviewers are iterated in insertion order.
    """

    def __init__(self) -> None:
        self._reviewers: dict[str, Reviewer] = {}

    # ------------------------------------------------------------------
    # Mutation
    # ------------------------------------------------------------------

    def register(self, reviewer: Reviewer) -> None:
        """Add *reviewer* to the registry.

        If a reviewer with the same ``name`` is already registered it will be
        replaced and a warning will be logged.
        """
        if reviewer.name in self._reviewers:
            log.warning("reviewer already registered, replacing: %s", reviewer.name)
        self._reviewers[reviewer.name] = reviewer
        log.info("reviewer registered: %s", reviewer.name)

    def unregister(self, name: str) -> None:
        """Remove the reviewer identified by *name* (no-op if not present)."""
        removed = self._reviewers.pop(name, None)
        if removed:
            log.info("reviewer unregistered: %s", name)

    # ------------------------------------------------------------------
    # Query
    # ------------------------------------------------------------------

    def get(self, name: str) -> Reviewer | None:
        """Return the reviewer for *name*, or ``None``."""
        return self._reviewers.get(name)

    def names(self) -> list[str]:
        """Return the names of all registered reviewers in order."""
        return list(self._reviewers)

    # ------------------------------------------------------------------
    # Protocol support
    # ------------------------------------------------------------------

    def __iter__(self) -> Iterator[Reviewer]:
        return iter(self._reviewers.values())

    def __len__(self) -> int:
        return len(self._reviewers)

    def __repr__(self) -> str:
        return f"ReviewerRegistry(reviewers={self.names()})"


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------


def build_default_registry(settings: Settings) -> ReviewerRegistry:
    """Build and return the default :class:`ReviewerRegistry`.

    This is the single place to configure which reviewers are active.
    Add, remove, or reorder entries here to change the default behaviour.

    To add a custom reviewer, implement the :class:`~app.review.base.Reviewer`
    protocol and register it here (or call ``registry.register()`` after the
    fact in ``app/main.py``).
    """
    # Late imports avoid circular dependencies and keep module load fast.
    from .reviewers.deps import DependencyReviewer  # noqa: PLC0415
    from .reviewers.llm import LLMReviewer  # noqa: PLC0415
    from .reviewers.secrets import SecretScanner  # noqa: PLC0415

    registry = ReviewerRegistry()
    registry.register(SecretScanner())           # fast, synchronous, no external calls
    registry.register(DependencyReviewer())      # async OSV.dev API lookup
    registry.register(LLMReviewer(settings))     # async OpenAI call (slowest)
    return registry

