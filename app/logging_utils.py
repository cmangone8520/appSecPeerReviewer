"""Structured logging utilities with per-request correlation context.

Uses a ``ContextVar`` so that every log line emitted during a webhook
background task automatically carries the GitHub delivery-id without it
being threaded through every function signature.

Usage
-----
    from app.logging_utils import configure_logging, set_delivery_id

    set_delivery_id("abc-123")          # once per request lifecycle
    log.info("doing something")         # prints [abc-123] automatically
"""

from __future__ import annotations

import logging
from contextvars import ContextVar, Token

# ---------------------------------------------------------------------------
# Correlation context
# ---------------------------------------------------------------------------

_DELIVERY_ID: ContextVar[str] = ContextVar("delivery_id", default="-")


def set_delivery_id(delivery_id: str) -> Token[str]:
    """Set the correlation id for the current async context.

    Returns the ``Token`` so callers can reset to the previous value if needed.
    """
    return _DELIVERY_ID.set(delivery_id)


def reset_delivery_id(token: Token[str]) -> None:
    """Restore the previous delivery-id for the current async context."""
    _DELIVERY_ID.reset(token)


def get_delivery_id() -> str:
    """Return the delivery-id for the current async context."""
    return _DELIVERY_ID.get()


# ---------------------------------------------------------------------------
# Log filter
# ---------------------------------------------------------------------------


class _CorrelationFilter(logging.Filter):
    """Injects ``delivery_id`` into every ``LogRecord`` for structured output."""

    def filter(self, record: logging.LogRecord) -> bool:  # noqa: A003
        record.delivery_id = get_delivery_id()  # type: ignore[attr-defined]
        return True


# ---------------------------------------------------------------------------
# Configuration helper
# ---------------------------------------------------------------------------

_CONFIGURED = False


def configure_logging(level_name: str = "INFO") -> None:
    """Idempotently configure the ``appsec_reviewer`` logger.

    Safe to call multiple times (e.g. from tests and from the app lifespan).
    """
    global _CONFIGURED  # noqa: PLW0603
    if _CONFIGURED:
        return
    _CONFIGURED = True

    level = getattr(logging, level_name.upper(), logging.INFO)
    logger = logging.getLogger("appsec_reviewer")
    logger.setLevel(level)
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(
            logging.Formatter(
                "%(asctime)s %(levelname)s [%(delivery_id)s] %(name)s: %(message)s"
            )
        )
        handler.addFilter(_CorrelationFilter())
        logger.addHandler(handler)
    logger.propagate = False

