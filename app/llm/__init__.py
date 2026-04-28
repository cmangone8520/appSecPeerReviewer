"""LLM integration package.

Swap providers by changing ``LLM_PROVIDER`` in your ``.env``::

    LLM_PROVIDER=openai      # default
    LLM_PROVIDER=anthropic   # Claude

Public surface::

    from app.llm import LLMClient, LLMResponse, build_llm_client
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .base import LLMClient, LLMResponse

if TYPE_CHECKING:
    from .factory import build_llm_client

__all__ = ["LLMClient", "LLMResponse", "build_llm_client"]


def __getattr__(name: str):
    if name == "build_llm_client":
        from .factory import build_llm_client as _build_llm_client

        return _build_llm_client
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

