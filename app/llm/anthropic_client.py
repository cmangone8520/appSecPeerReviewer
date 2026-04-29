"""Anthropic (Claude) LLM client implementation.

Wraps the official ``anthropic`` Python SDK and normalises its response into the
provider-agnostic :class:`~app.llm.base.LLMResponse`.

Installation
------------
The ``anthropic`` package is an optional dependency.  Install it alongside the
project when you want to use Claude::

    pip install anthropic
    # or, if using uv:
    uv add anthropic

Configuration (via ``Settings`` / ``.env``)
-------------------------------------------
    LLM_PROVIDER=anthropic           # select this implementation
    ANTHROPIC_API_KEY=sk-ant-...
    ANTHROPIC_MODEL=claude-opus-4-5  # or claude-3-7-sonnet-20250219, etc.
"""

from __future__ import annotations

import logging

from .base import LLMResponse

log = logging.getLogger("appsec_reviewer")

# Maximum tokens the model may generate.  Claude's context window is large; we
# cap the response to keep latency predictable.
_MAX_OUTPUT_TOKENS = 4096


class AnthropicClient:
    """Anthropic Messages API client.

    Implements :class:`~app.llm.base.LLMClient`.

    Parameters
    ----------
    api_key:
        Anthropic API key (``ANTHROPIC_API_KEY``).
    model:
        Model identifier (``ANTHROPIC_MODEL``),
        e.g. ``"claude-opus-4-5"``.

    Raises
    ------
    ImportError
        When the ``anthropic`` package is not installed.
    """

    def __init__(self, api_key: str, model: str) -> None:
        try:
            import anthropic  # noqa: PLC0415
        except ImportError as exc:
            raise ImportError(
                "The 'anthropic' package is required to use LLM_PROVIDER=anthropic. "
                "Install it with:  pip install anthropic"
            ) from exc

        self._model = model
        self._client = anthropic.AsyncAnthropic(api_key=api_key)

    # ------------------------------------------------------------------
    # LLMClient Protocol
    # ------------------------------------------------------------------

    @property
    def provider(self) -> str:
        return "anthropic"

    @property
    def model(self) -> str:
        return self._model

    async def complete(self, system_prompt: str, user_message: str) -> LLMResponse:
        """Call Anthropic Messages API.

        Claude uses a top-level ``system`` parameter (not a message role) and
        returns JSON natively when instructed to do so in the system prompt.
        """
        log.info("anthropic complete model=%s", self._model)
        resp = await self._client.messages.create(
            model=self._model,
            max_tokens=_MAX_OUTPUT_TOKENS,
            system=system_prompt,
            messages=[{"role": "user", "content": user_message}],
        )
        # Extract text from the first content block.
        content = ""
        for block in resp.content:
            if hasattr(block, "text"):
                content = block.text.strip()
                break

        return LLMResponse(
            content=content,
            model=resp.model,
            input_tokens=resp.usage.input_tokens if resp.usage else 0,
            output_tokens=resp.usage.output_tokens if resp.usage else 0,
        )

