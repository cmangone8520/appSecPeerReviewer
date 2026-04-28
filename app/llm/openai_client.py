"""OpenAI LLM client implementation.

Wraps the official ``openai`` Python SDK and normalises its response into the
provider-agnostic :class:`~app.llm.base.LLMResponse`.

Configuration (via ``Settings`` / ``.env``)
-------------------------------------------
    LLM_PROVIDER=openai            # select this implementation
    OPENAI_API_KEY=sk-...
    OPENAI_MODEL=gpt-4o            # any model that supports json_object response format
"""

from __future__ import annotations

import logging

from openai import AsyncOpenAI

from .base import LLMResponse

log = logging.getLogger("appsec_reviewer")


class OpenAIClient:
    """OpenAI chat-completions client.

    Implements :class:`~app.llm.base.LLMClient`.

    Parameters
    ----------
    api_key:
        OpenAI API key (``OPENAI_API_KEY``).
    model:
        Model identifier (``OPENAI_MODEL``), e.g. ``"gpt-4o"``.
    """

    def __init__(
        self,
        api_key: str,
        model: str,
        *,
        http_timeout: float = 30.0,
        max_output_tokens: int = 4096,
    ) -> None:
        self._api_key = api_key
        self._model = model
        self._max_output_tokens = max_output_tokens
        self._client = AsyncOpenAI(api_key=api_key, timeout=http_timeout)

    # ------------------------------------------------------------------
    # LLMClient Protocol
    # ------------------------------------------------------------------

    @property
    def provider(self) -> str:
        return "openai"

    @property
    def model(self) -> str:
        return self._model

    async def complete(self, system_prompt: str, user_message: str) -> LLMResponse:
        """Call OpenAI chat-completions with ``json_object`` response format."""
        log.info("openai complete model=%s", self._model)
        resp = await self._client.chat.completions.create(
            model=self._model,
            max_tokens=self._max_output_tokens,
            response_format={"type": "json_object"},
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_message},
            ],
        )
        content = resp.choices[0].message.content or "{}"
        usage = resp.usage
        return LLMResponse(
            content=content.strip(),
            model=resp.model,
            input_tokens=usage.prompt_tokens if usage else 0,
            output_tokens=usage.completion_tokens if usage else 0,
        )

