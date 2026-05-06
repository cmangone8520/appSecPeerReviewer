"""OpenAI LLM client implementation.

Wraps the official ``openai`` Python SDK and normalises its response into the
provider-agnostic :class:`~app.llm.base.LLMResponse`.

Configuration (via ``Settings`` / ``.env``)
-------------------------------------------
    LLM_PROVIDER=openai            # select this implementation
    OPENAI_API_KEY=sk-...
    OPENAI_MODEL=gpt-4o            # any chat-completions model
"""

from __future__ import annotations

import asyncio
import logging

from openai import AsyncOpenAI

from .base import LLMResponse

log = logging.getLogger("appsec_reviewer")

# Models that do NOT support response_format=json_object.
# For these we rely entirely on prompt instructions to return JSON.
_NO_JSON_FORMAT_PREFIXES = ("o1", "o3", "o4", "gpt-5")


class OpenAIClient:
    """OpenAI chat-completions client.

    Implements :class:`~app.llm.base.LLMClient`.

    Parameters
    ----------
    api_key:
        OpenAI API key (``OPENAI_API_KEY``).
    model:
        Model identifier (``OPENAI_MODEL``), e.g. ``"gpt-4o"``.
    http_timeout:
        Hard timeout in seconds for the API call.  Set to 0 to disable.
    """

    def __init__(
        self,
        api_key: str,
        model: str,
        *,
        http_timeout: float = 300.0,
        max_output_tokens: int = 4096,
    ) -> None:
        self._api_key = api_key
        self._model = model
        self._max_output_tokens = max_output_tokens
        self._http_timeout = http_timeout
        # Pass None to the SDK to disable its own timeout — we use asyncio.wait_for instead.
        self._client = AsyncOpenAI(api_key=api_key, timeout=None)
        log.info(
            "openai client initialised model=%s asyncio_timeout=%s max_output_tokens=%d",
            model,
            f"{http_timeout}s" if http_timeout > 0 else "none",
            max_output_tokens,
        )

    # ------------------------------------------------------------------
    # LLMClient Protocol
    # ------------------------------------------------------------------

    @property
    def provider(self) -> str:
        return "openai"

    @property
    def model(self) -> str:
        return self._model

    def _supports_json_format(self) -> bool:
        """Return False for models that don't support response_format=json_object."""
        lower = self._model.lower()
        return not any(lower.startswith(p) for p in _NO_JSON_FORMAT_PREFIXES)

    async def complete(self, system_prompt: str, user_message: str) -> LLMResponse:
        """Call OpenAI chat-completions and return a normalised LLMResponse."""
        use_json_format = self._supports_json_format()
        log.info(
            "openai calling model=%s json_format=%s timeout=%ss",
            self._model,
            use_json_format,
            self._http_timeout if self._http_timeout > 0 else "none",
        )

        kwargs: dict = dict(
            model=self._model,
            max_completion_tokens=self._max_output_tokens,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_message},
            ],
        )
        if use_json_format:
            kwargs["response_format"] = {"type": "json_object"}

        try:
            coro = self._client.chat.completions.create(**kwargs)
            if self._http_timeout > 0:
                resp = await asyncio.wait_for(coro, timeout=self._http_timeout)
            else:
                resp = await coro
        except asyncio.TimeoutError:
            log.error(
                "openai timeout model=%s timeout=%ss",
                self._model,
                self._http_timeout,
            )
            raise

        log.info(
            "openai response received model=%s input_tokens=%s output_tokens=%s",
            resp.model,
            resp.usage.prompt_tokens if resp.usage else "?",
            resp.usage.completion_tokens if resp.usage else "?",
        )
        content = resp.choices[0].message.content or "{}"
        usage = resp.usage
        return LLMResponse(
            content=content.strip(),
            model=resp.model,
            input_tokens=usage.prompt_tokens if usage else 0,
            output_tokens=usage.completion_tokens if usage else 0,
        )
