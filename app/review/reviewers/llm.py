"""LLM-based security reviewer plugin.

Sends the PR unified diff to the configured LLM provider and validates the
JSON response against the :class:`~app.models.Finding` schema.

The reviewer is **provider-agnostic** — it delegates all LLM calls to a
:class:`~app.llm.base.LLMClient` instance built by
:func:`~app.llm.factory.build_llm_client`.  To swap from OpenAI to Claude set::

    LLM_PROVIDER=anthropic
    ANTHROPIC_API_KEY=sk-ant-...
    ANTHROPIC_MODEL=claude-opus-4-5

in ``.env`` and restart.  No code changes required.

Prompt customisation
--------------------
Edit ``prompts/security_review.txt`` (or the file pointed to by ``PROMPT_FILE``).
Restart the server to pick up changes.
"""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from ...config import Settings
from ...diff.parser import is_added_line
from ...llm import LLMClient, build_llm_client
from ...models import Finding
from ..base import ReviewContext

log = logging.getLogger("appsec_reviewer")


# ---------------------------------------------------------------------------
# Prompt management
# ---------------------------------------------------------------------------


def _load_prompt(prompt_file: str, fallback_prompt: str) -> str:
    """Load the system prompt from *prompt_file*, falling back gracefully."""
    path = Path(prompt_file)
    try:
        text = path.read_text(encoding="utf-8").strip()
        log.info("loaded system prompt path=%s chars=%d", path, len(text))
        return text
    except FileNotFoundError:
        log.warning(
            "prompt file not found path=%s — using fallback prompt. "
            "Create the file to customise review instructions.",
            path,
        )
        return fallback_prompt
    except OSError as exc:
        log.warning(
            "prompt file unreadable path=%s error=%s — using fallback prompt",
            path,
            exc,
        )
        return fallback_prompt


# ---------------------------------------------------------------------------
# Reviewer plugin class
# ---------------------------------------------------------------------------


class LLMReviewer:
    """Provider-agnostic LLM security reviewer.

    Implements :class:`~app.review.base.Reviewer`.

    The concrete LLM provider (OpenAI, Anthropic, …) is injected via
    :class:`~app.llm.base.LLMClient`.  Use
    :func:`~app.llm.factory.build_llm_client` or pass a custom client directly
    (useful for testing).

    Parameters
    ----------
    settings:
        Application settings used to load the prompt file and, if no *client*
        is provided, to construct the default client via the factory.
    client:
        Optional pre-built :class:`~app.llm.base.LLMClient`.  Constructed from
        *settings* when not supplied.
    """

    name = "llm"

    def __init__(
        self,
        settings: Settings,
        *,
        client: LLMClient | None = None,
    ) -> None:
        self._settings = settings
        self._client: LLMClient = client or build_llm_client(settings.llm, settings.review)
        self._system_prompt = _load_prompt(settings.review.prompt_file, settings.llm.llm_fallback_prompt)
        log.info(
            "LLMReviewer initialised provider=%s model=%s",
            self._client.provider,
            self._client.model,
        )

    # ------------------------------------------------------------------
    # Reviewer Protocol
    # ------------------------------------------------------------------

    async def review(self, ctx: ReviewContext) -> list[Finding]:
        """Call the LLM and return validated, line-checked findings."""
        settings = ctx.settings

        # Validate that the active provider has its key configured.
        if not self._has_api_key(settings):
            log.warning(
                "no API key configured for provider=%s; skipping LLM review",
                self._client.provider,
            )
            return []

        if not ctx.diff_text.strip():
            log.info("llm review skipped: empty diff delivery=%s", ctx.delivery_id)
            return []

        started = time.perf_counter()
        log.info(
            "llm review start provider=%s model=%s diff_bytes=%d delivery=%s",
            self._client.provider,
            self._client.model,
            len(ctx.diff_text.encode()),
            ctx.delivery_id,
        )

        user_message = f"Unified diff under review:\n\n```diff\n{ctx.diff_text}\n```"
        try:
            response = await self._client.complete(self._system_prompt, user_message)
        except Exception as exc:
            log.warning(
                "llm complete error provider=%s delivery=%s error=%s",
                self._client.provider,
                ctx.delivery_id,
                exc,
            )
            return []

        elapsed_ms = int((time.perf_counter() - started) * 1000)
        log.info(
            "llm review response provider=%s model=%s payload_chars=%d "
            "input_tokens=%d output_tokens=%d elapsed_ms=%d delivery=%s",
            self._client.provider,
            response.model,
            len(response.content),
            response.input_tokens,
            response.output_tokens,
            elapsed_ms,
            ctx.delivery_id,
        )

        return self._parse_findings(response.content, ctx)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _has_api_key(self, settings: Settings) -> bool:
        """Return True when the active provider has a non-empty API key."""
        provider = self._client.provider
        if provider == "openai":
            return bool(settings.llm.openai_api_key)
        if provider == "anthropic":
            return bool(settings.llm.anthropic_api_key)
        # Unknown provider — assume key is present and let the SDK fail loudly.
        return True

    def _parse_findings(self, raw: str, ctx: ReviewContext) -> list[Finding]:
        """Parse the LLM JSON response into validated :class:`Finding` objects."""
        try:
            payload: Any = json.loads(raw)
        except json.JSONDecodeError as exc:
            log.warning(
                "llm non-json response provider=%s delivery=%s error=%s",
                self._client.provider,
                ctx.delivery_id,
                exc,
            )
            return []

        items = payload.get("findings") if isinstance(payload, dict) else None
        if not isinstance(items, list):
            log.info(
                "llm returned no findings array provider=%s delivery=%s",
                self._client.provider,
                ctx.delivery_id,
            )
            return []

        out: list[Finding] = []
        counters = {"malformed": 0, "non_added": 0, "non_dict": 0}

        for item in items:
            if not isinstance(item, dict):
                counters["non_dict"] += 1
                continue
            item.setdefault("source", "llm")
            try:
                finding = Finding(**item)
            except ValidationError as exc:
                log.info(
                    "llm malformed finding dropped delivery=%s error=%s",
                    ctx.delivery_id,
                    exc,
                )
                counters["malformed"] += 1
                continue
            if not is_added_line(ctx.parsed, finding.file, finding.line):
                log.info(
                    "llm hallucinated line dropped file=%s line=%d delivery=%s",
                    finding.file,
                    finding.line,
                    ctx.delivery_id,
                )
                counters["non_added"] += 1
                continue
            out.append(finding)

        log.info(
            "llm review complete provider=%s accepted=%d dropped=%s delivery=%s",
            self._client.provider,
            len(out),
            counters,
            ctx.delivery_id,
        )
        return out
