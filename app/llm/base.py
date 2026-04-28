"""Generic LLM client contract.

Any class that satisfies the :class:`LLMClient` ``Protocol`` can be returned
by :func:`~app.llm.factory.build_llm_client` and used by
:class:`~app.review.reviewers.llm.LLMReviewer` without knowing which provider
is behind it.

Implementing a new provider
---------------------------
1. Create ``app/llm/my_provider_client.py`` with a class that implements
   ``async def complete(system_prompt, user_message) -> LLMResponse``.
2. Add the provider name to
   :func:`~app.llm.factory.build_llm_client`.
3. Set ``LLM_PROVIDER=my_provider`` in ``.env``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable


@dataclass(frozen=True)
class LLMResponse:
    """Normalised response returned by every LLM provider.

    Attributes
    ----------
    content:
        The model's text output (already stripped of leading/trailing whitespace).
    model:
        The exact model identifier echoed back by the provider
        (e.g. ``"gpt-4o-2024-08-06"``).
    input_tokens:
        Number of tokens in the prompt; ``0`` when the provider doesn't report it.
    output_tokens:
        Number of tokens in the completion; ``0`` when not reported.
    """

    content: str
    model: str
    input_tokens: int = 0
    output_tokens: int = 0


@runtime_checkable
class LLMClient(Protocol):
    """Provider-agnostic LLM client interface.

    A class qualifies as an ``LLMClient`` if it exposes:

    - ``provider: str``  — human-readable provider name (e.g. ``"openai"``).
    - ``model: str``     — model identifier used for this instance.
    - ``complete(system_prompt, user_message) -> Awaitable[LLMResponse]``

    All exceptions from the underlying SDK should propagate as-is; the caller
    (:class:`~app.review.reviewers.llm.LLMReviewer`) handles them.
    """

    @property
    def provider(self) -> str:
        """Human-readable provider name (e.g. ``"openai"``, ``"anthropic"``)."""
        ...

    @property
    def model(self) -> str:
        """Model identifier used for this instance."""
        ...

    async def complete(
        self,
        system_prompt: str,
        user_message: str,
    ) -> LLMResponse:
        """Send a system + user turn and return the model's response.

        Parameters
        ----------
        system_prompt:
            The full system-level instructions (security review prompt).
        user_message:
            The user-facing content (the unified diff wrapped in markdown).

        Returns
        -------
        LLMResponse
            Normalised response with ``content``, ``model``, and token counts.
        """
        ...

