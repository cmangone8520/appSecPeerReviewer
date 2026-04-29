"""LLM client factory.

:func:`build_llm_client` is the single place that maps the ``LLM_PROVIDER``
config value to a concrete :class:`~app.llm.base.LLMClient` implementation.

Adding a new provider
---------------------
1. Create ``app/llm/my_provider_client.py`` implementing the
   :class:`~app.llm.base.LLMClient` Protocol.
2. Add an entry to :data:`_REGISTRY` below.
3. Set ``LLM_PROVIDER=my_provider`` in ``.env``.

No other files need to change.
"""

from __future__ import annotations

import logging
from collections.abc import Callable

from ..review.review_settings import ReviewSettings
from .anthropic_client import AnthropicClient
from .base import LLMClient
from .llm_settings import LLMSettings
from .openai_client import OpenAIClient

log = logging.getLogger("appsec_reviewer")

# ---------------------------------------------------------------------------
# Provider registry
# ---------------------------------------------------------------------------
# Maps provider name (lower-cased) -> factory that receives LLMSettings and
# returns a configured LLMClient.
# ---------------------------------------------------------------------------

_ProviderFactory = Callable[[LLMSettings], LLMClient]

_REGISTRY: dict[str, _ProviderFactory] = {
    "openai": lambda s: OpenAIClient(
        api_key=s.openai_api_key,
        model=s.openai_model,
        http_timeout=s.openai_http_timeout,
        max_output_tokens=s.openai_max_output_tokens,
    ),
    "anthropic": lambda s: AnthropicClient(
        api_key=s.anthropic_api_key,
        model=s.anthropic_model,
    ),
}


def build_llm_client(llm_settings: LLMSettings, review_settings: ReviewSettings) -> LLMClient:
    """Return a configured :class:`~app.llm.base.LLMClient` for the active provider.

    The provider is selected by ``LLMSettings.llm_provider`` (env var
    ``LLM_PROVIDER``).  Defaults to ``"openai"``.

    Raises
    ------
    ValueError
        When ``LLM_PROVIDER`` names an unknown provider.  Lists all registered
        providers in the error message so the operator knows what's available.
    """
    provider = llm_settings.llm_provider.lower()
    factory = _REGISTRY.get(provider)
    if factory is None:
        available = ", ".join(sorted(_REGISTRY))
        raise ValueError(
            f"Unknown LLM_PROVIDER={provider!r}. "
            f"Available providers: {available}. "
            "Add a new entry to app/llm/factory.py to register a custom provider."
        )
    client = factory(llm_settings)
    log.info(
        "llm client built provider=%s model=%s",
        client.provider,
        client.model,
    )
    return client
