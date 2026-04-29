"""LLM-related runtime configuration."""

from __future__ import annotations

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class LLMSettings(BaseSettings):
    """LLM-related settings."""
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # LLM provider selection
    llm_provider: str = Field(
        default="openai",
        alias="LLM_PROVIDER",
        description="Active LLM provider. Supported values: openai, anthropic.",
    )

    # OpenAI
    openai_api_key: str = Field(default="", alias="OPENAI_API_KEY")
    openai_model: str = Field(default="gpt-4o", alias="OPENAI_MODEL")
    openai_http_timeout: float = Field(
        default=30.0,
        alias="OPENAI_HTTP_TIMEOUT",
        description="Timeout (seconds) for each OpenAI completion request.",
    )
    openai_max_output_tokens: int = Field(
        default=4096,
        alias="OPENAI_MAX_OUTPUT_TOKENS",
        description="Maximum output tokens requested from OpenAI per completion.",
    )

    # Anthropic (Claude)
    anthropic_api_key: str = Field(default="", alias="ANTHROPIC_API_KEY")
    anthropic_model: str = Field(
        default="claude-opus-4-5",
        alias="ANTHROPIC_MODEL",
    )

    # LLM Reviewer specific settings
    llm_fallback_prompt: str = Field(
        default=(
            "You are an application-security peer reviewer for a financial institution.\n"
            "Review the unified diff for security vulnerabilities on `+` lines only.\n"
            "Respond with ONLY a JSON object: "
            '{"findings": [{"file": "...", "line": 1, "severity": "high", '
            '"vulnerability_class": "...", "title": "...", '
            '"explanation": "...", "recommendation": "..."}]}'
        ),
        alias="LLM_FALLBACK_PROMPT",
        description="Fallback prompt for the LLM reviewer if prompt_file is not found.",
    )

    # Anthropic tuning
    anthropic_max_output_tokens: int = Field(
        default=4096,
        alias="ANTHROPIC_MAX_OUTPUT_TOKENS",
        description="Maximum tokens the Anthropic model may generate per request.",
    )
