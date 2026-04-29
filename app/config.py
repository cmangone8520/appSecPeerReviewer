"""Runtime configuration loaded from environment variables / .env file.

All settings are read via ``pydantic-settings`` so they can be overridden by
environment variables, a ``.env`` file, or injected in tests.  Call
``get_settings()`` everywhere — the result is cached via ``@lru_cache`` so the
file is only read once per process.
"""

from __future__ import annotations

from functools import lru_cache

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from .github.github_settings import GitHubSettings
from .llm.llm_settings import LLMSettings
from .review.review_settings import ReviewSettings


class Settings(BaseSettings):
    """Validated runtime configuration for appSec Peer Reviewer.

    Required for a fully functional deployment:
        GITHUB_APP_ID, GITHUB_APP_PRIVATE_KEY, GITHUB_WEBHOOK_SECRET,
        OPENAI_API_KEY.

    Optional (have safe defaults):
        OPENAI_MODEL, GITHUB_API_BASE, MAX_DIFF_BYTES, LOG_LEVEL,
        PROMPT_FILE.
    """

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    github: GitHubSettings = Field(default_factory=GitHubSettings)
    llm: LLMSettings = Field(default_factory=LLMSettings)
    review: ReviewSettings = Field(default_factory=ReviewSettings)

    # ------------------------------------------------------------------
    # Application metadata
    # ------------------------------------------------------------------
    app_name: str = Field(
        default="appSec Peer Reviewer",
        alias="APP_NAME",
        description="Application name shown in FastAPI docs and PR review comments.",
    )
    app_version: str = Field(
        default="1.0.0",
        alias="APP_VERSION",
        description="Application version shown in FastAPI docs.",
    )
    app_env: str = Field(
        default="development",
        alias="APP_ENV",
        description="Runtime environment: development, test, staging, production.",
    )

    # ------------------------------------------------------------------
    # Observability
    # ------------------------------------------------------------------
    log_level: str = Field(default="INFO", alias="LOG_LEVEL")
    strict_startup_validation: bool = Field(
        default=False,
        alias="STRICT_STARTUP_VALIDATION",
        description="When true, require all integration secrets at app startup.",
    )
    max_webhook_bytes: int = Field(
        default=1_048_576,  # 1 MiB
        alias="MAX_WEBHOOK_BYTES",
        description="Maximum accepted webhook payload size in bytes.",
    )
    webhook_replay_ttl_seconds: int = Field(
        default=600,
        alias="WEBHOOK_REPLAY_TTL_SECONDS",
        description="How long to remember delivery IDs to ignore webhook replays.",
    )
    webhook_replay_cache_size: int = Field(
        default=10_000,
        alias="WEBHOOK_REPLAY_CACHE_SIZE",
        description="Maximum delivery IDs stored in replay cache.",
    )

    # ------------------------------------------------------------------
    # Validators
    # ------------------------------------------------------------------

    @field_validator("log_level")
    @classmethod
    def _validate_log_level(cls, v: str) -> str:
        valid = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        upper = v.upper()
        if upper not in valid:
            raise ValueError(f"LOG_LEVEL must be one of {valid}, got: {v!r}")
        return upper

    @field_validator("max_webhook_bytes", "webhook_replay_ttl_seconds", "webhook_replay_cache_size")
    @classmethod
    def _validate_positive_int(cls, v: int) -> int:
        if v <= 0:
            raise ValueError("must be a positive integer")
        return v

    @field_validator("app_env")
    @classmethod
    def _normalize_app_env(cls, v: str) -> str:
        return v.strip().lower()

    @model_validator(mode="after")
    def _validate_required_runtime_secrets(self) -> Settings:
        should_validate = self.strict_startup_validation or self.app_env in {
            "prod",
            "production",
            "staging",
        }
        if not should_validate:
            return self

        missing: list[str] = []
        if not self.github.github_app_id.strip():
            missing.append("GITHUB_APP_ID")
        if not self.github.github_app_private_key.strip():
            missing.append("GITHUB_APP_PRIVATE_KEY")
        if not self.github.github_webhook_secret.strip():
            missing.append("GITHUB_WEBHOOK_SECRET")

        provider = self.llm.llm_provider.strip().lower()
        if provider == "openai" and not self.llm.openai_api_key.strip():
            missing.append("OPENAI_API_KEY")
        if provider == "anthropic" and not self.llm.anthropic_api_key.strip():
            missing.append("ANTHROPIC_API_KEY")

        if missing:
            names = ", ".join(missing)
            raise ValueError(f"Missing required environment variables: {names}")
        return self

    # The max_diff_bytes validator was moved to ReviewSettings
    # @field_validator("max_diff_bytes")
    # @classmethod
    # def _validate_max_diff_bytes(cls, v: int) -> int:
    #     if v <= 0:
    #         raise ValueError(f"MAX_DIFF_BYTES must be a positive integer, got: {v}")
    #     return v


@lru_cache
def get_settings() -> Settings:
    """Return the cached application ``Settings`` singleton."""
    return Settings()
