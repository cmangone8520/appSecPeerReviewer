"""GitHub-related runtime configuration."""

from __future__ import annotations

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class GitHubSettings(BaseSettings):
    """GitHub-related settings."""
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # GitHub App
    github_app_id: str = Field(default="", alias="GITHUB_APP_ID")
    github_app_private_key: str = Field(default="", alias="GITHUB_APP_PRIVATE_KEY")
    github_webhook_secret: str = Field(default="", alias="GITHUB_WEBHOOK_SECRET")
    github_api_base: str = Field(
        default="https://api.github.com",
        alias="GITHUB_API_BASE",
    )

    # GitHub API protocol constants
    github_api_version: str = Field(
        default="2022-11-28",
        alias="GITHUB_API_VERSION",
        description="GitHub REST API version header sent on every request.",
    )
    github_user_agent: str = Field(
        default="appsec-peer-reviewer/1.0",
        alias="GITHUB_USER_AGENT",
        description="User-Agent header sent on every GitHub API request.",
    )
    github_http_timeout: float = Field(
        default=30.0,
        alias="GITHUB_HTTP_TIMEOUT",
        description="Timeout (seconds) for diff-fetch and review-post requests.",
    )
    github_auth_http_timeout: float = Field(
        default=15.0,
        alias="GITHUB_AUTH_HTTP_TIMEOUT",
        description="Timeout (seconds) for GitHub App installation-token requests.",
    )

    # GitHub App JWT tuning
    github_jwt_expiry_seconds: int = Field(
        default=540,
        alias="GITHUB_JWT_EXPIRY_SECONDS",
        description="Lifetime of the signed app JWT (max GitHub allows is 600 s).",
    )
    github_jwt_clock_skew_seconds: int = Field(
        default=60,
        alias="GITHUB_JWT_CLOCK_SKEW_SECONDS",
        description="Seconds to back-date the JWT iat claim to tolerate clock skew.",
    )
    github_jwt_algorithm: str = Field(
        default="RS256",
        alias="GITHUB_JWT_ALGORITHM",
        description="JWT signing algorithm used when minting the app JWT.",
    )
    github_token_expiry_buffer_seconds: int = Field(
        default=3300,
        alias="GITHUB_TOKEN_EXPIRY_BUFFER_SECONDS",
        description="How many seconds before actual expiry we treat the token as expired (55 min).",
    )

    # GitHub review settings
    github_review_event: str = Field(
        default="COMMENT",
        alias="GITHUB_REVIEW_EVENT",
        description="PR review event type: COMMENT, APPROVE, or REQUEST_CHANGES.",
    )
