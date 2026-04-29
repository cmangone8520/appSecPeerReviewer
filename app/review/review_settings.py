"""Review-related runtime configuration."""

from __future__ import annotations

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class ReviewSettings(BaseSettings):
    """Review-related settings."""
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # Review pipeline
    prompt_file: str = Field(
        default="prompts/security_review.txt",
        alias="PROMPT_FILE",
        description="Path (relative to project root) to the LLM system-prompt file.",
    )
    max_diff_bytes: int = Field(
        default=200_000,
        alias="MAX_DIFF_BYTES",
        description="Diffs larger than this are skipped to avoid LLM context blowup.",
    )

    # Secret Reviewer specific settings
    secret_vulnerability_class: str = Field(
        default="hardcoded-secret",
        alias="SECRET_VULNERABILITY_CLASS",
        description="Vulnerability class for hardcoded secrets.",
    )
    secret_explanation_template: str = Field(
        default=(
            "This added line matches the `{pattern_name}` pattern. "
            "Committed secrets must be rotated even after removal "
            "— git history preserves them indefinitely."
        ),
        alias="SECRET_EXPLANATION_TEMPLATE",
        description="Template for the explanation of a hardcoded secret finding.",
    )
    secret_recommendation_template: str = Field(
        default=(
            "Remove the value, rotate the credential at the issuer, "
            "and load it from a secret store or environment variable."
        ),
        alias="SECRET_RECOMMENDATION_TEMPLATE",
        description="Template for the recommendation of a hardcoded secret finding.",
    )
    secret_source: str = Field(
        default="secret-scan",
        alias="SECRET_SOURCE",
        description="Source identifier for secret scan findings.",
    )

    # Dependency Reviewer specific settings
    deps_vulnerability_class: str = Field(
        default="vulnerable-dependency",
        alias="DEPS_VULNERABILITY_CLASS",
        description="Vulnerability class for vulnerable dependencies.",
    )
    deps_explanation_template: str = Field(
        default=(
            "OSV reports {num_vulns} known "
            "{'vulnerability' if num_vulns == 1 else 'vulnerabilities'} "
            "affecting `{dep_name}=={dep_version}` ({dep_ecosystem}). "
            "Top advisory: {summary}"
        ),
        alias="DEPS_EXPLANATION_TEMPLATE",
        description="Template for the explanation of a vulnerable dependency finding.",
    )
    deps_recommendation_template: str = Field(
        default=(
            "Upgrade `{dep_name}` to a non-vulnerable version "
            "(see the linked advisories on osv.dev)."
        ),
        alias="DEPS_RECOMMENDATION_TEMPLATE",
        description="Template for the recommendation of a vulnerable dependency finding.",
    )
    deps_source: str = Field(
        default="dependency-cve",
        alias="DEPS_SOURCE",
        description="Source identifier for dependency CVE findings.",
    )

    # OSV.dev dependency-CVE checker
    osv_api_url: str = Field(
        default="https://api.osv.dev/v1/query",
        alias="OSV_API_URL",
        description="OSV.dev single-package query endpoint.",
    )
    osv_batch_api_url: str = Field(
        default="https://api.osv.dev/v1/querybatch",
        alias="OSV_BATCH_API_URL",
        description="OSV.dev batch query endpoint (reserved for future use).",
    )
    osv_http_timeout: float = Field(
        default=15.0,
        alias="OSV_HTTP_TIMEOUT",
        description="Timeout (seconds) for each OSV.dev API call.",
    )
