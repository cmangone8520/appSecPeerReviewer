"""GitHub App authentication: app JWT + per-installation access tokens.

GitHub Apps use a two-step auth flow:

1. Sign a short-lived JWT (≤ 10 min) with the app's RSA private key — this
   proves the caller's identity as the GitHub App.
2. Exchange that JWT for a per-installation access token (≈ 1 h) — this is
   scoped to a single installation and is used for all repository API calls.

The JWT is minted fresh on every call because tokens are cheap to produce and
caching them would add complexity without measurable benefit at this scale.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass

import httpx
import jwt

from ..exceptions import AuthenticationError
from .github_settings import GitHubSettings

log = logging.getLogger("appsec_reviewer")


# ---------------------------------------------------------------------------
# Data transfer objects
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class InstallationToken:
    """A GitHub per-installation access token with its expiry time."""

    token: str
    expires_at: float  # Unix epoch seconds


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _mint_app_jwt(settings: GitHubSettings) -> str:
    """Create a signed RS256 JWT identifying this GitHub App.

    Raises
    ------
    AuthenticationError
        When ``GITHUB_APP_ID`` or ``GITHUB_APP_PRIVATE_KEY`` is not configured.
    """
    if not settings.github_app_id or not settings.github_app_private_key:
        raise AuthenticationError(
            "GITHUB_APP_ID and GITHUB_APP_PRIVATE_KEY must be set to authenticate "
            "as a GitHub App."
        )

    log.info("minting app jwt app_id=%s", settings.github_app_id)
    now = int(time.time())
    payload = {
        # IAT is backdated by 60 s to tolerate clock skew on GitHub's side.
        "iat": now - settings.github_jwt_clock_skew_seconds,
        "exp": now + settings.github_jwt_expiry_seconds,
        "iss": settings.github_app_id,
    }
    # Support both literal-\n escaped PEM strings and real multiline PEM.
    private_key = settings.github_app_private_key.replace("\\n", "\n")
    token = jwt.encode(payload, private_key, algorithm=settings.github_jwt_algorithm)
    log.info("app jwt minted app_id=%s valid_for_s=%d", settings.github_app_id, settings.github_jwt_expiry_seconds)
    return token


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


async def get_installation_token(
    settings: GitHubSettings,
    installation_id: int,
    *,
    client: httpx.AsyncClient | None = None,
) -> InstallationToken:
    """Exchange an app JWT for a per-installation access token.

    Parameters
    ----------
    settings:
        Application settings carrying the app credentials.
    installation_id:
        The numeric installation ID from the webhook payload.
    client:
        Optional pre-built ``httpx.AsyncClient``; useful for testing.

    Returns
    -------
    InstallationToken
        A fresh token valid for approximately 55 minutes.

    Raises
    ------
    AuthenticationError
        When the GitHub API rejects the request.
    """
    started = time.perf_counter()
    log.info("requesting installation token installation_id=%d", installation_id)

    app_jwt = _mint_app_jwt(settings)
    url = f"{settings.github_api_base}/app/installations/{installation_id}/access_tokens"
    headers = {
        "Authorization": f"Bearer {app_jwt}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": settings.github_api_version,
    }

    owns_client = client is None
    client = client or httpx.AsyncClient(timeout=settings.github_auth_http_timeout)
    try:
        resp = await client.post(url, headers=headers)
        log.info(
            "installation token response installation_id=%d status=%d",
            installation_id,
            resp.status_code,
        )
        if not resp.is_success:
            raise AuthenticationError(
                f"GitHub returned {resp.status_code} when requesting an installation "
                f"token for installation_id={installation_id}: {resp.text[:200]}"
            )
        body = resp.json()
    finally:
        if owns_client:
            await client.aclose()

    expires_at = time.time() + settings.github_token_expiry_buffer_seconds  # GitHub issues ≈1 h; refresh a bit early.
    elapsed_ms = int((time.perf_counter() - started) * 1000)
    log.info(
        "installation token acquired installation_id=%d expires_in_s=%d elapsed_ms=%d",
        installation_id,
        settings.github_token_expiry_buffer_seconds,
        elapsed_ms,
    )
    return InstallationToken(token=body["token"], expires_at=expires_at)
