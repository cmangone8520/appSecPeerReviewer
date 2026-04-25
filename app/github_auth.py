"""GitHub App authentication: app JWT + per-installation tokens.

GitHub Apps use a two-step auth flow:
  1. Sign a short-lived JWT with the app's RSA private key (app identity).
  2. Exchange that JWT for a per-installation access token, scoped to one install.

Installation tokens are what we actually use for repo API calls.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

import httpx
import jwt

from .config import Settings


@dataclass
class InstallationToken:
    token: str
    expires_at: float  # epoch seconds


def _mint_app_jwt(settings: Settings) -> str:
    if not settings.github_app_id or not settings.github_app_private_key:
        raise RuntimeError("GITHUB_APP_ID and GITHUB_APP_PRIVATE_KEY must be set")
    now = int(time.time())
    payload = {
        # Backdate iat by 60s to tolerate clock skew on GitHub's side.
        "iat": now - 60,
        "exp": now + 9 * 60,
        "iss": settings.github_app_id,
    }
    private_key = settings.github_app_private_key.replace("\\n", "\n")
    return jwt.encode(payload, private_key, algorithm="RS256")


async def get_installation_token(
    settings: Settings,
    installation_id: int,
    *,
    client: httpx.AsyncClient | None = None,
) -> InstallationToken:
    """Exchange an app JWT for a per-installation access token (≈1h lifetime)."""
    app_jwt = _mint_app_jwt(settings)
    headers = {
        "Authorization": f"Bearer {app_jwt}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    url = f"{settings.github_api_base}/app/installations/{installation_id}/access_tokens"

    owns_client = client is None
    client = client or httpx.AsyncClient(timeout=15.0)
    try:
        resp = await client.post(url, headers=headers)
        resp.raise_for_status()
        body = resp.json()
    finally:
        if owns_client:
            await client.aclose()

    expires_at = time.time() + 55 * 60  # GitHub returns ~1h; refresh a bit early.
    return InstallationToken(token=body["token"], expires_at=expires_at)
