"""GitHub webhook signature verification.

GitHub signs each webhook delivery with HMAC-SHA256 over the raw request
body, keyed by the webhook secret you configured on the App. We MUST
compare in constant time and reject anything that doesn't match — without
this check, anyone on the internet can post fake events to /webhook.
"""

from __future__ import annotations

import hashlib
import hmac


def verify_signature(secret: str, body: bytes, signature_header: str | None) -> bool:
    if not secret:
        # Fail closed if the deploy is misconfigured.
        return False
    if not signature_header or not signature_header.startswith("sha256="):
        return False
    expected = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature_header)
