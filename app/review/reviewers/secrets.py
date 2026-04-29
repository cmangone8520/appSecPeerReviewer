"""Secret-scanner reviewer plugin.

Scans every ``+`` line in the diff against a curated set of vendor-published
credential patterns.  Runs synchronously (no external I/O) and is therefore
the fastest of the three built-in reviewers.

Extending the pattern list
--------------------------
Add a :class:`SecretPattern` entry to :data:`PATTERNS`.  Use the vendor's own
published token shape where possible — tight patterns mean fewer false positives.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from types import SimpleNamespace

from ...config import Settings
from ...diff.models import FileDiff
from ...diff.parser import _HUNK_RE
from ...models import Finding
from ..base import ReviewContext

log = logging.getLogger("appsec_reviewer")


# ---------------------------------------------------------------------------
# Pattern catalogue
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SecretPattern:
    """A single secret-detection rule."""

    name: str
    regex: re.Pattern[str]
    severity: str = "high"


# Patterns sourced from each vendor's own published prefixes / formats.
PATTERNS: tuple[SecretPattern, ...] = (
    SecretPattern("aws-access-key-id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    SecretPattern(
        "aws-secret-access-key",
        re.compile(r"(?i)aws(.{0,20})?(secret|sk)[^A-Za-z0-9]{0,5}([A-Za-z0-9/+=]{40})"),
    ),
    SecretPattern("github-pat", re.compile(r"\bghp_[A-Za-z0-9]{36}\b")),
    SecretPattern("github-fine-grained-pat", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{82}\b")),
    SecretPattern("github-app-token", re.compile(r"\b(ghs|ghu)_[A-Za-z0-9]{36}\b")),
    SecretPattern("openai-api-key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{20,}\b")),
    SecretPattern("stripe-secret", re.compile(r"\b(sk|rk)_(live|test)_[A-Za-z0-9]{20,}\b")),
    SecretPattern("slack-bot-token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
    SecretPattern("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    SecretPattern(
        "private-key-block",
        re.compile(r"-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    ),
)


# ---------------------------------------------------------------------------
# Core scanning logic (module-level function kept for direct/test use)
# ---------------------------------------------------------------------------


def scan(parsed: list[FileDiff], settings: Settings | None = None) -> list[Finding]:
    """Scan *parsed* diff files for hardcoded secrets.

    Returns one :class:`~app.models.Finding` per matched line (at most one
    pattern match per line — the highest-confidence match wins).
    """
    if settings is None:
        # Keep scan() backwards-compatible for tests/direct calls without
        # requiring the full app runtime environment variables.
        settings = SimpleNamespace(
            review=SimpleNamespace(
                secret_vulnerability_class="hardcoded-secret",
                secret_explanation_template=(
                    "This added line matches the `{pattern_name}` pattern. "
                    "Committed secrets must be rotated even after removal "
                    "— git history preserves them indefinitely."
                ),
                secret_recommendation_template=(
                    "Remove the value, rotate the credential at the issuer, "
                    "and load it from a secret store or environment variable."
                ),
                secret_source="secret-scan",
            )
        )

    log.info("secret scan start files=%d", len(parsed))
    findings: list[Finding] = []

    for f in parsed:
        if f.is_binary or not f.path:
            continue
        for line_no, content in _iter_added_lines(f):
            for p in PATTERNS:
                if p.regex.search(content):
                    log.info(
                        "secret pattern matched file=%s line=%d pattern=%s",
                        f.path,
                        line_no,
                        p.name,
                    )
                    findings.append(
                        Finding(
                            file=f.path,
                            line=line_no,
                            severity="critical" if "private-key" in p.name else "high",
                            vulnerability_class=settings.review.secret_vulnerability_class,
                            title=f"Possible {p.name} committed",
                            explanation=settings.review.secret_explanation_template.format(
                                pattern_name=p.name
                            ),
                            recommendation=settings.review.secret_recommendation_template,
                            source=settings.review.secret_source,
                        )
                    )
                    break  # one finding per line is sufficient

    log.info("secret scan complete findings=%d", len(findings))
    return findings


def _iter_added_lines(file_diff: FileDiff):  # noqa: ANN201
    """Yield ``(new_line_no, content)`` for every ``+`` line in *file_diff*."""
    new_line_no: int | None = None
    for raw in file_diff.raw.splitlines():
        if raw.startswith("@@"):
            m = _HUNK_RE.match(raw)
            if m:
                new_line_no = int(m.group(1))
            continue
        if new_line_no is None:
            continue
        if raw.startswith("+") and not raw.startswith("+++"):
            yield new_line_no, raw[1:]
            new_line_no += 1
        elif raw.startswith("-") and not raw.startswith("---"):
            continue
        else:
            new_line_no += 1


# ---------------------------------------------------------------------------
# Reviewer plugin class
# ---------------------------------------------------------------------------


class SecretScanner:
    """Reviewer plugin that wraps the :func:`scan` function.

    Implements :class:`~app.review.base.Reviewer`.
    """

    name = "secret-scan"

    async def review(self, ctx: ReviewContext) -> list[Finding]:
        """Run secret scan over the diff; always returns immediately (no I/O)."""
        return scan(ctx.parsed, ctx.settings)
