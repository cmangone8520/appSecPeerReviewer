"""High-confidence secret detector.

We deliberately keep this list short and tight — false positives are very
expensive in a PR-review bot. Each pattern targets a vendor-issued credential
shape that is hard to confuse with normal code.

Detection runs only over `+` lines in the diff so we don't flag
pre-existing secrets that this PR didn't introduce.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from ..diff_parser import FileDiff
from ..models import Finding


@dataclass(frozen=True)
class SecretPattern:
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


def scan(parsed: list[FileDiff]) -> list[Finding]:
    findings: list[Finding] = []
    for f in parsed:
        if f.is_binary or not f.path:
            continue
        # Reconstruct (line_no, content) for each + line.
        for line_no, content in _iter_added_lines(f):
            for p in PATTERNS:
                if p.regex.search(content):
                    findings.append(
                        Finding(
                            file=f.path,
                            line=line_no,
                            severity="critical" if "private-key" in p.name else "high",
                            vulnerability_class="hardcoded-secret",
                            title=f"Possible {p.name} committed",
                            explanation=(
                                f"This added line matches the `{p.name}` pattern. "
                                "Committed secrets must be rotated even after "
                                "removal — git history preserves them indefinitely."
                            ),
                            recommendation=(
                                "Remove the value, rotate the credential at the issuer, "
                                "and load it from a secret store / environment variable instead."
                            ),
                            source="secret-scan",
                        )
                    )
                    break  # one pattern hit per line is enough
    return findings


def _iter_added_lines(file_diff: FileDiff):
    """Yield (new_line_no, content) for every `+` line in the file's diff."""
    new_line_no: int | None = None
    for raw in file_diff.raw.splitlines():
        if raw.startswith("@@"):
            # Hunk header. Reuse the same regex as diff_parser.
            from ..diff_parser import _HUNK_RE  # local import to avoid cycles

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
