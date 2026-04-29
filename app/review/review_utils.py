"""Utility functions for PR review processing."""

from __future__ import annotations

from ..models import Finding

_SEVERITY_RANK: dict[str, int] = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def summary_body(findings: list[Finding]) -> str:
    """Build the markdown body for the top-level PR review comment."""
    if not findings:
        return (
            "**appSec Peer Reviewer**\n\n"
            "No security findings on this diff. "
            "(Reviewed via OpenAI + secret scan + OSV CVE check.)"
        )
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    pieces = [
        f"{n} {sev}"
        for sev, n in sorted(counts.items(), key=lambda kv: -_SEVERITY_RANK[kv[0]])
    ]
    return (
        "**appSec Peer Reviewer**\n\n"
        f"Found {len(findings)} potential security issue(s): {', '.join(pieces)}. "
        "See inline comments. Each finding is one of: LLM-detected (OWASP/auth/crypto), "
        "secret-scan (regex on added lines), or dependency-cve (OSV.dev lookup on pinned versions)."
    )


def dedupe_findings(findings: list[Finding]) -> list[Finding]:
    """Collapse findings with the same ``(file, line, vulnerability_class)``.

    When duplicates exist the entry with the highest severity is kept.
    The output is sorted by severity descending, then file, then line.
    """
    by_key: dict[tuple[str, int, str], Finding] = {}
    for f in findings:
        key = (f.file, f.line, f.vulnerability_class)
        prev = by_key.get(key)
        if prev is None or _SEVERITY_RANK[f.severity] > _SEVERITY_RANK[prev.severity]:
            by_key[key] = f
    return sorted(
        by_key.values(),
        key=lambda f: (-_SEVERITY_RANK[f.severity], f.file, f.line),
    )
