"""Top-level review orchestration.

Given a unified diff, run the LLM reviewer + secret scan + dep CVE
lookup in parallel, dedupe overlapping findings, and return the
combined list ready to post as inline PR comments.
"""

from __future__ import annotations

import asyncio
import logging

from ..config import Settings
from ..diff_parser import parse_diff
from ..models import Finding
from . import deps as deps_mod
from . import llm as llm_mod
from . import secrets as secrets_mod

log = logging.getLogger(__name__)

_SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


async def run_review(settings: Settings, diff_text: str) -> list[Finding]:
    if not diff_text.strip():
        return []
    parsed = parse_diff(diff_text)
    if not parsed:
        return []

    llm_task = llm_mod.review_diff(settings, diff_text, parsed)
    osv_task = deps_mod.query_osv(deps_mod.extract_added_deps(parsed))
    secret_findings = secrets_mod.scan(parsed)

    llm_findings, dep_findings = await asyncio.gather(llm_task, osv_task, return_exceptions=True)

    findings: list[Finding] = list(secret_findings)
    if isinstance(llm_findings, Exception):
        log.warning("LLM review failed: %s", llm_findings)
    else:
        findings.extend(llm_findings)
    if isinstance(dep_findings, Exception):
        log.warning("Dep CVE check failed: %s", dep_findings)
    else:
        findings.extend(dep_findings)

    return _dedupe(findings)


def _dedupe(findings: list[Finding]) -> list[Finding]:
    """Collapse same (file, line, vuln_class), keeping the highest severity."""
    by_key: dict[tuple[str, int, str], Finding] = {}
    for f in findings:
        key = (f.file, f.line, f.vulnerability_class)
        prev = by_key.get(key)
        if prev is None or _SEVERITY_RANK[f.severity] > _SEVERITY_RANK[prev.severity]:
            by_key[key] = f
    out = list(by_key.values())
    out.sort(
        key=lambda f: (-_SEVERITY_RANK[f.severity], f.file, f.line),
    )
    return out


def summary_body(findings: list[Finding]) -> str:
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
