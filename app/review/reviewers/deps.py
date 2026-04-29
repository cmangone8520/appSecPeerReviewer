"""Dependency-CVE reviewer plugin.

Parses newly-added pinned dependency lines from common manifest formats and
queries the public OSV.dev API for known vulnerabilities.

Supported manifest files
------------------------
- ``requirements*.txt`` (pip)
- ``pyproject.toml`` (PEP 517 / Poetry)
- ``package.json`` (npm)

Limitations (MVP)
-----------------
- Only ``name==version`` (PyPI) and ``"name": "version"`` (npm) pinned entries
  are checked; range specifiers, lockfiles, and transitive deps are out of scope.
"""

from __future__ import annotations

import json
import logging
import re
import time
from dataclasses import dataclass

import httpx

from ...config import Settings
from ...diff.models import FileDiff
from ...diff.parser import _HUNK_RE
from ...models import Finding
from ..base import ReviewContext

log = logging.getLogger("appsec_reviewer")


# ---------------------------------------------------------------------------
# Data transfer objects
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DepRef:
    """A pinned dependency identified in the diff."""

    file: str
    line: int
    ecosystem: str   # "PyPI" | "npm"
    name: str
    version: str


# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------

_REQ_RE = re.compile(r"^\s*([A-Za-z0-9_.\-]+)\s*==\s*([0-9][^\s;#]*)")
_PYPROJECT_RE = re.compile(r"\"([A-Za-z0-9_.\-]+)==([0-9][^\"\s]*)\"")
_NPM_RE = re.compile(r'"([@A-Za-z0-9_./\-]+)"\s*:\s*"((?:\^|~|=)?)([0-9][^"]+)"')

# Match any pip requirements-style file (requirements.txt, requirements-dev.txt, …).
_REQ_FILE_RE = re.compile(r"(^|/)requirements([_\-./][^/]*)?\.txt$")


# ---------------------------------------------------------------------------
# Dependency extraction (module-level for direct / test use)
# ---------------------------------------------------------------------------


def extract_added_deps(files: list[FileDiff]) -> list[DepRef]:
    """Extract newly-pinned dependencies from the diff."""
    log.info("dependency extractor start files=%d", len(files))
    deps: list[DepRef] = []

    for f in files:
        if f.is_binary or not f.path:
            continue
        path = f.path.lower()
        is_py_req = bool(_REQ_FILE_RE.search(path))
        is_pyproject = path.endswith("pyproject.toml")
        is_pkgjson = path.endswith("package.json")
        if not (is_py_req or is_pyproject or is_pkgjson):
            continue

        for line_no, content in _iter_added(f):
            if is_py_req:
                m = _REQ_RE.match(content)
                if m:
                    deps.append(DepRef(f.path, line_no, "PyPI", m.group(1), m.group(2).strip()))
            elif is_pyproject:
                for m in _PYPROJECT_RE.finditer(content):
                    deps.append(DepRef(f.path, line_no, "PyPI", m.group(1), m.group(2)))
            elif is_pkgjson:
                for m in _NPM_RE.finditer(content):
                    name, _prefix, version = m.group(1), m.group(2), m.group(3)
                    if name in ("dependencies", "devDependencies"):
                        continue
                    deps.append(DepRef(f.path, line_no, "npm", name, version))

    log.info("dependency extractor complete deps=%d", len(deps))
    return deps


# ---------------------------------------------------------------------------
# OSV.dev API
# ---------------------------------------------------------------------------


async def query_osv(
    deps: list[DepRef],
    settings: Settings,
    *,
    client: httpx.AsyncClient | None = None,
) -> list[Finding]:
    """Query OSV.dev for vulnerabilities in *deps* and return Findings."""
    if not deps:
        log.info("osv query skipped: no dependencies")
        return []

    started = time.perf_counter()
    log.info("osv query start deps=%d", len(deps))
    owns_client = client is None
    client = client or httpx.AsyncClient(timeout=settings.review.osv_http_timeout)
    findings: list[Finding] = []

    try:
        for dep in deps:
            try:
                resp = await client.post(
                    settings.review.osv_api_url,
                    json={
                        "package": {"name": dep.name, "ecosystem": dep.ecosystem},
                        "version": dep.version,
                    },
                )
                log.info(
                    "osv response dep=%s@%s ecosystem=%s status=%d",
                    dep.name,
                    dep.version,
                    dep.ecosystem,
                    resp.status_code,
                )
                resp.raise_for_status()
                vulns = resp.json().get("vulns") or []
            except (httpx.HTTPError, json.JSONDecodeError) as exc:
                log.warning("osv lookup failed dep=%s@%s error=%s", dep.name, dep.version, exc)
                continue

            if not vulns:
                log.info("osv clean dep=%s@%s", dep.name, dep.version)
                continue

            log.info("osv vulnerable dep=%s@%s advisories=%d", dep.name, dep.version, len(vulns))
            ids = ", ".join(v.get("id", "?") for v in vulns[:5])
            top = vulns[0]
            summary = top.get("summary") or top.get("details") or "No summary available"
            findings.append(
                Finding(
                    file=dep.file,
                    line=dep.line,
                    severity=_severity_from_osv(vulns),
                    vulnerability_class=settings.review.deps_vulnerability_class,
                    title=f"{dep.name}@{dep.version} has known vulnerabilities ({ids})",
                    explanation=settings.review.deps_explanation_template.format(
                        num_vulns=len(vulns),
                        dep_name=dep.name,
                        dep_version=dep.version,
                        dep_ecosystem=dep.ecosystem,
                        summary=summary,
                    ),
                    recommendation=settings.review.deps_recommendation_template.format(
                        dep_name=dep.name
                    ),
                    source=settings.review.deps_source,
                )
            )
    finally:
        if owns_client:
            await client.aclose()

    elapsed_ms = int((time.perf_counter() - started) * 1000)
    log.info(
        "osv query complete deps=%d findings=%d elapsed_ms=%d",
        len(deps),
        len(findings),
        elapsed_ms,
    )
    return findings


def _severity_from_osv(vulns: list[dict]) -> str:
    strongest_score = -1.0
    for v in vulns:
        db_severity = str(v.get("database_specific", {}).get("severity", "")).strip().lower()
        if db_severity in {"critical", "high", "medium", "low"}:
            return db_severity
        for sev in v.get("severity", []) or []:
            raw_score = str(sev.get("score", "")).strip()
            raw_upper = raw_score.upper()
            if raw_upper.startswith("CRITICAL"):
                return "critical"
            match = re.search(r"([0-9]+(?:\.[0-9]+)?)", raw_score)
            if match:
                strongest_score = max(strongest_score, float(match.group(1)))

    if strongest_score >= 9.0:
        return "critical"
    if strongest_score >= 7.0:
        return "high"
    if strongest_score >= 4.0:
        return "medium"
    if strongest_score >= 0.1:
        return "low"
    return "medium"


def _iter_added(file_diff: FileDiff):  # noqa: ANN201
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


class DependencyReviewer:
    """Reviewer plugin that checks newly-pinned deps against OSV.dev.

    Implements :class:`~app.review.base.Reviewer`.
    """

    name = "dependency-cve"

    async def review(self, ctx: ReviewContext) -> list[Finding]:
        """Extract pinned deps from the diff and query OSV.dev."""
        deps = extract_added_deps(ctx.parsed)
        return await query_osv(deps, ctx.settings)
