"""Dependency-CVE checker via the public OSV.dev API.

We look at the changed manifests (requirements.txt, pyproject.toml,
package.json) on `+` lines, extract `name@version`, and ask OSV whether
that exact pinned version has known vulnerabilities.

Notes / limitations:
  - This is intentionally narrow — only newly-added pinned dependencies
    are checked. Range specifiers and transitive deps are out of scope
    for the MVP (would need a full lockfile parse).
  - OSV is queried over HTTPS; no auth required.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass

import httpx

from ..diff_parser import FileDiff
from ..models import Finding

log = logging.getLogger(__name__)

OSV_URL = "https://api.osv.dev/v1/query"


@dataclass(frozen=True)
class DepRef:
    file: str
    line: int
    ecosystem: str  # "PyPI" | "npm"
    name: str
    version: str


_REQ_RE = re.compile(r"^\s*([A-Za-z0-9_.\-]+)\s*==\s*([0-9][^\s;#]*)")
_PYPROJECT_RE = re.compile(r"\"([A-Za-z0-9_.\-]+)==([0-9][^\"\s]*)\"")
_NPM_RE = re.compile(r'"([@A-Za-z0-9_./\-]+)"\s*:\s*"((?:\^|~|=)?)([0-9][^"]+)"')


def extract_added_deps(files: list[FileDiff]) -> list[DepRef]:
    deps: list[DepRef] = []
    for f in files:
        if f.is_binary or not f.path:
            continue
        path = f.path.lower()
        is_py_req = path.endswith("requirements.txt") or path.endswith("requirements-dev.txt")
        is_pyproject = path.endswith("pyproject.toml")
        is_pkgjson = path.endswith("package.json")
        if not (is_py_req or is_pyproject or is_pkgjson):
            continue

        for line_no, content in _iter_added(f):
            if is_py_req:
                m = _REQ_RE.match(content)
                if m:
                    deps.append(
                        DepRef(f.path, line_no, "PyPI", m.group(1), m.group(2).strip())
                    )
            elif is_pyproject:
                for m in _PYPROJECT_RE.finditer(content):
                    deps.append(DepRef(f.path, line_no, "PyPI", m.group(1), m.group(2)))
            elif is_pkgjson:
                for m in _NPM_RE.finditer(content):
                    name, _prefix, version = m.group(1), m.group(2), m.group(3)
                    if name in ("dependencies", "devDependencies"):
                        continue
                    deps.append(DepRef(f.path, line_no, "npm", name, version))
    return deps


async def query_osv(
    deps: list[DepRef], *, client: httpx.AsyncClient | None = None
) -> list[Finding]:
    if not deps:
        return []
    owns = client is None
    client = client or httpx.AsyncClient(timeout=15.0)
    findings: list[Finding] = []
    try:
        for dep in deps:
            try:
                resp = await client.post(
                    OSV_URL,
                    json={
                        "package": {"name": dep.name, "ecosystem": dep.ecosystem},
                        "version": dep.version,
                    },
                )
                resp.raise_for_status()
                vulns = resp.json().get("vulns") or []
            except (httpx.HTTPError, json.JSONDecodeError) as e:
                log.warning("OSV lookup failed for %s@%s: %s", dep.name, dep.version, e)
                continue
            if not vulns:
                continue
            ids = ", ".join(v.get("id", "?") for v in vulns[:5])
            top = vulns[0]
            summary = top.get("summary") or top.get("details") or "No summary available"
            findings.append(
                Finding(
                    file=dep.file,
                    line=dep.line,
                    severity=_severity_from_osv(vulns),
                    vulnerability_class="vulnerable-dependency",
                    title=f"{dep.name}@{dep.version} has known vulnerabilities ({ids})",
                    explanation=(
                        f"OSV reports {len(vulns)} known vulnerabilit"
                        f"{'y' if len(vulns) == 1 else 'ies'} affecting "
                        f"`{dep.name}=={dep.version}` ({dep.ecosystem}). "
                        f"Top advisory: {summary}"
                    ),
                    recommendation=(
                        f"Upgrade `{dep.name}` to a non-vulnerable version "
                        "(see the linked advisories on osv.dev)."
                    ),
                    source="dependency-cve",
                )
            )
    finally:
        if owns:
            await client.aclose()
    return findings


def _severity_from_osv(vulns: list[dict]) -> str:
    # OSV severities are inconsistent across ecosystems; we collapse to
    # 'high' for any reported CVE and bump to 'critical' if any advisory
    # is explicitly marked CRITICAL.
    for v in vulns:
        for sev in v.get("severity", []) or []:
            if str(sev.get("score", "")).upper().startswith("CRITICAL"):
                return "critical"
        if any(d.get("type") == "CVSS_V3" for d in v.get("severity", []) or []):
            return "high"
    return "medium"


def _iter_added(file_diff: FileDiff):
    """Same shape as secrets._iter_added_lines, intentionally duplicated to avoid coupling."""
    from ..diff_parser import _HUNK_RE  # local import

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
