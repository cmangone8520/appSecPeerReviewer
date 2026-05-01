"""Integration tests for the full review pipeline with mocked external services.

These exercise run_review end-to-end: diff parsing → parallel scanners → dedup,
with the LLM and OSV.dev calls mocked via respx / patched OpenAI client.
"""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock

import httpx
import respx

from app.config import Settings
from app.review.pipeline import run_review

VULN_DIFF = """diff --git a/app/main.py b/app/main.py
index 1111111..2222222 100644
--- a/app/main.py
+++ b/app/main.py
@@ -1,3 +1,6 @@
 import os
+import sqlite3
+
+def query(name):
+    conn = sqlite3.connect("db")
+    return conn.execute(f"SELECT * FROM users WHERE name = '{name}'")
"""

SECRET_DIFF = """diff --git a/config.py b/config.py
index 1..2 100644
--- a/config.py
+++ b/config.py
@@ -1,2 +1,4 @@
 X = 1
+AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
+OPENAI_KEY = "sk-proj-abcdefghij1234567890"
 Y = 2
"""

DEP_DIFF = """diff --git a/requirements.txt b/requirements.txt
index 1..2 100644
--- a/requirements.txt
+++ b/requirements.txt
@@ -1,1 +1,3 @@
 fastapi==0.115.0
+requests==2.19.0
+jinja2==2.10
"""

CLEAN_DIFF = """diff --git a/README.md b/README.md
index aaa..bbb 100644
--- a/README.md
+++ b/README.md
@@ -1,1 +1,2 @@
 # My Project
+This is a safe README update.
"""


def _settings(**overrides) -> Settings:
    defaults = {
        "GITHUB_APP_ID": "12345",
        "GITHUB_APP_PRIVATE_KEY": "",
        "GITHUB_WEBHOOK_SECRET": "test-secret",
        "OPENAI_API_KEY": "sk-test-key",
    }
    defaults.update(overrides)
    return Settings(**defaults)


def _mock_openai_response(findings: list[dict]) -> AsyncMock:
    """Build a mock AsyncOpenAI client that returns the given findings."""
    mock_client = AsyncMock()
    mock_choice = MagicMock()
    mock_choice.message.content = json.dumps({"findings": findings})
    mock_response = MagicMock()
    mock_response.choices = [mock_choice]
    mock_client.chat.completions.create = AsyncMock(return_value=mock_response)
    return mock_client


async def test_pipeline_detects_sql_injection_via_llm(monkeypatch):
    """LLM returns a valid finding on an added line; it should survive filtering."""
    llm_findings = [
        {
            "file": "app/main.py",
            "line": 6,
            "severity": "high",
            "vulnerability_class": "sql-injection",
            "title": "SQL injection via f-string",
            "explanation": "User input interpolated directly into SQL query.",
            "recommendation": "Use parameterized queries.",
        }
    ]
    mock_client = _mock_openai_response(llm_findings)
    monkeypatch.setattr("app.review.llm.AsyncOpenAI", lambda **kw: mock_client)

    settings = _settings()
    findings = await run_review(settings, VULN_DIFF)

    sql_findings = [f for f in findings if f.vulnerability_class == "sql-injection"]
    assert len(sql_findings) == 1
    assert sql_findings[0].file == "app/main.py"
    assert sql_findings[0].line == 6
    assert sql_findings[0].severity == "high"
    assert sql_findings[0].source == "llm"


async def test_pipeline_detects_secrets():
    """Secret scan should flag AWS key and OpenAI key without any LLM call."""
    settings = _settings(OPENAI_API_KEY="")  # no LLM key → skip LLM
    findings = await run_review(settings, SECRET_DIFF)

    secret_findings = [f for f in findings if f.source == "secret-scan"]
    assert len(secret_findings) >= 2
    classes = {f.vulnerability_class for f in secret_findings}
    assert "hardcoded-secret" in classes
    titles = {f.title for f in secret_findings}
    assert any("aws" in t for t in titles)
    assert any("openai" in t for t in titles)


@respx.mock
async def test_pipeline_detects_vulnerable_deps():
    """Dependency scanner should flag known CVEs via mocked OSV."""
    respx.post("https://api.osv.dev/v1/query").mock(
        side_effect=_osv_side_effect,
    )
    settings = _settings(OPENAI_API_KEY="")  # skip LLM
    findings = await run_review(settings, DEP_DIFF)

    dep_findings = [f for f in findings if f.source == "dependency-cve"]
    assert len(dep_findings) >= 1
    assert any("requests" in f.title for f in dep_findings)


def _osv_side_effect(request: httpx.Request) -> httpx.Response:
    body = json.loads(request.content)
    name = body["package"]["name"]
    if name == "requests":
        return httpx.Response(
            200,
            json={
                "vulns": [
                    {
                        "id": "PYSEC-2023-001",
                        "summary": "CRLF injection in requests",
                        "severity": [{"type": "CVSS_V3", "score": "HIGH"}],
                    }
                ]
            },
        )
    return httpx.Response(200, json={})


async def test_pipeline_clean_diff_no_findings(monkeypatch):
    """A clean diff with no vulnerabilities should produce zero findings."""
    mock_client = _mock_openai_response([])
    monkeypatch.setattr("app.review.llm.AsyncOpenAI", lambda **kw: mock_client)

    settings = _settings()
    findings = await run_review(settings, CLEAN_DIFF)
    assert findings == []


async def test_pipeline_empty_diff():
    settings = _settings()
    findings = await run_review(settings, "")
    assert findings == []
    findings = await run_review(settings, "   \n  ")
    assert findings == []


async def test_pipeline_llm_hallucination_filter(monkeypatch):
    """LLM findings on non-added lines should be dropped."""
    llm_findings = [
        {
            "file": "app/main.py",
            "line": 1,  # line 1 is a context line (import os), NOT added
            "severity": "high",
            "vulnerability_class": "info-disclosure",
            "title": "Hallucinated finding",
            "explanation": "This line wasn't added.",
            "recommendation": "N/A",
        },
        {
            "file": "app/main.py",
            "line": 6,  # this IS an added line
            "severity": "high",
            "vulnerability_class": "sql-injection",
            "title": "Real finding",
            "explanation": "SQL injection.",
            "recommendation": "Parameterize.",
        },
        {
            "file": "nonexistent.py",  # file doesn't exist in diff
            "line": 5,
            "severity": "medium",
            "vulnerability_class": "xss",
            "title": "Ghost file finding",
            "explanation": "File not in diff.",
            "recommendation": "N/A",
        },
    ]
    mock_client = _mock_openai_response(llm_findings)
    monkeypatch.setattr("app.review.llm.AsyncOpenAI", lambda **kw: mock_client)

    settings = _settings()
    findings = await run_review(settings, VULN_DIFF)

    llm_results = [f for f in findings if f.source == "llm"]
    assert len(llm_results) == 1
    assert llm_results[0].title == "Real finding"


async def test_pipeline_llm_malformed_json(monkeypatch):
    """LLM returning garbage JSON should not crash; scanner results still returned."""
    mock_client = AsyncMock()
    mock_choice = MagicMock()
    mock_choice.message.content = "NOT VALID JSON {{{{"
    mock_response = MagicMock()
    mock_response.choices = [mock_choice]
    mock_client.chat.completions.create = AsyncMock(return_value=mock_response)
    monkeypatch.setattr("app.review.llm.AsyncOpenAI", lambda **kw: mock_client)

    settings = _settings()
    findings = await run_review(settings, SECRET_DIFF)

    # LLM fails gracefully; secret scanner still finds the AWS + OpenAI keys.
    assert len(findings) >= 2
    assert all(f.source == "secret-scan" for f in findings)


async def test_pipeline_dedupes_across_scanners(monkeypatch):
    """If LLM and secret scan both flag the same line, keep highest severity."""
    llm_findings = [
        {
            "file": "config.py",
            "line": 2,
            "severity": "medium",
            "vulnerability_class": "hardcoded-secret",
            "title": "Possible secret",
            "explanation": "Looks like a credential.",
            "recommendation": "Use env vars.",
        }
    ]
    mock_client = _mock_openai_response(llm_findings)
    monkeypatch.setattr("app.review.llm.AsyncOpenAI", lambda **kw: mock_client)

    settings = _settings()
    findings = await run_review(settings, SECRET_DIFF)

    # line 2 of config.py: LLM says medium, secret-scan says high.
    # Dedup should keep the high-severity one.
    line2 = [f for f in findings if f.file == "config.py" and f.line == 2]
    assert len(line2) == 1
    assert line2[0].severity == "high"


@respx.mock
async def test_pipeline_osv_failure_does_not_crash(monkeypatch):
    """If OSV.dev is unreachable, the pipeline still returns other findings."""
    respx.post("https://api.osv.dev/v1/query").mock(
        return_value=httpx.Response(500, text="Internal Server Error"),
    )
    mock_client = _mock_openai_response([])
    monkeypatch.setattr("app.review.llm.AsyncOpenAI", lambda **kw: mock_client)

    settings = _settings()
    # DEP_DIFF has dependency additions but OSV will fail
    findings = await run_review(settings, DEP_DIFF)
    # Should not raise; returns whatever other scanners found (nothing here)
    assert isinstance(findings, list)


async def test_pipeline_llm_failure_does_not_crash(monkeypatch):
    """If the LLM call throws, the pipeline still returns secret scan results."""
    mock_client = AsyncMock()
    mock_client.chat.completions.create = AsyncMock(side_effect=RuntimeError("API down"))
    monkeypatch.setattr("app.review.llm.AsyncOpenAI", lambda **kw: mock_client)

    settings = _settings()
    findings = await run_review(settings, SECRET_DIFF)

    # LLM failed, but secret scan should still find the AWS and OpenAI keys.
    assert len(findings) >= 2
    assert all(f.source == "secret-scan" for f in findings)
