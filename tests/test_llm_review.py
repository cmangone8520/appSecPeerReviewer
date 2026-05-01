"""Unit tests for the LLM review module.

Tests the response parsing, hallucination filtering, and edge cases
without making real OpenAI API calls.
"""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock

from app.config import Settings
from app.diff_parser import parse_diff
from app.review.llm import review_diff

DIFF = """diff --git a/app/main.py b/app/main.py
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


def _settings(**overrides) -> Settings:
    defaults = {
        "GITHUB_APP_ID": "12345",
        "GITHUB_APP_PRIVATE_KEY": "",
        "GITHUB_WEBHOOK_SECRET": "test-secret",
        "OPENAI_API_KEY": "sk-test",
    }
    defaults.update(overrides)
    return Settings(**defaults)


def _mock_client(content: str) -> AsyncMock:
    mock = AsyncMock()
    choice = MagicMock()
    choice.message.content = content
    resp = MagicMock()
    resp.choices = [choice]
    mock.chat.completions.create = AsyncMock(return_value=resp)
    return mock


async def test_review_diff_parses_valid_findings():
    findings_json = json.dumps(
        {
            "findings": [
                {
                    "file": "app/main.py",
                    "line": 6,
                    "severity": "high",
                    "vulnerability_class": "sql-injection",
                    "title": "SQL injection",
                    "explanation": "f-string in SQL",
                    "recommendation": "Use params",
                }
            ]
        }
    )
    client = _mock_client(findings_json)
    settings = _settings()
    parsed = parse_diff(DIFF)

    results = await review_diff(settings, DIFF, parsed, client=client)
    assert len(results) == 1
    assert results[0].vulnerability_class == "sql-injection"
    assert results[0].source == "llm"


async def test_review_diff_drops_hallucinated_lines():
    findings_json = json.dumps(
        {
            "findings": [
                {
                    "file": "app/main.py",
                    "line": 1,  # context line, not added
                    "severity": "medium",
                    "vulnerability_class": "info-disclosure",
                    "title": "Should be dropped",
                    "explanation": "...",
                    "recommendation": "...",
                }
            ]
        }
    )
    client = _mock_client(findings_json)
    settings = _settings()
    parsed = parse_diff(DIFF)

    results = await review_diff(settings, DIFF, parsed, client=client)
    assert results == []


async def test_review_diff_drops_nonexistent_file():
    findings_json = json.dumps(
        {
            "findings": [
                {
                    "file": "nonexistent.py",
                    "line": 5,
                    "severity": "high",
                    "vulnerability_class": "xss",
                    "title": "Ghost file",
                    "explanation": "...",
                    "recommendation": "...",
                }
            ]
        }
    )
    client = _mock_client(findings_json)
    settings = _settings()
    parsed = parse_diff(DIFF)

    results = await review_diff(settings, DIFF, parsed, client=client)
    assert results == []


async def test_review_diff_handles_malformed_json():
    client = _mock_client("NOT VALID JSON")
    settings = _settings()
    parsed = parse_diff(DIFF)

    results = await review_diff(settings, DIFF, parsed, client=client)
    assert results == []


async def test_review_diff_handles_empty_response():
    client = _mock_client("{}")
    settings = _settings()
    parsed = parse_diff(DIFF)

    results = await review_diff(settings, DIFF, parsed, client=client)
    assert results == []


async def test_review_diff_handles_null_content():
    mock = AsyncMock()
    choice = MagicMock()
    choice.message.content = None
    resp = MagicMock()
    resp.choices = [choice]
    mock.chat.completions.create = AsyncMock(return_value=resp)

    settings = _settings()
    parsed = parse_diff(DIFF)

    results = await review_diff(settings, DIFF, parsed, client=mock)
    assert results == []


async def test_review_diff_skips_when_no_api_key():
    settings = _settings(OPENAI_API_KEY="")
    parsed = parse_diff(DIFF)

    results = await review_diff(settings, DIFF, parsed)
    assert results == []


async def test_review_diff_skips_empty_diff():
    settings = _settings()
    parsed = parse_diff("")

    results = await review_diff(settings, "", parsed)
    assert results == []


async def test_review_diff_drops_malformed_finding_items():
    """Individual invalid findings should be dropped, valid ones kept."""
    findings_json = json.dumps(
        {
            "findings": [
                "not-a-dict",
                {
                    "file": "app/main.py",
                    "line": -1,  # invalid: ge=1
                    "severity": "high",
                    "vulnerability_class": "xss",
                    "title": "Bad line",
                    "explanation": "...",
                    "recommendation": "...",
                },
                {
                    "file": "app/main.py",
                    "line": 6,
                    "severity": "high",
                    "vulnerability_class": "sql-injection",
                    "title": "Valid finding",
                    "explanation": "...",
                    "recommendation": "...",
                },
            ]
        }
    )
    client = _mock_client(findings_json)
    settings = _settings()
    parsed = parse_diff(DIFF)

    results = await review_diff(settings, DIFF, parsed, client=client)
    assert len(results) == 1
    assert results[0].title == "Valid finding"


async def test_review_diff_sets_source_to_llm():
    """Even if the LLM doesn't return a 'source' field, it defaults to 'llm'."""
    findings_json = json.dumps(
        {
            "findings": [
                {
                    "file": "app/main.py",
                    "line": 2,
                    "severity": "medium",
                    "vulnerability_class": "unsafe-import",
                    "title": "sqlite3 import",
                    "explanation": "...",
                    "recommendation": "...",
                    # no "source" key
                }
            ]
        }
    )
    client = _mock_client(findings_json)
    settings = _settings()
    parsed = parse_diff(DIFF)

    results = await review_diff(settings, DIFF, parsed, client=client)
    assert len(results) == 1
    assert results[0].source == "llm"
