"""LLM-based security reviewer.

We give the model the unified diff and ask for a strict JSON response of findings,
then validate it against our `Finding` schema. Findings on lines that aren't
actually `+` lines in the diff are dropped — the model occasionally hallucinates
line numbers, and posting to a non-diff line will be rejected by GitHub anyway.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from openai import AsyncOpenAI
from pydantic import ValidationError

from ..config import Settings
from ..diff_parser import FileDiff, is_added_line
from ..models import Finding

log = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are an application-security peer reviewer.
You read unified git diffs and report concrete, exploitable security issues
that the diff INTRODUCES OR LEAVES IN PLACE on `+` lines.

Vulnerability classes you must consider include (non-exhaustive):
  - OWASP Top 10 (injection, broken auth, broken access control, SSRF,
    insecure deserialization, XXE, security misconfiguration, sensitive
    data exposure, insufficient logging, vulnerable components).
  - Hardcoded secrets / credentials / API keys / private keys.
  - Unsafe crypto (weak hashes, ECB, hardcoded IVs, predictable RNG).
  - Path traversal, command injection, unsafe deserialization,
    template / prompt injection.
  - Authn/authz mistakes: missing auth checks on sensitive endpoints,
    IDOR, JWT verification mistakes, weak session handling.
  - SSRF / open redirects.
  - Logging or returning sensitive data (PII, tokens, secrets).

Rules:
  - Only report issues you can point to a specific `+` line for.
  - `line` MUST be a line number that appears as a `+` line in the diff
    (post-change line numbers).
  - Be precise. Do not make up file paths or line numbers.
  - If the diff has no security issues, return an empty findings array.
  - Do NOT comment on style, performance, or non-security bugs.

Respond with ONLY a JSON object of the form:
  {"findings": [
     {"file": "...", "line": 12, "severity": "high",
      "vulnerability_class": "sql-injection",
      "title": "...", "explanation": "...", "recommendation": "..."}
  ]}
Severity must be one of: info, low, medium, high, critical.
"""


async def review_diff(
    settings: Settings,
    diff_text: str,
    parsed: list[FileDiff],
    *,
    client: AsyncOpenAI | None = None,
) -> list[Finding]:
    if not settings.openai_api_key:
        log.warning("OPENAI_API_KEY missing; skipping LLM review")
        return []
    if not diff_text.strip():
        return []

    client = client or AsyncOpenAI(api_key=settings.openai_api_key)
    resp = await client.chat.completions.create(
        model=settings.openai_model,
        response_format={"type": "json_object"},
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": f"Unified diff under review:\n\n```diff\n{diff_text}\n```"},
        ],
    )
    raw = resp.choices[0].message.content or "{}"

    try:
        payload: Any = json.loads(raw)
    except json.JSONDecodeError as e:
        log.warning("LLM returned non-JSON payload (%s); dropping", e)
        return []

    items = payload.get("findings") if isinstance(payload, dict) else None
    if not isinstance(items, list):
        return []

    out: list[Finding] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        item.setdefault("source", "llm")
        try:
            f = Finding(**item)
        except ValidationError as e:
            log.info("Dropping malformed finding: %s", e)
            continue
        if not is_added_line(parsed, f.file, f.line):
            log.info(
                "Dropping finding on non-added line %s:%s (LLM hallucination)", f.file, f.line
            )
            continue
        out.append(f)
    return out
