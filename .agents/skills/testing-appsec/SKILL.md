# Testing appSecPeerReviewer

## Overview
The appSecPeerReviewer is a FastAPI backend (no frontend UI). All testing is shell-based.

## Quick Commands

```bash
# Activate venv
source .venv/bin/activate

# Run full test suite
pytest -v

# Run lint
ruff check app tests

# Start the server (for live HTTP testing)
uvicorn app.main:app --host 0.0.0.0 --port 8080 --reload
```

## Test Suite Structure

| File | What it tests |
|---|---|
| `tests/test_deps.py` | Dependency extraction from requirements.txt, pyproject.toml |
| `tests/test_diff_parser.py` | Unified diff parsing, added-line detection |
| `tests/test_secrets.py` | Secret pattern regex scanning (AWS, GitHub, OpenAI, etc.) |
| `tests/test_webhook_sig.py` | HMAC-SHA256 webhook signature verification |
| `tests/test_pipeline_dedupe.py` | Finding deduplication and summary body generation |
| `tests/test_webhook_endpoint.py` | Full webhook route (signature, event routing, action filtering) |
| `tests/test_pipeline_integration.py` | Full review pipeline with mocked OpenAI + OSV.dev |
| `tests/test_llm_review.py` | LLM review module (parsing, hallucination filter, edge cases) |

## Live Server Testing (Webhook)

The webhook endpoint requires HMAC-SHA256 signature verification. To test locally:

```bash
# Start server with a known webhook secret
GITHUB_WEBHOOK_SECRET=testsecret123 uvicorn app.main:app --host 0.0.0.0 --port 8080 --reload

# Compute signature and send a signed ping request
SECRET="testsecret123"
BODY='{"zen":"test ping"}'
SIG="sha256=$(echo -n "$BODY" | openssl dgst -sha256 -hmac "$SECRET" | awk '{print $2}')"

curl -s -X POST http://localhost:8080/webhook \
  -H "Content-Type: application/json" \
  -H "X-GitHub-Event: ping" \
  -H "X-Hub-Signature-256: $SIG" \
  -d "$BODY"
# Expected: {"status":"pong"} with HTTP 202
```

### Adversarial Auth Test
Send the same payload with an invalid signature (expect 401) then with a valid signature (expect 202). This proves the signature gate is the deciding factor.

## Mocking Strategy

- **OpenAI**: Use `unittest.mock.AsyncMock` to mock `AsyncOpenAI` client. Patch at `app.review.llm.AsyncOpenAI`.
- **OSV.dev**: Use `respx` to mock HTTP calls to `https://api.osv.dev/v1/query`.
- **Settings**: Use `monkeypatch.setattr("app.main.get_settings", lambda: settings)` to override config in endpoint tests.

## Devin Secrets Needed

For **unit/integration tests**: No secrets needed (all external calls are mocked).

For **full end-to-end testing with real GitHub webhooks**:
- `OPENAI_API_KEY` — for real LLM review
- `GITHUB_APP_ID` — GitHub App numeric ID
- `GITHUB_APP_PRIVATE_KEY` — PEM private key for the GitHub App
- `GITHUB_WEBHOOK_SECRET` — shared secret for webhook HMAC verification

A smee.io tunnel (`npx smee-client`) is also needed to forward GitHub webhooks to localhost.

## Key Behaviors to Verify

1. Unsigned requests → 401
2. Ping events → 202 + `{"status":"pong"}`
3. Non-PR events → 202 + `ignored`
4. Draft PRs → 202 + `ignored`
5. Valid PR events (opened/synchronize/reopened/ready_for_review) → 202 + `scheduled`
6. Missing `installation.id` → 400
7. LLM hallucinations (findings on non-added lines) → dropped silently
8. Scanner failures (LLM or OSV down) → other scanners still return results
9. Cross-scanner dedup → highest severity kept per (file, line, vuln_class)
