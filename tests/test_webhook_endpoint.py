"""Integration tests for the /webhook endpoint.

These test the full FastAPI route: signature verification, event routing,
background-task scheduling, and edge cases like draft PRs and ignored actions.
"""

from __future__ import annotations

import hashlib
import hmac
import json

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import app

SECRET = "test-webhook-secret"


def _sign(secret: str, body: bytes) -> str:
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def _pr_payload(
    action: str = "opened",
    *,
    draft: bool = False,
    installation_id: int = 999,
) -> dict:
    return {
        "action": action,
        "installation": {"id": installation_id},
        "repository": {
            "name": "test-repo",
            "owner": {"login": "test-owner"},
        },
        "pull_request": {
            "number": 42,
            "draft": draft,
            "head": {"sha": "abc123def456"},
        },
    }


@pytest.fixture
def client(monkeypatch):
    """Patch get_settings at the module level so the webhook route picks it up."""
    settings = Settings(
        GITHUB_APP_ID="12345",
        GITHUB_APP_PRIVATE_KEY="",
        GITHUB_WEBHOOK_SECRET=SECRET,
        OPENAI_API_KEY="",
    )
    monkeypatch.setattr("app.main.get_settings", lambda: settings)
    with TestClient(app) as c:
        yield c, settings


def test_health(client):
    c, _ = client
    resp = c.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_webhook_rejects_bad_signature(client):
    c, _ = client
    body = json.dumps(_pr_payload()).encode()
    resp = c.post(
        "/webhook",
        content=body,
        headers={
            "X-GitHub-Event": "pull_request",
            "X-Hub-Signature-256": "sha256=badsig",
            "Content-Type": "application/json",
        },
    )
    assert resp.status_code == 401


def test_webhook_rejects_missing_signature(client):
    c, _ = client
    body = json.dumps(_pr_payload()).encode()
    resp = c.post(
        "/webhook",
        content=body,
        headers={
            "X-GitHub-Event": "pull_request",
            "Content-Type": "application/json",
        },
    )
    assert resp.status_code == 401


def test_webhook_pong(client):
    c, settings = client
    body = json.dumps({"zen": "test"}).encode()
    sig = _sign(settings.github_webhook_secret, body)
    resp = c.post(
        "/webhook",
        content=body,
        headers={
            "X-GitHub-Event": "ping",
            "X-Hub-Signature-256": sig,
            "Content-Type": "application/json",
        },
    )
    assert resp.status_code == 202
    assert resp.json()["status"] == "pong"


def test_webhook_ignores_non_pr_event(client):
    c, settings = client
    body = json.dumps({"action": "created"}).encode()
    sig = _sign(settings.github_webhook_secret, body)
    resp = c.post(
        "/webhook",
        content=body,
        headers={
            "X-GitHub-Event": "issues",
            "X-Hub-Signature-256": sig,
            "Content-Type": "application/json",
        },
    )
    assert resp.status_code == 202
    assert "ignored" in resp.json()["status"]


def test_webhook_ignores_closed_action(client):
    c, settings = client
    payload = _pr_payload(action="closed")
    body = json.dumps(payload).encode()
    sig = _sign(settings.github_webhook_secret, body)
    resp = c.post(
        "/webhook",
        content=body,
        headers={
            "X-GitHub-Event": "pull_request",
            "X-Hub-Signature-256": sig,
            "Content-Type": "application/json",
        },
    )
    assert resp.status_code == 202
    assert "ignored" in resp.json()["status"]


def test_webhook_ignores_draft_pr(client):
    c, settings = client
    payload = _pr_payload(action="opened", draft=True)
    body = json.dumps(payload).encode()
    sig = _sign(settings.github_webhook_secret, body)
    resp = c.post(
        "/webhook",
        content=body,
        headers={
            "X-GitHub-Event": "pull_request",
            "X-Hub-Signature-256": sig,
            "Content-Type": "application/json",
        },
    )
    assert resp.status_code == 202
    assert "ignored" in resp.json()["status"]


def test_webhook_rejects_missing_installation_id(client):
    c, settings = client
    payload = _pr_payload()
    payload["installation"] = {}
    body = json.dumps(payload).encode()
    sig = _sign(settings.github_webhook_secret, body)
    resp = c.post(
        "/webhook",
        content=body,
        headers={
            "X-GitHub-Event": "pull_request",
            "X-Hub-Signature-256": sig,
            "Content-Type": "application/json",
        },
    )
    assert resp.status_code == 400


def test_webhook_schedules_review_for_valid_pr(client):
    """Valid opened PR event should return 202 'scheduled'."""
    c, settings = client
    payload = _pr_payload(action="opened")
    body = json.dumps(payload).encode()
    sig = _sign(settings.github_webhook_secret, body)
    resp = c.post(
        "/webhook",
        content=body,
        headers={
            "X-GitHub-Event": "pull_request",
            "X-Hub-Signature-256": sig,
            "Content-Type": "application/json",
        },
    )
    assert resp.status_code == 202
    assert resp.json()["status"] == "scheduled"


@pytest.mark.parametrize("action", ["opened", "synchronize", "reopened", "ready_for_review"])
def test_webhook_accepts_all_valid_actions(client, action):
    c, settings = client
    payload = _pr_payload(action=action)
    body = json.dumps(payload).encode()
    sig = _sign(settings.github_webhook_secret, body)
    resp = c.post(
        "/webhook",
        content=body,
        headers={
            "X-GitHub-Event": "pull_request",
            "X-Hub-Signature-256": sig,
            "Content-Type": "application/json",
        },
    )
    assert resp.status_code == 202
    assert resp.json()["status"] == "scheduled"
