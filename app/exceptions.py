"""Typed exception hierarchy for appSec Peer Reviewer.

All application exceptions inherit from ``AppSecError`` so callers can catch
the entire hierarchy with a single clause when needed, or be precise about
individual failure modes.
"""

from __future__ import annotations


class AppSecError(Exception):
    """Base exception for all appSec Peer Reviewer errors."""


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


class ConfigurationError(AppSecError):
    """Raised when a required configuration value is missing or invalid."""


class PromptLoadError(ConfigurationError):
    """Raised when the LLM system-prompt file cannot be read."""


# ---------------------------------------------------------------------------
# Webhook / HTTP ingress
# ---------------------------------------------------------------------------


class WebhookError(AppSecError):
    """Base class for webhook-related errors."""


class SignatureVerificationError(WebhookError):
    """Raised when the HMAC-SHA256 webhook signature does not match."""


class MissingInstallationError(WebhookError):
    """Raised when the webhook payload has no installation.id field."""


# ---------------------------------------------------------------------------
# GitHub API
# ---------------------------------------------------------------------------


class GitHubError(AppSecError):
    """Base class for GitHub API errors."""


class AuthenticationError(GitHubError):
    """Raised when GitHub App JWT minting or token exchange fails."""


class DiffFetchError(GitHubError):
    """Raised when fetching the PR unified diff fails."""


class ReviewPostError(GitHubError):
    """Raised when posting the review to the GitHub Reviews API fails."""


# ---------------------------------------------------------------------------
# Review pipeline
# ---------------------------------------------------------------------------


class ReviewError(AppSecError):
    """Raised when the review pipeline encounters an unrecoverable error."""


class ReviewerError(ReviewError):
    """Raised by an individual reviewer plugin when it cannot complete."""

