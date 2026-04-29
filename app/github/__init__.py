"""GitHub API integration package.

Public surface::

    from app.github import get_installation_token, get_pr_diff, post_review
"""

from .auth import InstallationToken, get_installation_token
from .client import get_pr_diff, post_review

__all__ = [
    "InstallationToken",
    "get_installation_token",
    "get_pr_diff",
    "post_review",
]

