"""TEST FIXTURE — DO NOT MERGE.

Intentionally vulnerable code used to verify the appSec Peer Reviewer
end-to-end. Each function below contains a different OWASP-class issue
the bot should flag.
"""

import sqlite3

# Hardcoded credentials. The bot's secret-scan should flag both of these
# as `hardcoded-secret` findings, and the LLM reviewer should also call
# them out as sensitive-data exposure.
GITHUB_TOKEN = "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"


def lookup_user(conn: sqlite3.Connection, username: str):
    """Returns the user row matching `username`.

    BUG: builds the SQL by string-formatting attacker-controlled input,
    so any single quote in `username` lets the caller append arbitrary
    SQL (classic SQLi).
    """
    cursor = conn.execute(f"SELECT * FROM users WHERE name = '{username}'")
    return cursor.fetchone()


def render_profile(template_str: str, user) -> str:
    """BUG: passes attacker-controlled string straight into eval -> RCE.

    The bot's LLM reviewer should catch this as a critical finding.
    """
    return eval(f"f'''{template_str}'''", {"user": user})  # noqa: S307


def open_redirect(next_url: str) -> str:
    """BUG: returns a redirect to whatever the caller passes, with no
    same-origin check. An attacker can phish users via /login?next=evil.com.
    """
    return f"Location: {next_url}"
