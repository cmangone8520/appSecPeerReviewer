from app.diff import parse_diff
from app.review.reviewers.secrets import scan

DIFF_WITH_SECRETS = """diff --git a/config.py b/config.py
index 1..2 100644
--- a/config.py
+++ b/config.py
@@ -1,2 +1,4 @@
 X = 1
+AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
+GITHUB_TOKEN = "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
 Y = 2
"""

DIFF_WITHOUT_SECRETS = """diff --git a/util.py b/util.py
index 1..2 100644
--- a/util.py
+++ b/util.py
@@ -1,1 +1,2 @@
 import os
+x = "AKIA-not-a-real-key"
"""


def test_secret_scan_flags_known_patterns():
    findings = scan(parse_diff(DIFF_WITH_SECRETS))
    classes = {f.vulnerability_class for f in findings}
    titles = {f.title for f in findings}
    assert classes == {"hardcoded-secret"}
    assert any("aws-access-key-id" in t for t in titles)
    assert any("github-pat" in t for t in titles)
    # Both findings must be on `+` lines, not pre-existing context lines.
    assert {f.line for f in findings} == {2, 3}


def test_secret_scan_does_not_flag_obvious_non_secrets():
    findings = scan(parse_diff(DIFF_WITHOUT_SECRETS))
    assert findings == []
