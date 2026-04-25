from app.diff_parser import parse_diff
from app.review.deps import extract_added_deps

REQ_DIFF = """diff --git a/requirements.txt b/requirements.txt
index 1..2 100644
--- a/requirements.txt
+++ b/requirements.txt
@@ -1,1 +1,3 @@
 fastapi==0.115.0
+requests==2.19.0
+jinja2==2.10
"""

PYPROJ_DIFF = """diff --git a/pyproject.toml b/pyproject.toml
index 1..2 100644
--- a/pyproject.toml
+++ b/pyproject.toml
@@ -1,1 +1,2 @@
 [project]
+dependencies = ["pyyaml==5.3", "fastapi>=0.115"]
"""


def test_extract_added_deps_from_requirements():
    deps = extract_added_deps(parse_diff(REQ_DIFF))
    pinned = {(d.name, d.version, d.ecosystem) for d in deps}
    assert pinned == {("requests", "2.19.0", "PyPI"), ("jinja2", "2.10", "PyPI")}


def test_extract_added_deps_from_pyproject_only_takes_pinned():
    deps = extract_added_deps(parse_diff(PYPROJ_DIFF))
    # `fastapi>=0.115` is a range, not pinned via ==, so we skip it.
    assert {(d.name, d.version) for d in deps} == {("pyyaml", "5.3")}
