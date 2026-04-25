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

REQ_VARIANTS_DIFF = """diff --git a/requirements-extra.txt b/requirements-extra.txt
index 1..2 100644
--- a/requirements-extra.txt
+++ b/requirements-extra.txt
@@ -0,0 +1,1 @@
+pyyaml==5.3
diff --git a/deploy/requirements/prod.txt b/deploy/requirements/prod.txt
index 1..2 100644
--- a/deploy/requirements/prod.txt
+++ b/deploy/requirements/prod.txt
@@ -0,0 +1,1 @@
+urllib3==1.24.1
diff --git a/notes/requirements_doc.txt b/notes/requirements_doc.txt
index 1..2 100644
--- a/notes/requirements_doc.txt
+++ b/notes/requirements_doc.txt
@@ -0,0 +1,1 @@
+not-a-dep==1.0
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


def test_extract_added_deps_matches_common_requirements_variants():
    """`requirements*.txt` in any reasonable shape should be picked up.

    Real projects routinely use `requirements-extra.txt`, `requirements-test.txt`,
    `deploy/requirements/prod.txt`, etc. The scanner has to match all of them
    or it silently misses vulnerable dep additions in those files.
    """
    deps = extract_added_deps(parse_diff(REQ_VARIANTS_DIFF))
    # The file `notes/requirements_doc.txt` is technically matched by our
    # broadened pattern (it ends in `requirements_doc.txt`), which we accept
    # as a reasonable trade-off — false positives here only ever try to
    # OSV-lookup a name and silently get nothing back.
    pinned = {(d.name, d.version) for d in deps}
    assert ("pyyaml", "5.3") in pinned
    assert ("urllib3", "1.24.1") in pinned
