from app.diff import is_added_line, parse_diff

DIFF = """diff --git a/app/main.py b/app/main.py
index 1111111..2222222 100644
--- a/app/main.py
+++ b/app/main.py
@@ -1,5 +1,7 @@
 import os
+import sqlite3
 
-def q(x):
-    return x
+def q(name):
+    conn = sqlite3.connect("db")
+    return conn.execute(f"SELECT * FROM users WHERE name = '{name}'")
diff --git a/README.md b/README.md
index aaa..bbb 100644
--- a/README.md
+++ b/README.md
@@ -10,0 +11,1 @@
+New line at 11.
"""


def test_parse_diff_collects_added_lines_per_file():
    files = parse_diff(DIFF)
    paths = {f.path for f in files}
    assert paths == {"app/main.py", "README.md"}

    main = next(f for f in files if f.path == "app/main.py")
    # Hunk starts at +1; new file has: 1 ctx, 2 add, 3 ctx, 4-6 add.
    assert main.added_lines == {2, 4, 5, 6}

    readme = next(f for f in files if f.path == "README.md")
    assert readme.added_lines == {11}


def test_is_added_line_helper():
    files = parse_diff(DIFF)
    assert is_added_line(files, "app/main.py", 2) is True
    assert is_added_line(files, "app/main.py", 1) is False
    assert is_added_line(files, "missing.py", 2) is False
