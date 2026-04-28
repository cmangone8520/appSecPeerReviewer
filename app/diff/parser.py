"""Unified-diff parser.

Converts the raw ``text/x-diff`` body returned by the GitHub API into a list
of :class:`~app.diff.models.FileDiff` objects that map each file to the set of
post-change line numbers introduced by the PR.

The GitHub Reviews API accepts inline comments addressed by ``line`` +
``side="RIGHT"`` (post-change line numbers), so we only need to track ``+``
line numbers — context lines and ``-`` lines are silently skipped.
"""

from __future__ import annotations

import logging
import re

from .models import FileDiff

log = logging.getLogger("appsec_reviewer")

# Matches a hunk header, e.g.:  @@ -3,7 +5,12 @@
# Group 1 → start line in the new file.
_HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")


def parse_diff(text: str) -> list[FileDiff]:
    """Parse a unified diff string into per-file :class:`FileDiff` objects.

    Parameters
    ----------
    text:
        The full unified diff as returned by the GitHub Pulls API with the
        ``application/vnd.github.v3.diff`` accept header.

    Returns
    -------
    list[FileDiff]
        One entry per file touched by the diff, in order of appearance.
    """
    log.info("diff parser start diff_bytes=%d", len(text.encode()))

    files: list[FileDiff] = []
    current: FileDiff | None = None
    new_line_no: int | None = None

    for line in text.splitlines():
        if line.startswith("diff --git "):
            if current is not None:
                files.append(current)
            current = FileDiff(path="")
            current.raw = line + "\n"
            new_line_no = None
            continue

        if current is None:
            continue
        current.raw += line + "\n"

        if line.startswith("+++ "):
            target = line[4:].strip()
            if target == "/dev/null":
                continue  # file deletion — no path on +++ side
            current.path = target[2:] if target.startswith("b/") else target
            continue

        if line.startswith("Binary files "):
            current.is_binary = True
            continue

        if line.startswith("@@"):
            m = _HUNK_RE.match(line)
            if m:
                new_line_no = int(m.group(1))
            continue

        if new_line_no is None:
            continue

        if line.startswith("+") and not line.startswith("+++"):
            current.added_lines.add(new_line_no)
            new_line_no += 1
        elif line.startswith("-") and not line.startswith("---"):
            current.removed_count += 1
        else:
            new_line_no += 1

    if current is not None:
        files.append(current)

    added_total = sum(len(f.added_lines) for f in files)
    removed_total = sum(f.removed_count for f in files)
    binary_files = sum(1 for f in files if f.is_binary)
    log.info(
        "diff parser complete files=%d binary=%d added_lines=%d removed_lines=%d",
        len(files),
        binary_files,
        added_total,
        removed_total,
    )
    return files


def is_added_line(files: list[FileDiff], path: str, line: int) -> bool:
    """Return ``True`` iff ``line`` is a ``+`` line in ``path``'s diff.

    Used to validate LLM-reported line numbers before posting them as GitHub
    inline comments (GitHub rejects comments on non-diff lines).
    """
    for f in files:
        if f.path == path:
            return line in f.added_lines
    return False

