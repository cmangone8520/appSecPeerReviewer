"""Minimal unified-diff parser.

The GitHub Reviews API can take inline comments addressed by either
`position` (offset within a diff hunk) or `line` + `side`. We use
`line` + `side="RIGHT"` (the new file's line numbers) so the LLM only
needs to think in terms of the post-change line numbers it actually
sees in the `+` lines of the diff.

This module exposes:
  - parse_diff(text)        -> list of FileDiff
  - is_added_line(diff, file, line) for cheap validation of LLM output
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

_HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")


@dataclass
class FileDiff:
    path: str
    added_lines: set[int] = field(default_factory=set)
    removed_count: int = 0
    is_binary: bool = False
    raw: str = ""


def parse_diff(text: str) -> list[FileDiff]:
    """Parse a unified diff into per-file added-line sets."""
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
                # File deletion — no path on the +++ side.
                continue
            # Strip the conventional "b/" prefix.
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
    return files


def is_added_line(files: list[FileDiff], path: str, line: int) -> bool:
    """True iff `line` is a `+` line in `path`'s diff (i.e. safe to comment on)."""
    for f in files:
        if f.path == path:
            return line in f.added_lines
    return False
