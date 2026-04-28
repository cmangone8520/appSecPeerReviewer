"""Data model for a parsed file diff."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class FileDiff:
    """Represents the diff for a single file in a pull request.

    Attributes
    ----------
    path:
        The file path on the new (right) side of the diff.
    added_lines:
        Set of line numbers (1-based, post-change) that have a ``+`` prefix.
    removed_count:
        Number of ``-`` lines removed in this file.
    is_binary:
        True when the diff reports "Binary files … differ".
    raw:
        The raw diff text for this file, used by secret and dep scanners.
    """

    path: str
    added_lines: set[int] = field(default_factory=set)
    removed_count: int = 0
    is_binary: bool = False
    raw: str = ""

