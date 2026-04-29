"""Diff domain package.

Public surface::

    from app.diff import FileDiff, parse_diff, is_added_line
"""

from .models import FileDiff
from .parser import is_added_line, parse_diff

__all__ = ["FileDiff", "is_added_line", "parse_diff"]

