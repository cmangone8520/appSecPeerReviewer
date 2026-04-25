from app.models import Finding
from app.review.pipeline import _dedupe, summary_body


def _f(file: str, line: int, sev: str, cls: str, src: str = "llm") -> Finding:
    return Finding(
        file=file,
        line=line,
        severity=sev,  # type: ignore[arg-type]
        vulnerability_class=cls,
        title=f"{cls} at {file}:{line}",
        explanation="x",
        recommendation="y",
        source=src,  # type: ignore[arg-type]
    )


def test_dedupe_keeps_highest_severity_per_key():
    findings = [
        _f("a.py", 5, "low", "sql-injection", "llm"),
        _f("a.py", 5, "high", "sql-injection", "llm"),
        _f("a.py", 5, "medium", "sql-injection", "llm"),
        _f("b.py", 1, "critical", "hardcoded-secret", "secret-scan"),
    ]
    out = _dedupe(findings)
    assert len(out) == 2
    by_file = {f.file: f for f in out}
    assert by_file["a.py"].severity == "high"
    assert by_file["b.py"].severity == "critical"
    # Sorted by severity desc.
    assert out[0].severity == "critical"


def test_summary_body_handles_empty_and_nonempty():
    empty = summary_body([])
    assert "No security findings" in empty

    findings = [
        _f("a.py", 1, "high", "sql-injection"),
        _f("b.py", 1, "low", "info-disclosure"),
        _f("c.py", 1, "high", "ssrf"),
    ]
    body = summary_body(findings)
    assert "Found 3 potential security issue(s)" in body
    assert "high" in body and "low" in body
