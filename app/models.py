from typing import Literal

from pydantic import BaseModel, Field

Severity = Literal["info", "low", "medium", "high", "critical"]


class Finding(BaseModel):
    """A single application-security finding to surface as a PR comment."""

    file: str
    line: int = Field(ge=1, description="Line number in the file's RIGHT side of the diff.")
    severity: Severity
    vulnerability_class: str = Field(
        description=(
            "Short label, e.g. 'sql-injection', 'hardcoded-secret', "
            "'insecure-deserialization'."
        ),
    )
    title: str
    explanation: str = Field(description="Why this is a problem in this code, in plain English.")
    recommendation: str = Field(description="Concrete suggested fix.")
    source: Literal["llm", "secret-scan", "dependency-cve"] = "llm"


class ReviewResult(BaseModel):
    findings: list[Finding] = Field(default_factory=list)
