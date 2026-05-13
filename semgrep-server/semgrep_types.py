from typing import Any, TypedDict


class Credentials(TypedDict, total=False):
    """Optional credentials supplied by the React UI."""

    pat: str


class SemgrepScanRequest(TypedDict, total=False):
    """
    Request body accepted by POST /scan.

    Expected JSON shape:
      {
        "gitUrl": "https://github.com/org/repo",
        "branch": "main",
        "commit": "abc123",
        "subfolder": "src",
        "credentials": {
          "pat": "..."
        }
      }
    """

    gitUrl: str
    branch: str
    commit: str
    subfolder: str
    credentials: Credentials


class SemgrepLocation(TypedDict, total=False):
    """Source location object from a Semgrep finding."""

    line: int
    col: int


class SemgrepExtra(TypedDict, total=False):
    """Semgrep's extra finding data."""

    message: str
    severity: str
    metadata: dict[str, Any]


class RawSemgrepFinding(TypedDict, total=False):
    """Single finding object from raw Semgrep JSON."""

    check_id: str
    path: str
    start: SemgrepLocation
    extra: SemgrepExtra


class RawSemgrepOutput(TypedDict, total=False):
    """Raw Semgrep JSON output."""

    results: list[RawSemgrepFinding]
    errors: list[dict[str, Any]]
    paths: dict[str, Any]


class NormalizedSemgrepFinding(TypedDict):
    """Finding shape returned to the React UI."""

    ruleId: str
    algorithm: str
    message: str
    severity: str
    path: str
    line: int | None
    column: int | None
    metadata: dict[str, Any]


class SemgrepSummary(TypedDict):
    """Compact Semgrep result shape returned by the runner."""

    count: int
    findings: list[NormalizedSemgrepFinding]
    raw: RawSemgrepOutput


class SemgrepScanResponse(TypedDict):
    """Successful POST /scan response."""

    ok: bool
    gitUrl: str
    branch: str | None
    commit: str | None
    subfolder: str
    result: SemgrepSummary