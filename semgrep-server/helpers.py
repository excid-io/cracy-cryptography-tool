import logging
import os
import urllib.parse
from typing import Any

from run_command import run_command
from semgrep_types import RawSemgrepFinding, RawSemgrepOutput, SemgrepSummary


logger = logging.getLogger(__name__)

SEMGREP_TIMEOUT_SECONDS = int(os.environ.get("SEMGREP_TIMEOUT_SECONDS", "600"))


def redact_token(text: str, pat: str | None) -> str:
    """Avoid returning PATs to the browser in error messages."""
    if not pat:
        return text

    return text.replace(pat, "***REDACTED***")


def normalize_repo_url(git_url: str) -> str:
    """
    Normalize the repository URL into a form that `git clone` can use.

    CBOMkit scan inputs/results and UI scan inputs may refer to repositories in
    slightly different formats. For Semgrep, we need a cloneable Git URL because
    the runner checks out the requested repository before scanning it.

    Supported input:
      - https://github.com/org/repo
      - https://github.com/org/repo.git

    Rejected input:
      - pkg:github/org/repo@commit

    A package URL identifies a software package/version, but it is not directly
    cloneable by Git. If CBOMkit returns only a package URL, the caller should
    pass the separate `gitUrl` field from the CBOMkit record instead.

    For GitHub HTTPS URLs, append `.git` when it is missing so the URL is in the
    conventional clone format:
      https://github.com/org/repo -> https://github.com/org/repo.git
    """
    git_url = git_url.strip()

    if git_url.startswith("pkg:"):
        raise ValueError("Semgrep runner needs a cloneable Git URL, not a package URL.")

    if "github.com" in git_url and not git_url.endswith(".git"):
        git_url = f"{git_url}.git"

    return git_url


def make_auth_url(git_url: str, pat: str | None) -> str:
    """
    Add a GitHub PAT to an HTTPS clone URL when a token is provided.

    This is needed for private GitHub repositories or public repositories where
    unauthenticated cloning may hit rate limits.

    Supported behavior:
      - If no PAT is provided, return the original URL unchanged.
      - If the URL is not HTTP/HTTPS, return it unchanged.
      - If the URL is not a GitHub URL, return it unchanged.
      - If the URL is a GitHub HTTPS URL, embed the PAT using GitHub's
        token-auth clone format:
          https://x-access-token:<TOKEN>@github.com/org/repo.git

    Security notes:
      - The PAT is only used inside the Semgrep runner container for `git clone`.
      - The token must never be returned to the browser, logs, or error output.
      - Callers should pass the PAT to `run_command(..., secrets=[pat])` so any
        command failures are redacted before being returned.
      - This function URL-encodes the token so special characters in the PAT do
        not break the URL structure.
    """
    # Public repositories and unauthenticated scans do not need URL rewriting.
    if not pat:
        return git_url

    parsed = urllib.parse.urlparse(git_url)

    # Only rewrite HTTP(S) URLs. SSH URLs, local paths, or other schemes are left
    # untouched because embedding a PAT in them would be invalid.
    if parsed.scheme not in ("http", "https"):
        return git_url

    # Only add GitHub PATs to GitHub hosts. This avoids accidentally sending a
    # GitHub token to another domain.
    if "github.com" not in parsed.netloc:
        return git_url

    # Quote the token before putting it into the URL userinfo section. This
    # prevents characters like ":" or "@" from being interpreted as URL syntax.
    safe_pat = urllib.parse.quote(pat, safe="")

    # GitHub supports the x-access-token username convention for token-based
    # HTTPS cloning.
    netloc = f"x-access-token:{safe_pat}@{parsed.netloc}"

    return urllib.parse.urlunparse(
        (
            parsed.scheme,
            netloc,
            parsed.path,
            parsed.params,
            parsed.query,
            parsed.fragment,
        )
    )


def safe_subfolder_path(repo_dir: str, subfolder: str | None) -> str:
    """
    Resolve the requested scan target and ensure it stays inside the cloned repo.

    The React app may send an optional `subfolder` so Semgrep scans the same
    requested subdirectory. Because that value is user-controlled, it must not be
    trusted as a raw filesystem path.

    Security goals:
      - Allow "" or None to mean "scan the whole repository".
      - Allow normal relative paths such as "frontend" or "src/main".
      - Reject path traversal such as "../../etc".
      - Reject absolute paths that point outside the cloned repository.
      - Return a canonical real path that can safely be passed to Semgrep.
    """
    # Canonicalize the repository path. realpath resolves symlinks and removes
    # path segments like "." and "..", giving us a stable directory boundary.
    repo_dir = os.path.realpath(repo_dir)

    # Join the user-provided subfolder to the repository root, then canonicalize
    # it as well. This turns values like "src/../frontend" into their real target.
    scan_target = os.path.realpath(os.path.join(repo_dir, subfolder or ""))

    # Ensure the resolved target is either the repository itself or a path inside
    # the repository. This prevents traversal like "../../etc" and absolute paths
    # like "/tmp/other-repo" from being scanned.
    if not scan_target.startswith(repo_dir + os.sep) and scan_target != repo_dir:
        raise ValueError("Invalid subfolder path.")

    # Make failure explicit if the requested subfolder does not exist at the
    # checked-out commit or branch. This is safer than letting Semgrep scan an
    # unintended fallback path.
    if not os.path.exists(scan_target):
        raise ValueError(f"Subfolder does not exist: {subfolder}")

    return scan_target

def find_semgrep_configs(configs_dir: str) -> list[str]:
    """
    Find all Semgrep YAML config files under the mounted config root.

    The repository stores multiple Semgrep rule packs under nested directories,
    for example:
      /configs/symmetric-atomic-primitives/symmetric-atomic-primitives.yaml
      /configs/symmetric-constructions/symmetric-constructions.yaml
      /configs/cryptographic-protocols/standard_ssl.yaml

    Passing each YAML file explicitly avoids relying on Semgrep's directory
    discovery behavior.
    """
    configs = []

    for root, _dirs, files in os.walk(configs_dir):
        for filename in files:
            if filename.endswith((".yaml", ".yml")):
                configs.append(os.path.join(root, filename))

    configs.sort()

    if not configs:
        raise ValueError(f"No Semgrep YAML config files found under {configs_dir}")

    logger.info("Discovered %s Semgrep config files: %s", len(configs), configs)

    return configs

def checkout_repo(
    git_url: str,
    branch: str | None,
    commit: str | None,
    pat: str | None,
    destination: str,
) -> None:
    """
    Clone the requested repository and check out the requested revision.

    Inputs may come directly from the React UI:
      - gitUrl
      - branch
      - optional commit
      - optional PAT

    If a commit is provided, the runner checks out that exact commit. This is
    useful when the caller wants Semgrep to match a CBOMkit-generated revision.

    If no commit is provided, the runner checks out HEAD for the requested
    branch/default branch. This allows Semgrep to run directly from UI arguments
    without waiting for CBOMkit metadata.

    Security notes:
      - The clone URL may contain a PAT for private repositories.
      - Any command execution must pass `secrets=[pat]` so command errors redact
        the token before returning output to the browser.
      - `run_command` performs command allowlisting, uses `shell=False`, and
        rejects unsupported Git subcommands/flags.
    """
    # Normalize the repo URL into a cloneable Git URL and inject the PAT only
    # when needed. For public repos, this remains the original unauthenticated URL.
    clone_url = make_auth_url(normalize_repo_url(git_url), pat)

    # Clone without immediately checking out files. This lets us explicitly
    # checkout the requested commit when one is provided after the clone completes.
    clone_args = ["git", "clone", "--no-checkout"]

    # If the UI or CBOMkit reported a branch, clone that branch to reduce the
    # amount of history Git has to inspect and to improve the chance that the
    # target commit is already available locally.
    if branch:
        clone_args.extend(["--branch", branch])

    # Destination is a temporary directory controlled by the server, not by the
    # client. The clone URL may contain a PAT, so it must be redacted on errors.
    clone_args.extend([clone_url, destination])

    logger.info(
        "Cloning repository for Semgrep scan: gitUrl=%s branch=%s commit=%s destination=%s",
        git_url,
        branch or "",
        commit or "",
        destination,
    )

    try:
        run_command(
            clone_args,
            timeout=SEMGREP_TIMEOUT_SECONDS,
            secrets=[pat],
        )

        if commit:
            try:
                # First try a direct checkout. This works when the commit exists
                # in the cloned branch/history.
                run_command(
                    ["git", "checkout", commit],
                    cwd=destination,
                    timeout=SEMGREP_TIMEOUT_SECONDS,
                    secrets=[pat],
                )
            except Exception:
                logger.info(
                    "Commit was not available after clone; fetching commit directly: %s",
                    commit,
                )

                # Some commits may not be present in the initial clone. Fetch
                # only the requested commit with depth 1 instead of fetching the
                # full repository history.
                run_command(
                    ["git", "fetch", "--depth", "1", "origin", commit],
                    cwd=destination,
                    timeout=SEMGREP_TIMEOUT_SECONDS,
                    secrets=[pat],
                )

                # After fetching the missing commit, check it out explicitly so
                # Semgrep scans the exact requested revision.
                run_command(
                    ["git", "checkout", commit],
                    cwd=destination,
                    timeout=SEMGREP_TIMEOUT_SECONDS,
                    secrets=[pat],
                )
        else:
            # If no commit was provided, fall back to the cloned HEAD. This is
            # less precise than a commit checkout, but still allows Semgrep to
            # scan the requested repository/branch.
            run_command(
                ["git", "checkout", "HEAD"],
                cwd=destination,
                timeout=SEMGREP_TIMEOUT_SECONDS,
                secrets=[pat],
            )

    except Exception as error:
        # Redact the PAT one final time before surfacing the failure to the HTTP
        # handler. This is defense-in-depth in case an error message includes the
        # authenticated clone URL.
        logger.exception("Repository checkout failed for gitUrl=%s", git_url)
        raise RuntimeError(redact_token(str(error), pat)) from error


def normalize_severity(value: Any) -> str:
    if not value:
        return ""

    return str(value).strip().lower()


def extract_algorithm_name(item: RawSemgrepFinding) -> str:
    """
    Prefer explicit Semgrep metadata fields for algorithm name.

    Your rules can set any of these in YAML metadata:
      metadata:
        algorithm: AES
        severity: ERROR
    """
    extra = item.get("extra", {}) or {}
    metadata = extra.get("metadata", {}) or {}

    return (
        metadata.get("algorithm")
        or metadata.get("algorithm_name")
        or metadata.get("primitive")
        or metadata.get("name")
        or item.get("check_id")
        or "Unknown algorithm"
    )


def summarize_semgrep(raw: RawSemgrepOutput) -> SemgrepSummary:
    """
    Convert raw Semgrep JSON into a smaller, UI-friendly result shape.

    Semgrep's native JSON output contains a lot of data. The React UI only needs
    a few fields for display and filtering:
      - rule ID
      - algorithm name
      - message
      - severity
      - file path
      - line/column
      - metadata

    The full raw Semgrep output is still included under `raw` so it can be
    downloaded or inspected later without rerunning the scan.
    """
    # Semgrep places individual rule matches in the top-level "results" array.
    # If the key is missing, treat it as no findings instead of failing.
    results = raw.get("results", [])

    findings = []

    for item in results:
        # "extra" contains Semgrep's human-facing message, severity, and rule
        # metadata.
        extra = item.get("extra", {}) or {}

        # Custom YAML metadata lives here. Your rules can include fields such as:
        # metadata:
        #   algorithm: AES
        #   category: symmetric-atomic-primitives
        metadata = extra.get("metadata", {}) or {}

        # The "start" object gives the source location where the match begins.
        start = item.get("start", {}) or {}

        # Prefer Semgrep's native severity value because the rules are written
        # using Semgrep's severity model. Semgrep commonly returns values such as
        # INFO, WARNING, and ERROR in extra.severity.
        #
        # Metadata fields are only fallbacks in case a rule/output variant does
        # not include extra.severity.
        severity = normalize_severity(
            extra.get("severity")
            or metadata.get("severity")
            or metadata.get("impact")
        )

        findings.append(
            {
                # Semgrep rule identifier, usually the YAML rule id.
                "ruleId": item.get("check_id", ""),

                # Human-friendly crypto primitive/algorithm name. This is pulled
                # from custom metadata when available, with rule ID as fallback.
                "algorithm": extract_algorithm_name(item),

                # Message shown in the UI for the finding.
                "message": extra.get("message", ""),

                # Normalized lowercase Semgrep severity, for example "error",
                # "warning", or "info".
                "severity": severity,

                # File and location of the match inside the checked-out repo.
                "path": item.get("path", ""),
                "line": start.get("line"),
                "column": start.get("col"),

                # Preserve metadata so the frontend can add more display fields
                # later without changing the runner response format.
                "metadata": metadata,
            }
        )

    logger.info("Normalized Semgrep results: count=%s", len(findings))

    return {
        "count": len(findings),
        "findings": findings,
        "raw": raw,
    }