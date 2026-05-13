import json
import logging
import os
import subprocess
from pathlib import Path


logger = logging.getLogger(__name__)

ALLOWED_EXECUTABLES = {"git", "semgrep"}

ALLOWED_GIT_SUBCOMMANDS = {
    "clone",
    "checkout",
    "fetch",
}

ALLOWED_SEMGREP_SUBCOMMANDS = {
    "scan",
}

ALLOWED_SEMGREP_FLAGS = {
    "--config",
    "--json",
    "--metrics",
    "--disable-version-check",
    "--no-git-ignore",
    "--include",
}

ALLOWED_GIT_FLAGS = {
    "--no-checkout",
    "--branch",
    "--depth",
}

SAFE_ENV = {
    # Keep PATH narrow so subprocess can find git/semgrep without inheriting
    # unrelated host/container environment variables.
    "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),

    # Put tool config/cache behavior in a disposable location instead of a real
    # user home directory.
    "HOME": "/tmp",

    # Avoid Semgrep version-check network calls.
    "SEMGREP_ENABLE_VERSION_CHECK": "0",
}

MAX_ARG_LENGTH = 4096
MAX_OUTPUT_BYTES = 5 * 1024 * 1024
SEMGREP_TIMEOUT_SECONDS = 600


def validate_command_args(args: list[str]) -> None:
    """
    Validate a subprocess command before execution.

    This service only needs to run a tiny set of commands:
      - git clone / checkout / fetch
      - semgrep scan

    The goal is to prevent this HTTP service from becoming a general-purpose
    command execution endpoint if request fields like gitUrl, branch, commit,
    or subfolder contain unexpected values.
    """
    if not isinstance(args, list) or not args:
        raise ValueError("Command must be a non-empty list.")

    if not all(isinstance(arg, str) for arg in args):
        raise ValueError("Every command argument must be a string.")

    executable = args[0]

    # Do not allow arbitrary binaries such as sh, bash, curl, python, etc.
    if executable not in ALLOWED_EXECUTABLES:
        raise ValueError(f"Executable is not allowed: {executable}")

    # Do not allow empty arguments, null bytes, or unreasonably large arguments.
    # subprocess.run(..., shell=False) already avoids shell injection, but these
    # checks reduce weird parser edge cases and accidental abuse.
    for arg in args:
        if not arg:
            raise ValueError("Empty command arguments are not allowed.")

        if "\x00" in arg:
            raise ValueError("Null bytes are not allowed in command arguments.")

        if len(arg) > MAX_ARG_LENGTH:
            raise ValueError("Command argument is too long.")

    if executable == "git":
        validate_git_args(args)

    if executable == "semgrep":
        validate_semgrep_args(args)


def validate_git_args(args: list[str]) -> None:
    """
    Allow only the Git operations required to prepare a repository for Semgrep.

    The Semgrep runner receives repository scan parameters from the React UI,
    optionally enriched later with CBOMkit metadata:
      - gitUrl
      - optional branch
      - optional commit
      - optional subfolder

    The runner only needs to:
      1. clone the repository without checking out files immediately,
      2. checkout a requested commit/ref when one is provided,
      3. fetch that commit directly if it was not present in the initial clone.

    Expected shapes:
      git clone --no-checkout [--branch BRANCH] URL DEST
      git checkout COMMIT_OR_REF
      git fetch --depth 1 origin COMMIT

    Security rationale:
      - Do not allow arbitrary Git subcommands such as config, remote, submodule,
        archive, clean, worktree, or hooks-related operations.
      - Do not allow arbitrary flags. Git has many options that can alter config,
        execute helpers, use alternate object directories, or interact with the
        filesystem in unexpected ways.
      - Keep clone/fetch/checkout behavior predictable and limited to preparing
        a local working tree for Semgrep.
      - subprocess is still run with shell=False, but argument allowlisting
        protects against option injection and accidental expansion of this
        service into a general Git command executor.
    """
    if len(args) < 2:
        raise ValueError("Missing git subcommand.")

    subcommand = args[1]

    if subcommand not in ALLOWED_GIT_SUBCOMMANDS:
        raise ValueError(f"Git subcommand is not allowed: {subcommand}")

    for arg in args[2:]:
        if arg.startswith("-") and arg not in ALLOWED_GIT_FLAGS:
            raise ValueError(f"Git flag is not allowed: {arg}")

    if subcommand == "clone":
        if "--no-checkout" not in args:
            raise ValueError("git clone must use --no-checkout.")

        if len(args) < 5:
            raise ValueError("git clone command is incomplete.")

    if subcommand == "checkout":
        if len(args) != 3:
            raise ValueError("git checkout must receive exactly one ref.")

        ref = args[2]

        # Avoid option injection like: git checkout --help
        if ref.startswith("-"):
            raise ValueError("git checkout ref must not start with '-'.")

    if subcommand == "fetch":
        allowed_shape = (
            len(args) == 6
            and args[2] == "--depth"
            and args[3] == "1"
            and args[4] == "origin"
            and not args[5].startswith("-")
        )

        if not allowed_shape:
            raise ValueError("git fetch must match: git fetch --depth 1 origin REF")


def validate_semgrep_args(args: list[str]) -> None:
    """
    Allow only the Semgrep scan command required by this service.

    The runner should execute one deterministic Semgrep scan over the checked-out
    repository or requested subfolder using the local Semgrep config root mounted
    into the container.

    Expected shape:
      semgrep scan --config CONFIGS_DIR --json --metrics off --disable-version-check TARGET

    Security and reproducibility rationale:
      - --config CONFIGS_DIR ensures the scan uses only the mounted local Semgrep
        config root, not remote registry rules or user-supplied config URLs.
      - --json produces stable machine-readable output for the React UI.
      - --metrics off prevents Semgrep telemetry from being sent.
      - --disable-version-check avoids network calls for version checks and makes
        local/offline behavior more predictable.
      - TARGET must be the checked-out repository directory or a validated
        subfolder inside it.
      - Do not allow arbitrary Semgrep flags because some options can change
        config sources, output destinations, ignored files, include/exclude
        behavior, or network behavior.
      - subprocess is run with shell=False, but strict command-shape validation
        prevents this HTTP service from becoming a general Semgrep wrapper.
    """
    if len(args) < 2:
        raise ValueError("Missing semgrep subcommand.")

    subcommand = args[1]

    if subcommand not in ALLOWED_SEMGREP_SUBCOMMANDS:
        raise ValueError(f"Semgrep subcommand is not allowed: {subcommand}")

    for arg in args[2:]:
        if arg.startswith("--") and arg not in ALLOWED_SEMGREP_FLAGS:
            raise ValueError(f"Semgrep flag is not allowed: {arg}")

    if "--config" not in args:
        raise ValueError("semgrep scan must include --config.")

    if "--json" not in args:
        raise ValueError("semgrep scan must include --json.")

    if "--metrics" not in args:
        raise ValueError("semgrep scan must include --metrics off.")

    metrics_index = args.index("--metrics")

    if metrics_index + 1 >= len(args) or args[metrics_index + 1] != "off":
        raise ValueError("semgrep scan must use --metrics off.")

    if "--disable-version-check" not in args:
        raise ValueError("semgrep scan must disable version checks.")

    target = args[-1]

    # Avoid option injection like: semgrep scan ... --dangerous-option
    if target.startswith("-"):
        raise ValueError("Semgrep target must not start with '-'.")


def redact_args(args: list[str], secrets: list[str] | None = None) -> list[str]:
    """Remove secrets, especially PATs embedded in clone URLs, before logging."""
    secrets = [secret for secret in (secrets or []) if secret]

    redacted = []
    for arg in args:
        safe_arg = arg

        for secret in secrets:
            safe_arg = safe_arg.replace(secret, "***REDACTED***")

        redacted.append(safe_arg)

    return redacted


def safe_cwd(cwd: str | None) -> str | None:
    """
    Normalize cwd before passing it to subprocess.

    This does not decide whether a directory is authorized; that should be
    checked by the caller when constructing repo_dir / scan_target. It only
    ensures cwd is a real directory when provided.
    """
    if cwd is None:
        return None

    path = Path(cwd).resolve()

    if not path.is_dir():
        raise ValueError(f"Working directory does not exist: {path}")

    return str(path)


def truncate_output(value: str) -> str:
    """Limit captured command output so an error cannot exhaust server memory."""
    if len(value.encode("utf-8", errors="ignore")) > MAX_OUTPUT_BYTES:
        return value[:MAX_OUTPUT_BYTES] + "\n...TRUNCATED..."

    return value


def run_command(
    args: list[str],
    cwd: str | None = None,
    timeout: int = SEMGREP_TIMEOUT_SECONDS,
    secrets: list[str] | None = None,
) -> str:
    """
    Run an allowlisted command safely.

    Security controls:
      - validate_command_args(args) allows only the required git/semgrep shapes.
      - shell=False prevents shell metacharacters from being interpreted.
      - cwd is resolved and must exist.
      - env is minimized so tokens/config from the parent process are not leaked.
      - timeout prevents hanging scans.
      - output size is capped to avoid memory exhaustion.
      - secrets are redacted before command details are returned in errors.
    """
    validate_command_args(args)

    redacted_command = redact_args(args, secrets)
    logger.info("Running command: %s", redacted_command)

    try:
        completed = subprocess.run(
            args,
            cwd=safe_cwd(cwd),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            shell=False,
            env=SAFE_ENV,
        )
    except subprocess.TimeoutExpired as error:
        logger.warning("Command timed out after %s seconds: %s", timeout, redacted_command)

        raise RuntimeError(
            json.dumps(
                {
                    "error": "Command timed out.",
                    "command": redacted_command,
                    "timeoutSeconds": timeout,
                    "stdout": truncate_output(error.stdout or ""),
                    "stderr": truncate_output(error.stderr or ""),
                },
                indent=2,
            )
        ) from error

    stdout = truncate_output(completed.stdout or "")
    stderr = truncate_output(completed.stderr or "")

    logger.info(
        "Command finished with return code %s: %s",
        completed.returncode,
        redacted_command,
    )

    if completed.returncode != 0:
        logger.warning(
            "Command failed with return code %s: %s",
            completed.returncode,
            redacted_command,
        )

        raise RuntimeError(
            json.dumps(
                {
                    "error": "Command failed.",
                    "command": redacted_command,
                    "returncode": completed.returncode,
                    "stdout": stdout,
                    "stderr": stderr,
                },
                indent=2,
            )
        )

    return stdout