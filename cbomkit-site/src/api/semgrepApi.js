import { getSemgrepEndpoint } from "../config/endpoints";
import { buildSemgrepScanRequest } from "../utils/urls";

/**
 * Runs a Semgrep scan through the local Semgrep service.
 *
 * Expected input shape:
 *
 * {
 *   url: "https://github.com/org/repo",
 *   branch: "optional-branch",
 *   commit: "optional-commit-sha",
 *   scanPath: "optional/subfolder",
 *   pat: "optional-personal-access-token",
 *   signal: AbortSignal
 * }
 *
 * The request body is built by `buildSemgrepScanRequest`, which normalizes the
 * Git URL and includes optional fields only when present.
 *
 * Expected successful response shape:
 *
 * {
 *   ok: true,
 *   result: {
 *     findings: [...]
 *   }
 * }
 *
 * If the Semgrep server returns `ok: false` or a non-2xx HTTP response, this
 * function throws an Error for the UI hook to catch and display.
 */
export async function runSemgrepScan({
  url,
  branch,
  commit,
  scanPath,
  pat,
  signal,
}) {
  const semgrepScanRequest = buildSemgrepScanRequest({
    url,
    branch,
    commit,
    scanPath,
    pat,
  });

  const response = await fetch(getSemgrepEndpoint(), {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(semgrepScanRequest),
    signal,
  });

  const body = await response.json().catch(() => null);

  console.log("Semgrep response from server:", body);

  if (!response.ok || body?.ok === false) {
    throw new Error(
      body?.error || `Semgrep scan failed with HTTP ${response.status}.`
    );
  }

  return body;
}