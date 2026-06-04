import { HTTP_API_BASE } from "../config/endpoints";
import { buildCbomScanRequest, recordMatchesScanUrl } from "../utils/urls";
import { sleep } from "../utils/sleep";

/**
 * Submits a new CBOM scan request to the CBOMkit backend.
 *
 * Expected input shape:
 *
 * {
 *   url: "https://github.com/org/repo",
 *   scanPath: "optional/subfolder",
 *   pat: "optional-personal-access-token",
 *   signal: AbortSignal
 * }
 *
 * The request body is built by `buildCbomScanRequest`, which normalizes the
 * repository URL and only includes optional fields when they are present.
 *
 * CBOMkit normally returns HTTP 202 when the scan is accepted. Some successful
 * responses may also be represented by `response.ok`, so this function accepts
 * either condition.
 *
 * Returns the normalized scan request so the polling step can use the exact
 * `scanUrl` value that was submitted.
*/
export async function submitCbomScan({ url, scanPath, pat, signal }) {
  const scanRequest = buildCbomScanRequest({ url, scanPath, pat });

  const response = await fetch(`${HTTP_API_BASE}/api/v1/scan`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(scanRequest),
    signal,
  });

  if (response.status !== 202 && !response.ok) {
    const body = await response.text().catch(() => "");
    throw new Error(
      body || `CBOM scan request failed with HTTP ${response.status}.`
    );
  }

  return scanRequest;
}

/**
 * Polls CBOMkit until the newly generated CBOM is available.
 *
 * Expected input shape:
 *
 * {
 *   scanUrl: "https://github.com/org/repo",
 *   scanStartedAt: 1710000000000,
 *   signal: AbortSignal,
 *   onStatus: function | undefined
 * }
 *
 * The function repeatedly requests the latest CBOM records from:
 *
 *   GET /api/v1/cbom/last/50
 *
 * It then filters records by:
 * 1. Matching repository URL using `recordMatchesScanUrl`.
 * 2. `createdAt >= scanStartedAt`, so old CBOMs for the same repo are ignored.
 *
 * Matching records are sorted newest-first, and the newest record with a `bom`
 * payload is returned.
 *
 * `onStatus` is optional and is used by the UI to display polling progress.
 * The polling loop can be cancelled through the provided `AbortSignal`.
*/
export async function pollForCbom({ scanUrl, scanStartedAt, signal, onStatus }) {
  const maxAttempts = 90;
  const delayMs = 2000;

  for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
    if (signal?.aborted) {
      throw new DOMException("The operation was aborted.", "AbortError");
    }

    const response = await fetch(`${HTTP_API_BASE}/api/v1/cbom/last/50`, {
      signal,
    });

    if (!response.ok) {
      throw new Error(`Could not retrieve CBOMs: HTTP ${response.status}.`);
    }

    const records = await response.json();

    const matches = records
      .filter((record) => {
        const createdAt = Number(record.createdAt || 0);

        return (
          recordMatchesScanUrl(record, scanUrl) && createdAt >= scanStartedAt
        );
      })
      .sort((a, b) => Number(b.createdAt || 0) - Number(a.createdAt || 0));

    const newestMatch = matches[0];

    if (newestMatch?.bom) {
      return newestMatch.bom;
    }

    onStatus?.(`Waiting for new CBOM... ${attempt}/${maxAttempts}`);

    await sleep(delayMs, signal);
  }

  throw new Error("Timed out waiting for a newly generated CBOM.");
}


/**
 * Runs the full CBOM generation flow.
 *
 * Expected input shape:
 *
 * {
 *   url: "https://github.com/org/repo",
 *   scanPath: "optional/subfolder",
 *   pat: "optional-personal-access-token",
 *   signal: AbortSignal,
 *   onStatus: function | undefined
 * }
 *
 * Flow:
 * 1. Notify the UI that the scan is being submitted.
 * 2. Submit the scan request to CBOMkit.
 * 3. Notify the UI that polling has started.
 * 4. Poll until the generated CBOM is available.
 * 5. Return the generated CBOM object.
 *
 * This function is the main API entry point used by the scanner hook/component.
*/
export async function generateCbom({ url, scanPath, pat, signal, onStatus }) {
  onStatus?.("Submitting CBOM scan...");

  const scanStartedAt = Date.now();
  const scanRequest = await submitCbomScan({ url, scanPath, pat, signal });

  onStatus?.("Scan accepted. Waiting for new CBOM...");

  return pollForCbom({
    scanUrl: scanRequest.scanUrl,
    scanStartedAt,
    signal,
    onStatus,
  });
}