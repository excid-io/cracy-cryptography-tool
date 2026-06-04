import { getOpaEndpoint } from "../config/endpoints";

/**
 * Converts an OPA error response into a readable error message.
 *
 * Expected OPA error response shape:
 *
 * {
 *   errors: [
 *     {
 *       message: "rego_parse_error: ...",
 *       code: "rego_parse_error",
 *       location: {
 *         file: "policies/main.rego",
 *         row: 12,
 *         col: 5
 *       }
 *     }
 *   ]
 * }
 *
 * The function also handles simpler response shapes such as:
 *
 * {
 *   message: "some error message"
 * }
 *
 * or:
 *
 * {
 *   error: "some error message"
 * }
 *
 * If the response cannot be parsed as JSON, the raw response text is used.
 * This is mainly used to show useful details in the UI when REGO evaluation
 * fails.
*/
export function formatOpaErrors(body, responseText) {
  if (Array.isArray(body?.errors)) {
    return body.errors
      .map((error) => {
        const location = error.location
          ? `${error.location.file || "policy"}:${error.location.row || "?"}:${
              error.location.col || "?"
            }`
          : "";

        return [error.message, error.code, location].filter(Boolean).join(" | ");
      })
      .join("\n");
  }

  if (body?.message) return body.message;
  if (body?.error) return body.error;
  if (responseText) return responseText;

  return "";
}

/**
 * Sends a CBOM to the OPA policy endpoint for REGO evaluation.
 *
 * Expected input shape:
 *
 * {
 *   cbom: { ...CycloneDX CBOM object... },
 *   signal: AbortSignal
 * }
 *
 * OPA expects the CBOM to be wrapped under the `input` key:
 *
 * {
 *   input: cbom
 * }
 *
 * The endpoint is resolved through `getOpaEndpoint()`, which usually points to:
 *
 *   /v1/data/cbom/eccg
 *
 * Expected successful OPA response shape:
 *
 * {
 *   result: {
 *     compliant: false,
 *     findings: [
 *       {
 *         ruleId: "ECCG-HASH-001",
 *         severity: "critical",
 *         component: "SHA224",
 *         message: "Hash function 'SHA224' is legacy-only...",
 *         section: "Symmetric Atomic Primitives",
 *         subsection: "Hash Primitives",
 *         policyPath: "Symmetric Atomic Primitives / Hash Primitives",
 *         references: [...]
 *       }
 *     ]
 *   }
 * }
 *
 * If the request fails, this function formats the OPA error response and throws
 * an Error with both a short message and a `details` property that the UI can
 * display.
*/
export async function evaluatePolicy({ cbom, signal }) {
  if (!cbom) {
    const error = new Error("No CBOM is available to evaluate.");
    error.details = "Generate a CBOM first, then run REGO evaluation again.";
    throw error;
  }

  const response = await fetch(getOpaEndpoint(), {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      input: cbom,
    }),
    signal,
  });

  const responseText = await response.text();

  let body = null;

  try {
    body = responseText ? JSON.parse(responseText) : null;
  } catch {
    body = null;
  }

  console.log("OPA response status:", response.status);
  console.log("OPA response body:", body || responseText);

  if (!response.ok) {
    const details = formatOpaErrors(body, responseText);
    const error = new Error(
      details || `OPA policy evaluation failed with HTTP ${response.status}.`
    );

    error.details =
      details ||
      JSON.stringify(
        {
          status: response.status,
          statusText: response.statusText,
          endpoint: getOpaEndpoint(),
        },
        null,
        2
      );

    throw error;
  }

  return body;
}