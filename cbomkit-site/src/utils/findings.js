/**
 * Severities that should be shown in the UI.
 *
 * The REGO response can contain findings of many severities, but the UI only
 * displays findings whose normalized severity is included in this set.
 */
export const IMPORTANT_SEVERITIES = new Set(["high", "critical", "medium", "error"]);

/**
 * Returns the first non-empty string value found for a list of possible keys.
 *
 * This is useful because REGO and Semgrep findings may use slightly different
 * field names for the same concept, such as `ruleId`, `rule_id`, or `id`.
 * If no usable string is found, it returns an empty string.
 */
export function getStringValue(object, keys) {
  for (const key of keys) {
    const value = object?.[key];

    if (typeof value === "string" && value.trim()) {
      return value.trim();
    }
  }

  return "";
}

/**
 * Converts a severity value into a consistent lowercase format.
 *
 * Non-string values are treated as missing and return an empty string.
 */
export function normalizeSeverity(value) {
  if (typeof value !== "string") return "";
  return value.trim().toLowerCase();
}

/**
 * Converts a confidence value into a consistent display format.
 *
 * This handles common variations such as `very-high`, `very_high`, and
 * `very high`, and normalizes them to `very high`.
 */
export function normalizeConfidence(value) {
  if (typeof value !== "string") return "";

  const normalized = value.trim().toLowerCase();

  if (["very-high", "very_high", "very high"].includes(normalized)) {
    return "very high";
  }

  if (["high", "medium", "low", "unknown"].includes(normalized)) {
    return normalized;
  }

  return normalized || "unknown";
}

/**
 * Extracts the actual OPA decision payload from an OPA API response.
 *
 * OPA usually wraps decisions under a `result` key. This helper supports both
 * wrapped responses and already-unwrapped objects, making the rest of the code
 * simpler.
 */
export function extractOpaResult(policyResult) {
  if (!policyResult) return null;

  if (Object.prototype.hasOwnProperty.call(policyResult, "result")) {
    return policyResult.result;
  }

  return policyResult;
}

/**
 * Converts an identifier-like string into a readable label.
 *
 * For example:
 * - `hash_primitives` becomes `Hash Primitives`
 * - `rsa-integer-factorization` becomes `Rsa Integer Factorization`
 */
export function humanizeKey(value) {
  if (!value) return "";

  return String(value)
    .replace(/_/g, " ")
    .replace(/-/g, " ")
    .replace(/\b\w/g, (letter) => letter.toUpperCase());
}

/**
 * Builds a display label from a traversal path in the OPA response.
 *
 * Internal path parts such as `findings` and numeric array indexes are removed,
 * then the remaining parts are humanized and joined with `/`.
 */
export function makePathLabel(path) {
  return path
    .filter((part) => part !== "findings" && !/^\d+$/.test(part))
    .map(humanizeKey)
    .join(" / ");
}

/**
 * Chooses the best title for a REGO finding.
 *
 * The function checks several possible fields in priority order. This makes the
 * UI resilient to findings produced by different policy packages with slightly
 * different field names. If no title-like field exists, it falls back to the
 * policy path or the generic label `Finding`.
 */
export function getRegoFindingTitle(finding, path) {
  return (
    getStringValue(finding, [
      "component",
      "algorithm",
      "scheme",
      "primitive",
      "ruleId",
      "rule_id",
      "status",
      "title",
      "name",
      "id",
    ]) ||
    makePathLabel(path) ||
    "Finding"
  );
}

/**
 * Determines which UI group a REGO finding belongs to.
 *
 * Newer top-level REGO results should include `policyPath`, `section`, and
 * `subsection`. If those fields are missing, this falls back to deriving a
 * label from the OPA traversal path.
 */
export function getRegoSection(finding, path) {
  const policyPath = getStringValue(finding, ["policyPath", "policy_path"]);

  if (policyPath) return policyPath;

  const section = getStringValue(finding, ["section"]);
  const subsection = getStringValue(finding, ["subsection"]);

  if (section && subsection) return `${section} / ${subsection}`;
  if (section) return section;

  return makePathLabel(path) || "REGO Findings";
}

/**
 * Chooses the best human-readable description for a REGO finding.
 *
 * Policy findings may use `message`, `description`, `reason`, or similar fields.
 * This helper checks those common options and falls back to a default message
 * when none is present.
 */
export function getRegoFindingInfo(finding) {
  return (
    getStringValue(finding, [
      "message",
      "info",
      "msg",
      "description",
      "details",
      "reason",
      "note",
    ]) || "No info message provided."
  );
}

/**
 * Extracts, filters, normalizes, and de-duplicates REGO findings for display.
 *
 * Expected OPA response shape:
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
 * The function normalizes each REGO finding into the UI shape:
 *
 * {
 *   title: string,
 *   message: string,
 *   severity: string,
 *   ruleId: string,
 *   section: string,
 *   references: array,
 *   raw: object
 * }
 *
 * The function:
 * 1. Unwraps the OPA response using `extractOpaResult`.
 * 2. Reads only the top-level `result.findings` array.
 * 3. Keeps only findings whose severity is in `IMPORTANT_SEVERITIES`.
 * 4. Normalizes each finding into the shape expected by the UI.
 * 5. Removes duplicate findings based on severity, rule ID, title, and message.
 */
export function extractImportantFindings(policyResult) {
  const root = extractOpaResult(policyResult);

  if (!root) return [];

  const sourceFindings = Array.isArray(root.findings) ? root.findings : [];
  const findings = [];

  for (const finding of sourceFindings) {
    if (!finding || typeof finding !== "object") continue;

    const severity = normalizeSeverity(
        finding.severity ||
        finding.level ||
        finding.risk ||
        finding.impact ||
        finding.priority
    );

    if (!IMPORTANT_SEVERITIES.has(severity)) continue;

    findings.push({
      title: getRegoFindingTitle(finding, []),
      message: getRegoFindingInfo(finding),
      severity,
      ruleId: getStringValue(finding, ["ruleId", "rule_id", "id"]),
      section: getRegoSection(finding, []),
      references: Array.isArray(finding.references) ? finding.references : [],
      raw: finding,
    });
  }

  const seen = new Set();

  return findings.filter((finding) => {
    const key = `${finding.severity}|${finding.ruleId}|${finding.title}|${finding.message}`;

    if (seen.has(key)) return false;

    seen.add(key);
    return true;
  });
}

/**
 * Extracts the numeric suffix from a rule ID for rule-order sorting.
 *
 * For example:
 * - `ECCG-HASH-001` returns `1`
 * - `ECCG-HASH-005` returns `5`
 *
 * Rules without a numeric suffix are sorted last.
 */
export function getRuleOrder(ruleId) {
  const match = String(ruleId || "").match(/-(\d+)$/);

  if (!match) return Number.MAX_SAFE_INTEGER;

  return Number(match[1]);
}

/**
 * Compares two findings by their numeric rule order.
 *
 * This keeps findings in policy order, such as `001`, `002`, `003`, instead of
 * sorting alphabetically or by severity. If two rule IDs have the same numeric
 * suffix, the full rule ID is used as a stable tie-breaker.
 */
export function compareByRuleOrder(a, b) {
  const aOrder = getRuleOrder(a.ruleId);
  const bOrder = getRuleOrder(b.ruleId);

  if (aOrder !== bOrder) return aOrder - bOrder;

  return String(a.ruleId || "").localeCompare(String(b.ruleId || ""));
}

/**
 * Groups normalized REGO findings by policy section for display.
 *
 * Expected input shape:
 *
 * [
 *   {
 *     title: "SHA224",
 *     message: "Hash function 'SHA224' is legacy-only...",
 *     severity: "critical",
 *     ruleId: "ECCG-HASH-001",
 *     section: "Symmetric Atomic Primitives / Hash Primitives",
 *     references: [
 *       {
 *         location: "demo/code/symmetric_atomic_primitives_hashes.py",
 *         line: 13,
 *         offset: 10,
 *         additionalContext: "HMAC"
 *       }
 *     ],
 *     raw: { ...originalRegoFinding }
 *   }
 * ]
 *
 * Output shape:
 *
 * [
 *   {
 *     title: "Symmetric Atomic Primitives / Hash Primitives",
 *     ruleId: "",
 *     severity: "",
 *     message: "",
 *     findings: [
 *       {
 *         title: "SHA224",
 *         message: "Hash function 'SHA224' is legacy-only...",
 *         severity: "critical",
 *         confidence: "",
 *         ruleId: "ECCG-HASH-001",
 *         location: "",
 *         references: [ ... ],
 *         raw: { ...originalRegoFinding }
 *       }
 *     ]
 *   }
 * ]
 *
 * Each top-level group represents a UI section such as:
 * - `Symmetric Atomic Primitives / Hash Primitives`
 * - `Asymmetric Atomic Primitives / RSA Integer Factorization`
 *
 * Findings inside each group are sorted by rule order, then by title.
 * Groups are sorted alphabetically by group title.
 */
export function groupRegoFindings(findings) {
  const groups = new Map();

  for (const finding of findings) {
    const groupKey = finding.section || "REGO Findings";

    if (!groups.has(groupKey)) {
      groups.set(groupKey, {
        title: groupKey,
        ruleId: "",
        severity: "",
        message: "",
        findings: [],
      });
    }

    groups.get(groupKey).findings.push({
      title: finding.title,
      message: finding.message,
      severity: finding.severity || "unknown",
      confidence: "",
      ruleId: finding.ruleId,
      location: "",
      references: finding.references,
      raw: finding.raw,
    });
  }

  return Array.from(groups.values())
    .map((group) => ({
      ...group,
      findings: group.findings.sort((a, b) => {
        const ruleOrder = compareByRuleOrder(a, b);

        if (ruleOrder !== 0) return ruleOrder;

        return String(a.title || "").localeCompare(String(b.title || ""));
      }),
    }))
    .sort((a, b) => a.title.localeCompare(b.title));
}