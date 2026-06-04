import { styles } from "../styles/styles";

/**
 * Formats a source reference into a compact location string.
 *
 * Expected input shape:
 *
 * {
 *   location: "demo/code/file.py",
 *   path: "demo/code/file.py",
 *   line: 13,
 *   column: 2
 * }
 */
function formatReference(reference) {
  const location = reference.location || reference.path || "Unknown file";
  const line = reference.line ? `:${reference.line}` : "";
  const column = reference.column ? `:${reference.column}` : "";

  return `${location}${line}${column}`;
}

/**
 * Converts a normalized severity value into a compact UI label.
 */
function formatSeverity(severity) {
  if (typeof severity !== "string") return "";

  return severity.trim().toLowerCase();
}

/**
 * Returns the badge theme used for finding severity values.
 */
function getSeverityTheme(severity, theme) {
  const normalized = formatSeverity(severity);
  
  if (normalized === "error") {
    return {
      background: theme.dangerBg || theme.badgeBg,
      color: theme.dangerText || theme.badgeText,
      borderColor: theme.dangerBorder || theme.badgeBorder,
    };
  }

  if (normalized === "critical") {
    return {
      background: theme.dangerBg || theme.badgeBg,
      color: theme.dangerText || theme.badgeText,
      borderColor: theme.dangerBorder || theme.badgeBorder,
    };
  }

  if (normalized === "high") {
    return {
      background: theme.confidenceHighBg || theme.badgeBg,
      color: theme.confidenceHighText || theme.badgeText,
      borderColor: theme.confidenceHighBorder || theme.badgeBorder,
    };
  }

  if (normalized === "medium") {
    return {
      background: theme.confidenceMediumBg || theme.badgeBg,
      color: theme.confidenceMediumText || theme.badgeText,
      borderColor: theme.confidenceMediumBorder || theme.badgeBorder,
    };
  }

  if (normalized === "low") {
    return {
      background: theme.confidenceLowBg || theme.badgeBg,
      color: theme.confidenceLowText || theme.badgeText,
      borderColor: theme.confidenceLowBorder || theme.badgeBorder,
    };
  }

  return {
    background: theme.badgeBg,
    color: theme.badgeText,
    borderColor: theme.badgeBorder,
  };
}

/**
 * Returns the badge theme used for Semgrep confidence values.
 */
function getConfidenceTheme(confidence, theme) {
  const normalized =
    typeof confidence === "string" ? confidence.trim().toLowerCase() : "";

  if (normalized === "very high" || normalized === "high") {
    return {
      background: theme.confidenceHighBg,
      color: theme.confidenceHighText,
      borderColor: theme.confidenceHighBorder,
    };
  }

  if (normalized === "medium") {
    return {
      background: theme.confidenceMediumBg,
      color: theme.confidenceMediumText,
      borderColor: theme.confidenceMediumBorder,
    };
  }

  if (normalized === "low") {
    return {
      background: theme.confidenceLowBg,
      color: theme.confidenceLowText,
      borderColor: theme.confidenceLowBorder,
    };
  }

  return {
    background: theme.badgeBg,
    color: theme.badgeText,
    borderColor: theme.badgeBorder,
  };
}

/**
 * Avoids repeating the same message twice when a group-level message and
 * finding-level message are identical.
 */
function shouldShowFindingMessage(finding, group) {
  const findingMessage = String(finding.message || "").trim();
  const groupMessage = String(group.message || "").trim();

  if (!findingMessage) return false;
  if (groupMessage && findingMessage === groupMessage) return false;

  return true;
}

/**
 * Displays grouped REGO or Semgrep findings.
 *
 * Expected `groups` shape:
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
 *         references: [...],
 *         raw: {...}
 *       }
 *     ]
 *   }
 * ]
 */
export function FindingGroups({
  title,
  emptyText,
  resultText,
  groups,
  theme,
  showFindingSeverity = true,
  showFindingConfidence = false,
}) {
  return (
    <section
      style={{
        ...styles.resultBox,
        background: theme.resultBg,
        borderColor: theme.border,
      }}
    >
      <h2 style={{ ...styles.resultTitle, color: theme.title }}>{title}</h2>

      <p style={{ ...styles.resultSummary, color: theme.muted }}>
        {groups.length === 0 ? emptyText : resultText}
      </p>

      {groups.length > 0 && (
        <div style={styles.findingsList}>
          {groups.map((group, groupIndex) => (
            <article
              key={`${group.title}-${group.ruleId}-${groupIndex}`}
              style={{
                ...styles.findingCard,
                background: theme.findingBg,
                borderColor: theme.border,
              }}
            >
              <div style={styles.findingHeader}>
                <div style={styles.groupTitleArea}>
                  <strong
                    style={{
                      ...styles.findingAlgorithm,
                      color: theme.title,
                    }}
                  >
                    {group.title}
                  </strong>

                  {group.ruleId && (
                    <p
                      style={{
                        ...styles.findingMeta,
                        color: theme.muted,
                        marginTop: 4,
                      }}
                    >
                      Rule: {group.ruleId}
                    </p>
                  )}
                </div>

                <div style={styles.badgeStack}>
                  <span
                    style={{
                      ...styles.countBadge,
                      background: theme.badgeBg,
                      color: theme.badgeText,
                      borderColor: theme.badgeBorder,
                    }}
                  >
                    {group.findings.length} finding
                    {group.findings.length === 1 ? "" : "s"}
                  </span>
                </div>
              </div>

              {group.message && (
                <p style={{ ...styles.findingInfo, color: theme.text }}>
                  {group.message}
                </p>
              )}

              <details
                style={{
                  ...styles.findingsDropdown,
                  borderColor: theme.border,
                  background: theme.locationBg,
                }}
              >
                <summary
                  style={{
                    ...styles.findingsDropdownSummary,
                    color: theme.title,
                  }}
                >
                  View {group.findings.length} finding
                  {group.findings.length === 1 ? "" : "s"}
                </summary>

                <ol style={styles.locationList}>
                  {group.findings.map((finding, findingIndex) => {
                    const showMessage = shouldShowFindingMessage(finding, group);
                    const severity = formatSeverity(finding.severity);
                    const findingSeverityStyle = getSeverityTheme(severity, theme);
                    const findingConfidenceStyle = getConfidenceTheme(
                      finding.confidence,
                      theme
                    );

                    return (
                      <li
                        key={`${group.title}-${finding.title}-${finding.ruleId}-${findingIndex}`}
                        style={{
                          ...styles.locationItem,
                          color: theme.muted,
                          borderColor: theme.border,
                        }}
                      >
                        <div style={styles.findingRowHeader}>
                          <strong
                            style={{
                              ...styles.findingRowTitle,
                              color: theme.title,
                            }}
                          >
                            {finding.title || "Finding"}
                          </strong>

                          <div style={styles.findingRowBadges}>
                            {showFindingSeverity && severity && (
                              <span
                                style={{
                                  ...styles.confidenceBadge,
                                  ...findingSeverityStyle,
                                }}
                              >
                                Severity: {severity}
                              </span>
                            )}

                            {showFindingConfidence && finding.confidence && (
                              <span
                                style={{
                                  ...styles.confidenceBadge,
                                  ...findingConfidenceStyle,
                                }}
                              >
                                Confidence: {finding.confidence}
                              </span>
                            )}
                          </div>
                        </div>

                        {finding.ruleId && finding.ruleId !== group.ruleId && (
                          <div style={styles.findingRowMeta}>
                            Rule: {finding.ruleId}
                          </div>
                        )}

                        {finding.location && (
                          <div style={styles.findingRowMeta}>
                            Location: {finding.location}
                          </div>
                        )}

                        {showMessage && (
                          <p
                            style={{
                              ...styles.locationMessage,
                              color: theme.text,
                            }}
                          >
                            {finding.message}
                          </p>
                        )}

                        {finding.references?.length > 0 && (
                          <details
                            style={{
                              ...styles.innerDropdown,
                              borderColor: theme.border,
                              background: theme.resultBg,
                            }}
                          >
                            <summary
                              style={{
                                ...styles.innerDropdownSummary,
                                color: theme.title,
                              }}
                            >
                              View {finding.references.length} reference
                              {finding.references.length === 1 ? "" : "s"}
                            </summary>

                            <ul style={styles.referenceList}>
                              {finding.references.map((reference, referenceIndex) => (
                                <li
                                  key={`${finding.ruleId}-${referenceIndex}`}
                                  style={{
                                    ...styles.referenceItem,
                                    color: theme.muted,
                                  }}
                                >
                                  {formatReference(reference)}
                                </li>
                              ))}
                            </ul>
                          </details>
                        )}
                      </li>
                    );
                  })}
                </ol>
              </details>
            </article>
          ))}
        </div>
      )}
    </section>
  );
}
