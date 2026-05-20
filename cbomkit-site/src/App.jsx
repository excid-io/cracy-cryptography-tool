import React, { useRef, useState } from "react";

const HTTP_API_BASE =
  import.meta.env.VITE_CBOMKIT_HTTP_API_BASE || "http://localhost:8081";

const SEMGREP_API_BASE =
  import.meta.env.VITE_SEMGREP_API_BASE || "http://localhost:9091";

const POLICY_API_BASE = import.meta.env.VITE_POLICY_API_BASE || "/opa";

const OPA_DECISION_PATH =
  import.meta.env.VITE_OPA_DECISION_PATH || "/v1/data/cbom/eccg";

//const IMPORTANT_SEVERITIES = new Set(["high", "critical", "warning"]);
const IMPORTANT_SEVERITIES = new Set(["high", "critical", "medium"]);

function normalizeScanUrl(value) {
  let scanUrl = value.trim();

  if (!scanUrl.startsWith("pkg:")) {
    scanUrl = scanUrl.replace(/^scm:git:git:\/\//, "").replace(/\.git$/, "");

    if (!scanUrl.includes("://")) {
      scanUrl = `https://${scanUrl}`;
    }
  }

  return scanUrl;
}

function normalizeGitUrlForSemgrep(value) {
  let gitUrl = value.trim();

  if (gitUrl.startsWith("pkg:")) {
    throw new Error(
      "Semgrep needs a cloneable Git URL, for example https://github.com/org/repo."
    );
  }

  gitUrl = gitUrl.replace(/^scm:git:git:\/\//, "");

  if (!gitUrl.includes("://")) {
    gitUrl = `https://${gitUrl}`;
  }

  return gitUrl;
}

function buildCbomScanRequest({ url, scanPath, pat }) {
  const request = { scanUrl: normalizeScanUrl(url) };

  if (scanPath.trim()) {
    request.subfolder = scanPath.trim();
  }

  if (pat.trim()) {
    request.credentials = {
      pat: pat.trim(),
    };
  }

  return request;
}

function buildSemgrepScanRequest({ url, branch, commit, scanPath, pat }) {
  const request = {
    gitUrl: normalizeGitUrlForSemgrep(url),
  };

  if (branch.trim()) {
    request.branch = branch.trim();
  }

  if (commit.trim()) {
    request.commit = commit.trim();
  }

  if (scanPath.trim()) {
    request.subfolder = scanPath.trim();
  }

  if (pat.trim()) {
    request.credentials = {
      pat: pat.trim(),
    };
  }

  return request;
}

function isBusyStatus(status) {
  return (
    status.startsWith("Generating") ||
    status.startsWith("Submitting") ||
    status.startsWith("Scan accepted") ||
    status.startsWith("Waiting") ||
    status.startsWith("Evaluating") ||
    status.startsWith("Running")
  );
}

function recordMatchesScanUrl(record, scanUrl) {
  if (record.gitUrl === scanUrl) return true;

  return record.bom?.metadata?.properties?.some(
    (property) => property.name === "gitUrl" && property.value === scanUrl
  );
}

function getOpaEndpoint() {
  const base = POLICY_API_BASE.replace(/\/$/, "");
  const path = OPA_DECISION_PATH.startsWith("/")
    ? OPA_DECISION_PATH
    : `/${OPA_DECISION_PATH}`;

  return `${base}${path}`;
}

function getSemgrepEndpoint() {
  return `${SEMGREP_API_BASE.replace(/\/$/, "")}/scan`;
}

function extractOpaResult(policyResult) {
  if (!policyResult) return null;

  if (Object.prototype.hasOwnProperty.call(policyResult, "result")) {
    return policyResult.result;
  }

  return policyResult;
}

function getStringValue(object, keys) {
  for (const key of keys) {
    const value = object?.[key];

    if (typeof value === "string" && value.trim()) {
      return value.trim();
    }
  }

  return "";
}

function normalizeSeverity(value) {
  if (typeof value !== "string") return "";
  return value.trim().toLowerCase();
}

function normalizeConfidence(value) {
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

function getConfidenceFromMetadata(metadata) {
  return normalizeConfidence(
    getStringValue(metadata || {}, [
      "confidence",
      "rule_confidence",
      "ruleConfidence",
      "precision",
      "certainty",
    ])
  );
}

function humanizeKey(value) {
  if (!value) return "";

  return String(value)
    .replace(/_/g, " ")
    .replace(/-/g, " ")
    .replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function makePathLabel(path) {
  return path
    .filter((part) => part !== "findings" && !/^\d+$/.test(part))
    .map(humanizeKey)
    .join(" / ");
}

function getRegoFindingTitle(finding, path) {
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

function getRegoFindingInfo(finding) {
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

function extractImportantFindings(policyResult) {
  const root = extractOpaResult(policyResult);
  const findings = [];

  function visit(value, path = []) {
    if (Array.isArray(value)) {
      value.forEach((item, index) => visit(item, [...path, String(index)]));
      return;
    }

    if (!value || typeof value !== "object") {
      return;
    }

    const severity = normalizeSeverity(
      value.severity ||
        value.level ||
        value.risk ||
        value.impact ||
        value.priority
    );

    if (IMPORTANT_SEVERITIES.has(severity)) {
      findings.push({
        title: getRegoFindingTitle(value, path),
        message: getRegoFindingInfo(value),
        severity,
        ruleId: getStringValue(value, ["ruleId", "rule_id", "id"]),
        section: makePathLabel(path),
        references: Array.isArray(value.references) ? value.references : [],
        raw: value,
      });
    }

    for (const [key, child] of Object.entries(value)) {
      visit(child, [...path, key]);
    }
  }

  visit(root);

  const seen = new Set();

  return findings.filter((finding) => {
    const key = `${finding.severity}|${finding.ruleId}|${finding.title}|${finding.message}`;

    if (seen.has(key)) {
      return false;
    }

    seen.add(key);
    return true;
  });
}

function groupRegoFindings(findings) {
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

  return Array.from(groups.values()).sort((a, b) =>
    a.title.localeCompare(b.title)
  );
}

function getSemgrepFindings(semgrepResult) {
  return semgrepResult?.result?.findings || [];
}

function getRuleDisplayNameFromMetadata(metadata) {
  return getStringValue(metadata, [
    "display_name",
    "displayName",
    "human_name",
    "humanName",
    "human_readable_name",
    "humanReadableName",
    "title",
    "name",
    "algorithm",
    "algorithm_name",
    "algorithmName",
    "primitive",
  ]);
}

function humanizeRuleId(ruleId) {
  if (!ruleId) return "Unknown Rule";

  let parts = ruleId
    .replace(/^configs?\./, "")
    .split(/[._-]+/)
    .filter(Boolean);

  const cryptoIndex = parts.lastIndexOf("crypto");

  if (cryptoIndex >= 0 && cryptoIndex + 1 < parts.length) {
    parts = parts.slice(cryptoIndex + 1);
  }

  const ignoredWords = new Set([
    "configs",
    "config",
    "security",
    "rule",
    "rules",
    "python",
    "java",
    "javascript",
    "typescript",
    "crypto",
  ]);

  const acronymMap = {
    aes: "AES",
    des: "DES",
    "3des": "3DES",
    tripledes: "Triple-DES",
    rsa: "RSA",
    dsa: "DSA",
    ecdsa: "ECDSA",
    dh: "DH",
    ecdh: "ECDH",
    md2: "MD2",
    md4: "MD4",
    md5: "MD5",
    sha1: "SHA-1",
    sha224: "SHA-224",
    sha256: "SHA-256",
    sha384: "SHA-384",
    sha512: "SHA-512",
    rc2: "RC2",
    rc4: "RC4",
    ssl: "SSL",
    tls: "TLS",
    ecb: "ECB",
    cbc: "CBC",
    gcm: "GCM",
    ccm: "CCM",
    fips: "FIPS",
    kdf: "KDF",
    hkdf: "HKDF",
    pbkdf2: "PBKDF2",
  };

  return parts
    .filter((part) => !ignoredWords.has(part.toLowerCase()))
    .map((part) => {
      const lower = part.toLowerCase();

      if (acronymMap[lower]) {
        return acronymMap[lower];
      }

      return lower.charAt(0).toUpperCase() + lower.slice(1);
    })
    .join(" ");
}

function formatLocation(finding) {
  const path = finding.path || finding.location || "Unknown file";
  const line = finding.line ? `:${finding.line}` : "";
  const column = finding.column ? `:${finding.column}` : "";

  return `${path}${line}${column}`;
}

function formatReference(reference) {
  const location = reference.location || reference.path || "Unknown file";
  const line = reference.line ? `:${reference.line}` : "";
  const column = reference.column ? `:${reference.column}` : "";

  return `${location}${line}${column}`;
}

function getSemgrepSectionFromMetadata(metadata) {
  return getStringValue(metadata, [
    "section",
    "policy_section",
    "policySection",
    "eccg_section",
    "eccgSection",
    "chapter",
    "family",
  ]);
}

function getSemgrepSectionFromRuleId(ruleId) {
  const normalized = String(ruleId || "").toLowerCase();

  if (
    normalized.includes("symmetric-atomic-primitives") &&
    (normalized.includes(".aes.") ||
      normalized.includes(".des.") ||
      normalized.includes(".3des.") ||
      normalized.includes(".tripledes.") ||
      normalized.includes(".block-cipher") ||
      normalized.includes(".block_cipher"))
  ) {
    return "Symmetric Atomic Primitives / Block Ciphers";
  }

  if (
    normalized.includes("symmetric-atomic-primitives") &&
    (normalized.includes(".sha") ||
      normalized.includes(".md5") ||
      normalized.includes(".md4") ||
      normalized.includes(".md2") ||
      normalized.includes(".hash"))
  ) {
    return "Symmetric Atomic Primitives / Hash Functions";
  }

  if (
    normalized.includes("symmetric-atomic-primitives") &&
    (normalized.includes(".hmac.") ||
      normalized.includes(".mac.") ||
      normalized.includes("cmac") ||
      normalized.includes("gmac"))
  ) {
    return "Symmetric Atomic Primitives / MACs";
  }

  if (
    normalized.includes("symmetric-atomic-primitives") &&
    (normalized.includes(".rng.") ||
      normalized.includes(".random.") ||
      normalized.includes(".drbg.") ||
      normalized.includes("secure-random"))
  ) {
    return "Symmetric Atomic Primitives / Random Bit Generation";
  }

  if (
    normalized.includes("asymmetric") ||
    normalized.includes(".rsa.") ||
    normalized.includes(".dsa.") ||
    normalized.includes(".ecdsa.") ||
    normalized.includes(".ecdh.") ||
    normalized.includes(".dh.")
  ) {
    return "Asymmetric Atomic Primitives";
  }

  if (
    normalized.includes(".tls.") ||
    normalized.includes(".ssl.") ||
    normalized.includes("protocol")
  ) {
    return "Protocols";
  }

  if (
    normalized.includes(".kdf.") ||
    normalized.includes("pbkdf") ||
    normalized.includes("hkdf") ||
    normalized.includes("scrypt") ||
    normalized.includes("argon")
  ) {
    return "Key Derivation Functions";
  }

  if (
    normalized.includes("secretsharing") ||
    normalized.includes("secret-sharing") ||
    normalized.includes("secret_sharing") ||
    normalized.includes("shamir")
  ) {
    return "Secret Sharing";
  }

  return "Semgrep Findings";
}

function getSemgrepSection(finding) {
  return (
    getSemgrepSectionFromMetadata(finding.metadata || {}) ||
    getSemgrepSectionFromRuleId(finding.ruleId)
  );
}

function getSeverityRank(severity) {
  const severityOrder = {
    critical: 0,
    error: 1,
    high: 2,
    warning: 3,
    medium: 4,
    info: 5,
    low: 6,
    unknown: 7,
  };

  return severityOrder[normalizeSeverity(severity)] ?? 99;
}

function getMoreSevereSeverity(a, b) {
  return getSeverityRank(a) <= getSeverityRank(b) ? a : b;
}

function getConfidenceRank(confidence) {
  const confidenceOrder = {
    "very high": 0,
    high: 1,
    medium: 2,
    low: 3,
    unknown: 4,
  };

  return confidenceOrder[normalizeConfidence(confidence)] ?? 99;
}

function getHigherConfidence(a, b) {
  return getConfidenceRank(a) <= getConfidenceRank(b) ? a : b;
}

function groupSemgrepFindingsBySection(findings) {
  const sectionGroups = new Map();

  for (const finding of findings) {
    const section = getSemgrepSection(finding);
    const ruleId = finding.ruleId || "unknown-rule";
    const confidence =
      getConfidenceFromMetadata(finding.metadata || {}) || "unknown";

    if (!sectionGroups.has(section)) {
      sectionGroups.set(section, {
        title: section,
        ruleId: "",
        severity: "",
        message: "",
        findingsByRule: new Map(),
      });
    }

    const sectionGroup = sectionGroups.get(section);

    if (!sectionGroup.findingsByRule.has(ruleId)) {
      sectionGroup.findingsByRule.set(ruleId, {
        title:
          getRuleDisplayNameFromMetadata(finding.metadata || {}) ||
          finding.algorithm ||
          humanizeRuleId(ruleId),
        message: finding.message || "",
        severity: finding.severity || "unknown",
        confidence,
        ruleId,
        location: "",
        references: [],
        raw: finding,
      });
    }

    const ruleFinding = sectionGroup.findingsByRule.get(ruleId);

    ruleFinding.severity = getMoreSevereSeverity(
      ruleFinding.severity,
      finding.severity || "unknown"
    );

    ruleFinding.confidence = getHigherConfidence(
      ruleFinding.confidence || "unknown",
      confidence || "unknown"
    );

    if (!ruleFinding.message && finding.message) {
      ruleFinding.message = finding.message;
    }

    ruleFinding.references.push({
      location: finding.path || finding.location || "Unknown file",
      line: finding.line,
      column: finding.column,
      raw: finding,
    });
  }

  return Array.from(sectionGroups.values())
    .map((sectionGroup) => {
      const findingsForSection = Array.from(
        sectionGroup.findingsByRule.values()
      )
        .map((ruleFinding) => ({
          ...ruleFinding,
          references: ruleFinding.references.sort((a, b) =>
            formatReference(a).localeCompare(formatReference(b))
          ),
        }))
        .sort((a, b) => {
          const aSeverity = getSeverityRank(a.severity);
          const bSeverity = getSeverityRank(b.severity);

          if (aSeverity !== bSeverity) {
            return aSeverity - bSeverity;
          }

          const aConfidence = getConfidenceRank(a.confidence);
          const bConfidence = getConfidenceRank(b.confidence);

          if (aConfidence !== bConfidence) {
            return aConfidence - bConfidence;
          }

          return a.title.localeCompare(b.title);
        });

      return {
        title: sectionGroup.title,
        ruleId: "",
        severity: "",
        message: "",
        findings: findingsForSection,
      };
    })
    .sort((a, b) => a.title.localeCompare(b.title));
}

function getSeverityTheme(severity, theme) {
  const normalized = normalizeSeverity(severity);

  if (normalized === "critical" || normalized === "error") {
    return {
      background: theme.criticalBg,
      color: theme.criticalText,
      borderColor: theme.criticalBorder,
    };
  }

  if (normalized === "high" || normalized === "warning") {
    return {
      background: theme.highBg,
      color: theme.highText,
      borderColor: theme.highBorder,
    };
  }

  return {
    background: theme.infoBg,
    color: theme.infoText,
    borderColor: theme.infoBorder,
  };
}

function getConfidenceTheme(confidence, theme) {
  const normalized = normalizeConfidence(confidence);

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

function formatOpaErrors(body, responseText) {
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

function makeErrorDetails(error) {
  if (!error) return "";

  if (error.details) return error.details;

  return error instanceof Error ? error.message : String(error);
}

function shouldShowFindingMessage(finding, group) {
  const findingMessage = String(finding.message || "").trim();
  const groupMessage = String(group.message || "").trim();

  if (!findingMessage) return false;
  if (groupMessage && findingMessage === groupMessage) return false;

  return true;
}

function sleep(ms, signal) {
  return new Promise((resolve, reject) => {
    const timeoutId = setTimeout(resolve, ms);

    if (signal) {
      signal.addEventListener(
        "abort",
        () => {
          clearTimeout(timeoutId);
          reject(new DOMException("The operation was aborted.", "AbortError"));
        },
        { once: true }
      );
    }
  });
}

function Field({ label, value, onChange, placeholder, type = "text", theme }) {
  return (
    <label style={styles.field}>
      <span style={{ ...styles.label, color: theme.label }}>{label}</span>
      <input
        type={type}
        value={value}
        placeholder={placeholder}
        onChange={(event) => onChange(event.target.value)}
        style={{
          ...styles.input,
          background: theme.inputBg,
          color: theme.text,
          borderColor: theme.border,
        }}
      />
    </label>
  );
}

function FindingGroups({
  title,
  emptyText,
  resultText,
  groups,
  theme,
  showGroupSeverity = true,
  showFindingSeverity = false,
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
          {groups.map((group, groupIndex) => {
            const groupSeverityStyle = getSeverityTheme(group.severity, theme);

            return (
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
                    {showGroupSeverity && (
                      <span
                        style={{
                          ...styles.severityBadge,
                          ...groupSeverityStyle,
                        }}
                      >
                        Severity: {group.severity || "unknown"}
                      </span>
                    )}

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
                      const showMessage = shouldShowFindingMessage(
                        finding,
                        group
                      );

                      const findingSeverityStyle = getSeverityTheme(
                        finding.severity,
                        theme
                      );

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
                              {showFindingSeverity && (
                                <span
                                  style={{
                                    ...styles.severityBadge,
                                    ...findingSeverityStyle,
                                  }}
                                >
                                  Severity: {finding.severity || "unknown"}
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
                                {finding.references.map(
                                  (reference, referenceIndex) => (
                                    <li
                                      key={`${finding.ruleId}-${referenceIndex}`}
                                      style={{
                                        ...styles.referenceItem,
                                        color: theme.muted,
                                      }}
                                    >
                                      {formatReference(reference)}
                                    </li>
                                  )
                                )}
                              </ul>
                            </details>
                          )}
                        </li>
                      );
                    })}
                  </ol>
                </details>
              </article>
            );
          })}
        </div>
      )}
    </section>
  );
}

export default function CbomkitSimpleScanner() {
  const [url, setUrl] = useState("");
  const [scanPath, setScanPath] = useState("");
  const [branch, setBranch] = useState("");
  const [commit, setCommit] = useState("");
  const [pat, setPat] = useState("");
  const [status, setStatus] = useState("Ready");
  const [error, setError] = useState("");
  const [cbom, setCbom] = useState(null);
  const [policyResult, setPolicyResult] = useState(null);
  const [policyError, setPolicyError] = useState("");
  const [policyErrorDetails, setPolicyErrorDetails] = useState("");
  const [semgrepResult, setSemgrepResult] = useState(null);
  const [semgrepError, setSemgrepError] = useState("");
  const [darkMode, setDarkMode] = useState(false);

  const abortControllerRef = useRef(null);

  const theme = darkMode ? darkTheme : lightTheme;
  const busy = isBusyStatus(status);
  const opaEndpoint = getOpaEndpoint();
  const semgrepEndpoint = getSemgrepEndpoint();

  const importantFindings = extractImportantFindings(policyResult);
  const groupedRegoFindings = groupRegoFindings(importantFindings);

  const semgrepFindings = getSemgrepFindings(semgrepResult);
  const groupedSemgrepFindings = groupSemgrepFindingsBySection(semgrepFindings);

  function startControlledRun() {
    abortControllerRef.current?.abort();

    const controller = new AbortController();
    abortControllerRef.current = controller;

    setError("");

    return controller;
  }

  function clearRegoState() {
    setPolicyResult(null);
    setPolicyError("");
    setPolicyErrorDetails("");
  }

  function clearSemgrepState() {
    setSemgrepResult(null);
    setSemgrepError("");
  }

  function clearEvaluationState() {
    clearRegoState();
    clearSemgrepState();
  }

  function finishControlledRun(controller) {
    if (abortControllerRef.current === controller) {
      abortControllerRef.current = null;
    }
  }

  function requireUrl() {
    if (!url.trim()) {
      setError("Enter a URL first.");
      return false;
    }

    return true;
  }

  async function generateCbom(signal) {
    setCbom(null);

    setStatus("Submitting CBOM scan...");

    const scanStartedAt = Date.now();
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

    setStatus("Scan accepted. Waiting for new CBOM...");

    const generatedCbom = await pollForCbom({
      scanUrl: scanRequest.scanUrl,
      scanStartedAt,
      signal,
    });

    setCbom(generatedCbom);
    return generatedCbom;
  }

  async function handleGenerateCbom() {
    const controller = startControlledRun();

    clearEvaluationState();

    if (!requireUrl()) {
      finishControlledRun(controller);
      return;
    }

    try {
      setStatus("Generating CBOM...");
      await generateCbom(controller.signal);
      setStatus("CBOM generated");
    } catch (err) {
      if (err instanceof DOMException && err.name === "AbortError") {
        setStatus("Cancelled");
        return;
      }

      setStatus("CBOM generation failed");
      setError(err instanceof Error ? err.message : "CBOM generation failed.");
    } finally {
      finishControlledRun(controller);
    }
  }

  async function handleRegoEvaluation() {
    const controller = startControlledRun();

    clearSemgrepState();
    clearRegoState();

    if (!requireUrl()) {
      finishControlledRun(controller);
      return;
    }

    try {
      setStatus("Generating CBOM for REGO evaluation...");
      const generatedCbom = await generateCbom(controller.signal);

      console.log("Generated CBOM for REGO evaluation:", generatedCbom);

      setStatus("Evaluating REGO policy...");
      await evaluatePolicy(generatedCbom, controller.signal);

      setStatus("REGO evaluation finished");
    } catch (err) {
      if (err instanceof DOMException && err.name === "AbortError") {
        setStatus("Cancelled");
        return;
      }

      const details = makeErrorDetails(err);

      setStatus("REGO evaluation failed");
      setPolicyError(
        err instanceof Error ? err.message : "REGO evaluation failed."
      );
      setPolicyErrorDetails(details);
    } finally {
      finishControlledRun(controller);
    }
  }

  async function handleSemgrepEvaluation() {
    const controller = startControlledRun();

    clearRegoState();
    clearSemgrepState();

    if (!requireUrl()) {
      finishControlledRun(controller);
      return;
    }

    try {
      setStatus("Running Semgrep evaluation...");
      await runSemgrepScan(controller.signal);
      setStatus("Semgrep evaluation finished");
    } catch (err) {
      if (err instanceof DOMException && err.name === "AbortError") {
        setStatus("Cancelled");
        return;
      }

      setStatus("Semgrep evaluation failed");
      setSemgrepError(
        err instanceof Error ? err.message : "Semgrep evaluation failed."
      );
    } finally {
      finishControlledRun(controller);
    }
  }

  async function runSemgrepScan(signal) {
    setSemgrepError("");
    setSemgrepResult(null);

    const semgrepScanRequest = buildSemgrepScanRequest({
      url,
      branch,
      commit,
      scanPath,
      pat,
    });

    const response = await fetch(semgrepEndpoint, {
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

    setSemgrepResult(body);
    return body;
  }

  async function pollForCbom({ scanUrl, scanStartedAt, signal }) {
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

      setStatus(`Waiting for new CBOM... ${attempt}/${maxAttempts}`);

      await sleep(delayMs, signal);
    }

    throw new Error("Timed out waiting for a newly generated CBOM.");
  }

  async function evaluatePolicy(cbomToEvaluate = cbom, signal) {
    setPolicyError("");
    setPolicyErrorDetails("");
    setPolicyResult(null);

    if (!cbomToEvaluate) {
      const noCbomError = new Error("No CBOM is available to evaluate.");
      noCbomError.details =
        "Generate a CBOM first, then run REGO evaluation again.";
      throw noCbomError;
    }

    const response = await fetch(opaEndpoint, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        input: cbomToEvaluate,
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
            endpoint: opaEndpoint,
          },
          null,
          2
        );

      throw error;
    }

    setPolicyResult(body);
    return body;
  }

  function cancelProcess() {
    abortControllerRef.current?.abort();
    abortControllerRef.current = null;
    setStatus("Cancelled");
  }

  function downloadJson(filename, value) {
    if (!value) return;

    const blob = new Blob([JSON.stringify(value, null, 2)], {
      type: "application/json",
    });

    const objectUrl = URL.createObjectURL(blob);
    const link = document.createElement("a");

    link.href = objectUrl;
    link.download = filename;
    link.click();

    URL.revokeObjectURL(objectUrl);
  }

  function resetForm() {
    abortControllerRef.current?.abort();
    abortControllerRef.current = null;

    setUrl("");
    setScanPath("");
    setBranch("");
    setCommit("");
    setPat("");
    setStatus("Ready");
    setError("");
    setCbom(null);
    clearEvaluationState();
  }

  return (
    <main
      style={{
        ...styles.page,
        background: theme.pageBg,
        color: theme.text,
      }}
    >
      <section
        style={{
          ...styles.card,
          background: theme.cardBg,
          borderColor: theme.border,
        }}
      >
        <div style={styles.headerRow}>
          <div style={styles.headerText}>
            <h1 style={{ ...styles.title, color: theme.title }}>
              CBOM, REGO, and Semgrep
            </h1>
          </div>

          <label style={{ ...styles.darkModeLabel, color: theme.text }}>
            <input
              type="checkbox"
              checked={darkMode}
              onChange={(event) => setDarkMode(event.target.checked)}
            />
            Dark mode
          </label>
        </div>

        <Field
          label="Git URL"
          placeholder="https://github.com/org/repo"
          value={url}
          onChange={setUrl}
          theme={theme}
        />

        <Field
          label="Scan path"
          placeholder="Optional, e.g. src"
          value={scanPath}
          onChange={setScanPath}
          theme={theme}
        />

        <Field
          label="Branch"
          placeholder="Optional, e.g. main"
          value={branch}
          onChange={setBranch}
          theme={theme}
        />

        <Field
          label="Commit"
          placeholder="Optional exact commit SHA"
          value={commit}
          onChange={setCommit}
          theme={theme}
        />

        <Field
          label="PAT"
          type="password"
          placeholder="Optional token for private repos or rate limits"
          value={pat}
          onChange={setPat}
          theme={theme}
        />

        {error && <p style={styles.error}>{error}</p>}
        {semgrepError && <p style={styles.error}>{semgrepError}</p>}

        {policyError && (
          <section
            style={{
              ...styles.errorPanel,
              background: theme.dangerBg,
              borderColor: theme.dangerBorder,
              color: theme.dangerText,
            }}
          >
            <h2 style={styles.errorPanelTitle}>REGO evaluation failed</h2>

            <p style={styles.errorPanelMessage}>{policyError}</p>

            {policyErrorDetails && (
              <pre
                style={{
                  ...styles.errorDetails,
                  background: theme.errorDetailsBg,
                  borderColor: theme.dangerBorder,
                  color: theme.dangerText,
                }}
              >
                {policyErrorDetails}
              </pre>
            )}
          </section>
        )}

        <div style={styles.buttonRow}>
          <button
            onClick={handleGenerateCbom}
            disabled={busy}
            style={{
              ...styles.primaryButton,
              background: theme.primaryBg,
              color: theme.primaryText,
              opacity: busy ? 0.7 : 1,
              cursor: busy ? "not-allowed" : "pointer",
            }}
          >
            Generate CBOM
          </button>

          <button
            onClick={handleRegoEvaluation}
            disabled={busy}
            style={{
              ...styles.secondaryButton,
              borderColor: theme.border,
              color: theme.text,
              opacity: busy ? 0.7 : 1,
              cursor: busy ? "not-allowed" : "pointer",
            }}
          >
            REGO Evaluation
          </button>

          <button
            onClick={handleSemgrepEvaluation}
            disabled={busy}
            style={{
              ...styles.secondaryButton,
              borderColor: theme.border,
              color: theme.text,
              opacity: busy ? 0.7 : 1,
              cursor: busy ? "not-allowed" : "pointer",
            }}
          >
            Semgrep Evaluation
          </button>

          {busy && (
            <button
              onClick={cancelProcess}
              style={{
                ...styles.dangerButton,
                borderColor: theme.dangerBorder,
                color: theme.dangerText,
                background: theme.dangerBg,
              }}
            >
              Cancel
            </button>
          )}

          <button
            onClick={resetForm}
            disabled={busy}
            style={{
              ...styles.secondaryButton,
              borderColor: theme.border,
              color: theme.text,
              opacity: busy ? 0.7 : 1,
              cursor: busy ? "not-allowed" : "pointer",
            }}
          >
            Reset
          </button>

          {cbom && (
            <button
              onClick={() => downloadJson("cbom.json", cbom)}
              style={{
                ...styles.secondaryButton,
                borderColor: theme.border,
                color: theme.text,
                cursor: "pointer",
              }}
            >
              Download CBOM
            </button>
          )}

          {policyResult && (
            <button
              onClick={() =>
                downloadJson("policy-evaluation.json", policyResult)
              }
              style={{
                ...styles.secondaryButton,
                borderColor: theme.border,
                color: theme.text,
                cursor: "pointer",
              }}
            >
              Download REGO Result
            </button>
          )}

          {semgrepResult && (
            <button
              onClick={() => downloadJson("semgrep-result.json", semgrepResult)}
              style={{
                ...styles.secondaryButton,
                borderColor: theme.border,
                color: theme.text,
                cursor: "pointer",
              }}
            >
              Download Semgrep Result
            </button>
          )}
        </div>

        <p style={{ ...styles.status, color: theme.muted }}>Status: {status}</p>

        {semgrepResult && (
          <FindingGroups
            title="Semgrep high and critical findings"
            emptyText="No Semgrep findings were returned."
            resultText={`${semgrepFindings.length} finding${
              semgrepFindings.length === 1 ? "" : "s"
            } across ${groupedSemgrepFindings.length} group${
              groupedSemgrepFindings.length === 1 ? "" : "s"
            }.`}
            groups={groupedSemgrepFindings}
            theme={theme}
            showGroupSeverity={false}
            showFindingSeverity={true}
            showFindingConfidence={true}
          />
        )}

        {policyResult && (
          <FindingGroups
            title="REGO high and critical findings"
            emptyText="No high or critical REGO findings were returned."
            resultText={`${importantFindings.length} high/critical finding${
              importantFindings.length === 1 ? "" : "s"
            } across ${groupedRegoFindings.length} group${
              groupedRegoFindings.length === 1 ? "" : "s"
            }.`}
            groups={groupedRegoFindings}
            theme={theme}
            showGroupSeverity={false}
            showFindingSeverity={true}
            showFindingConfidence={false}
          />
        )}
      </section>
    </main>
  );
}

const lightTheme = {
  pageBg: "#f1f5f9",
  cardBg: "#f8fafc",
  inputBg: "#ffffff",
  text: "#0f172a",
  title: "#0f172a",
  label: "#0f172a",
  muted: "#64748b",
  border: "#bfd0e3",
  primaryBg: "#0f172a",
  primaryText: "#ffffff",
  badgeBg: "#ffffff",
  badgeText: "#0f172a",
  badgeBorder: "#bfd0e3",
  resultBg: "#ffffff",
  findingBg: "#ffffff",
  locationBg: "#f8fafc",
  dangerBg: "#fef2f2",
  dangerText: "#991b1b",
  dangerBorder: "#fecaca",
  errorDetailsBg: "#fff7f7",
  highBg: "#fff7ed",
  highText: "#9a3412",
  highBorder: "#fed7aa",
  criticalBg: "#fef2f2",
  criticalText: "#991b1b",
  criticalBorder: "#fecaca",
  infoBg: "#eff6ff",
  infoText: "#1d4ed8",
  infoBorder: "#bfdbfe",
  confidenceHighBg: "#ecfdf5",
  confidenceHighText: "#166534",
  confidenceHighBorder: "#bbf7d0",
  confidenceMediumBg: "#fefce8",
  confidenceMediumText: "#854d0e",
  confidenceMediumBorder: "#fde68a",
  confidenceLowBg: "#f8fafc",
  confidenceLowText: "#475569",
  confidenceLowBorder: "#cbd5e1",
};

const darkTheme = {
  pageBg: "#020617",
  cardBg: "#071a3d",
  inputBg: "#020817",
  text: "#f8fafc",
  title: "#ffffff",
  label: "#ffffff",
  muted: "#9db1d1",
  border: "#27446f",
  primaryBg: "#ffffff",
  primaryText: "#0f172a",
  badgeBg: "#0f172a",
  badgeText: "#f8fafc",
  badgeBorder: "#334155",
  resultBg: "#06142f",
  findingBg: "#071a3d",
  locationBg: "#06142f",
  dangerBg: "#450a0a",
  dangerText: "#fecaca",
  dangerBorder: "#7f1d1d",
  errorDetailsBg: "#2a0606",
  highBg: "#431407",
  highText: "#fed7aa",
  highBorder: "#9a3412",
  criticalBg: "#450a0a",
  criticalText: "#fecaca",
  criticalBorder: "#991b1b",
  infoBg: "#172554",
  infoText: "#bfdbfe",
  infoBorder: "#1d4ed8",
  confidenceHighBg: "#052e16",
  confidenceHighText: "#bbf7d0",
  confidenceHighBorder: "#15803d",
  confidenceMediumBg: "#422006",
  confidenceMediumText: "#fde68a",
  confidenceMediumBorder: "#a16207",
  confidenceLowBg: "#0f172a",
  confidenceLowText: "#cbd5e1",
  confidenceLowBorder: "#475569",
};

const styles = {
  page: {
    minHeight: "100vh",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    padding: 24,
    boxSizing: "border-box",
    fontFamily:
      "Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, Segoe UI, sans-serif",
  },
  card: {
    width: "100%",
    maxWidth: 860,
    border: "1px solid",
    borderRadius: 20,
    padding: 28,
    boxSizing: "border-box",
    boxShadow: "0 18px 50px rgba(15, 23, 42, 0.12)",
  },
  headerRow: {
    display: "flex",
    alignItems: "flex-start",
    justifyContent: "space-between",
    gap: 16,
    marginBottom: 24,
  },
  headerText: {
    flex: 1,
    minWidth: 0,
  },
  title: {
    margin: 0,
    fontSize: 32,
    lineHeight: 1.1,
    fontWeight: 800,
    textAlign: "left",
  },
  subtitle: {
    margin: "14px 0 6px",
    fontSize: 14,
    textAlign: "left",
  },
  apiBadge: {
    display: "block",
    width: "fit-content",
    maxWidth: "100%",
    margin: 0,
    border: "1px solid",
    borderRadius: 8,
    padding: "6px 10px",
    fontSize: 14,
    fontFamily:
      "ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace",
    lineHeight: 1.3,
    overflowWrap: "anywhere",
    boxSizing: "border-box",
  },
  darkModeLabel: {
    display: "flex",
    alignItems: "center",
    gap: 8,
    fontSize: 14,
    fontWeight: 600,
    whiteSpace: "nowrap",
    userSelect: "none",
  },
  field: {
    display: "block",
    marginBottom: 16,
  },
  label: {
    display: "block",
    marginBottom: 8,
    fontSize: 14,
    fontWeight: 700,
    textAlign: "left",
  },
  input: {
    width: "100%",
    height: 40,
    border: "1px solid",
    borderRadius: 10,
    padding: "0 12px",
    fontSize: 15,
    outline: "none",
    boxSizing: "border-box",
  },
  buttonRow: {
    display: "flex",
    alignItems: "center",
    gap: 10,
    flexWrap: "wrap",
    marginTop: 8,
  },
  primaryButton: {
    border: 0,
    borderRadius: 10,
    padding: "10px 16px",
    fontSize: 15,
    fontWeight: 700,
  },
  secondaryButton: {
    background: "transparent",
    border: "1px solid",
    borderRadius: 10,
    padding: "9px 15px",
    fontSize: 15,
    fontWeight: 650,
  },
  dangerButton: {
    border: "1px solid",
    borderRadius: 10,
    padding: "9px 15px",
    fontSize: 15,
    fontWeight: 700,
    cursor: "pointer",
  },
  status: {
    margin: "18px 0 0",
    fontSize: 14,
    textAlign: "center",
  },
  error: {
    margin: "0 0 16px",
    color: "#dc2626",
    fontSize: 14,
    textAlign: "center",
  },
  errorPanel: {
    margin: "0 0 18px",
    border: "1px solid",
    borderRadius: 12,
    padding: 14,
  },
  errorPanelTitle: {
    margin: 0,
    fontSize: 16,
    fontWeight: 800,
    textAlign: "left",
  },
  errorPanelMessage: {
    margin: "8px 0 0",
    fontSize: 14,
    lineHeight: 1.5,
    textAlign: "left",
    overflowWrap: "anywhere",
  },
  errorDetails: {
    margin: "12px 0 0",
    border: "1px solid",
    borderRadius: 10,
    padding: 12,
    fontSize: 12,
    lineHeight: 1.5,
    whiteSpace: "pre-wrap",
    overflowX: "auto",
    overflowWrap: "anywhere",
    fontFamily:
      "ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace",
  },
  resultBox: {
    marginTop: 24,
    border: "1px solid",
    borderRadius: 14,
    padding: 16,
  },
  resultTitle: {
    margin: 0,
    fontSize: 20,
    fontWeight: 800,
    textAlign: "left",
  },
  resultSummary: {
    margin: "8px 0 12px",
    fontSize: 14,
    textAlign: "left",
  },
  findingsList: {
    display: "grid",
    gap: 12,
  },
  findingCard: {
    border: "1px solid",
    borderRadius: 12,
    padding: 14,
  },
  findingHeader: {
    display: "flex",
    alignItems: "flex-start",
    justifyContent: "space-between",
    gap: 12,
    marginBottom: 8,
  },
  groupTitleArea: {
    minWidth: 0,
    flex: 1,
  },
  badgeStack: {
    display: "flex",
    alignItems: "flex-end",
    gap: 6,
    flexDirection: "column",
  },
  findingAlgorithm: {
    fontSize: 16,
    lineHeight: 1.35,
    overflowWrap: "anywhere",
  },
  severityBadge: {
    border: "1px solid",
    borderRadius: 999,
    padding: "3px 8px",
    fontSize: 12,
    fontWeight: 800,
    textTransform: "uppercase",
    whiteSpace: "nowrap",
  },
  confidenceBadge: {
    border: "1px solid",
    borderRadius: 999,
    padding: "3px 8px",
    fontSize: 12,
    fontWeight: 800,
    textTransform: "uppercase",
    whiteSpace: "nowrap",
  },
  countBadge: {
    border: "1px solid",
    borderRadius: 999,
    padding: "3px 8px",
    fontSize: 12,
    fontWeight: 800,
    whiteSpace: "nowrap",
  },
  findingInfo: {
    margin: 0,
    fontSize: 14,
    lineHeight: 1.5,
    overflowWrap: "anywhere",
    textAlign: "left",
  },
  findingMeta: {
    margin: "8px 0 0",
    fontSize: 12,
    lineHeight: 1.4,
    overflowWrap: "anywhere",
    fontFamily:
      "ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace",
  },
  findingsDropdown: {
    marginTop: 12,
    border: "1px solid",
    borderRadius: 10,
    padding: 12,
  },
  findingsDropdownSummary: {
    cursor: "pointer",
    fontSize: 13,
    fontWeight: 800,
    userSelect: "none",
    textAlign: "left",
  },
  locationList: {
    margin: "12px 0 0",
    paddingLeft: 20,
  },
  locationItem: {
    marginBottom: 8,
    paddingBottom: 8,
    borderBottom: "1px solid",
    fontSize: 12,
    lineHeight: 1.4,
    overflowWrap: "anywhere",
    fontFamily:
      "ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace",
  },
  findingRowHeader: {
    display: "flex",
    alignItems: "flex-start",
    justifyContent: "space-between",
    gap: 10,
    marginBottom: 6,
  },
  findingRowBadges: {
    display: "flex",
    alignItems: "flex-end",
    justifyContent: "flex-end",
    gap: 6,
    flexWrap: "wrap",
  },
  findingRowTitle: {
    fontSize: 13,
    lineHeight: 1.35,
    overflowWrap: "anywhere",
    fontFamily:
      "Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, Segoe UI, sans-serif",
  },
  findingRowMeta: {
    marginTop: 5,
    fontSize: 12,
    lineHeight: 1.4,
    overflowWrap: "anywhere",
  },
  locationMessage: {
    margin: "6px 0 0",
    fontSize: 12,
    lineHeight: 1.4,
    fontFamily:
      "Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, Segoe UI, sans-serif",
  },
  innerDropdown: {
    marginTop: 10,
    border: "1px solid",
    borderRadius: 8,
    padding: 10,
  },
  innerDropdownSummary: {
    cursor: "pointer",
    fontSize: 12,
    fontWeight: 800,
    userSelect: "none",
  },
  referenceList: {
    margin: "8px 0 0",
    paddingLeft: 18,
  },
  referenceItem: {
    marginBottom: 6,
    fontSize: 12,
    lineHeight: 1.4,
    overflowWrap: "anywhere",
  },
};