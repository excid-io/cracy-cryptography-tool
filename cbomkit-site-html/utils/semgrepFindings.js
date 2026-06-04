import {
  getStringValue,
  normalizeConfidence,
  normalizeSeverity,
} from "./regoFindings.js";

/**
 * Returns the raw Semgrep findings array from the Semgrep server response.
 *
 * Expected response shape:
 *
 * {
 *   ok: true,
 *   result: {
 *     findings: [...]
 *   }
 * }
 */
export function getSemgrepFindings(semgrepResult) {
  return semgrepResult?.result?.findings || [];
}

/**
 * Extracts confidence from Semgrep rule metadata.
 */
export function getConfidenceFromMetadata(metadata) {
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

/**
 * Gets a readable rule title from Semgrep metadata.
 */
export function getRuleDisplayNameFromMetadata(metadata) {
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

/**
 * Converts a Semgrep rule ID into a readable title.
 */
export function humanizeRuleId(ruleId) {
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

/**
 * Formats a Semgrep reference for sorting.
 */
export function formatReference(reference) {
  const location = reference.location || reference.path || "Unknown file";
  const line = reference.line ? `:${reference.line}` : "";
  const column = reference.column ? `:${reference.column}` : "";

  return `${location}${line}${column}`;
}

/**
 * Gets a Semgrep policy section from metadata, if provided.
 */
export function getSemgrepSectionFromMetadata(metadata) {
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

/**
 * Infers a Semgrep policy section from the rule ID.
 */
export function getSemgrepSectionFromRuleId(ruleId) {
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

/**
 * Gets the display section for a Semgrep finding.
 */
export function getSemgrepSection(finding) {
  return (
    getSemgrepSectionFromMetadata(finding.metadata || {}) ||
    getSemgrepSectionFromRuleId(finding.ruleId)
  );
}

/**
 * Sort ranking for severities.
 */
export function getSeverityRank(severity) {
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

/**
 * Sort ranking for confidence.
 */
export function getConfidenceRank(confidence) {
  const confidenceOrder = {
    "very high": 0,
    high: 1,
    medium: 2,
    low: 3,
    unknown: 4,
  };

  return confidenceOrder[normalizeConfidence(confidence)] ?? 99;
}

/**
 * Returns the more severe of two severities.
 */
export function getMoreSevereSeverity(a, b) {
  return getSeverityRank(a) <= getSeverityRank(b) ? a : b;
}

/**
 * Returns the higher confidence value.
 */
export function getHigherConfidence(a, b) {
  return getConfidenceRank(a) <= getConfidenceRank(b) ? a : b;
}

/**
 * Groups Semgrep findings by policy section, then by rule.
 */
export function groupSemgrepFindingsBySection(findings) {
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