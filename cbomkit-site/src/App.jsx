import React, { useRef, useState } from "react";

const HTTP_API_BASE =
  import.meta.env.VITE_CBOMKIT_HTTP_API_BASE || "http://localhost:8081";

const POLICY_API_BASE = import.meta.env.VITE_POLICY_API_BASE || "/opa";

const OPA_DECISION_PATH =
  import.meta.env.VITE_OPA_DECISION_PATH || "/v1/data/cbom/eccg";

const IMPORTANT_SEVERITIES = new Set(["high", "critical"]);

function normalizeScanUrl(value) {
  let scanUrl = value.trim();

  if (!scanUrl.startsWith("pkg:")) {
    scanUrl = scanUrl
      .replace(/^scm:git:git:\/\//, "")
      .replace(/\.git$/, "");

    if (!scanUrl.includes("://")) {
      scanUrl = `https://${scanUrl}`;
    }
  }

  return scanUrl;
}

function buildScanRequest({ url, scanPath, pat }) {
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

function isBusyStatus(status) {
  return (
    status.startsWith("Submitting") ||
    status.startsWith("Scan accepted") ||
    status.startsWith("Waiting") ||
    status.startsWith("Evaluating")
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
      const algorithm =
        getStringValue(value, [
          "algorithm",
          "algorithmName",
          "algorithm_name",
          "primitive",
          "primitiveName",
          "primitive_name",
          "name",
          "title",
          "id",
        ]) || path.filter(Boolean).slice(-2).join(" / ");

      const info =
        getStringValue(value, [
          "info",
          "message",
          "msg",
          "description",
          "details",
          "reason",
          "note",
        ]) || "No info message provided.";

      findings.push({
        algorithm,
        info,
        severity,
      });
    }

    for (const [key, child] of Object.entries(value)) {
      visit(child, [...path, key]);
    }
  }

  visit(root);

  const seen = new Set();

  return findings.filter((finding) => {
    const key = `${finding.severity}|${finding.algorithm}|${finding.info}`;

    if (seen.has(key)) {
      return false;
    }

    seen.add(key);
    return true;
  });
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

export default function CbomkitSimpleScanner() {
  const [url, setUrl] = useState("");
  const [scanPath, setScanPath] = useState("");
  const [pat, setPat] = useState("");
  const [status, setStatus] = useState("Ready");
  const [error, setError] = useState("");
  const [cbom, setCbom] = useState(null);
  const [policyResult, setPolicyResult] = useState(null);
  const [policyError, setPolicyError] = useState("");
  const [darkMode, setDarkMode] = useState(false);

  const abortControllerRef = useRef(null);

  const theme = darkMode ? darkTheme : lightTheme;
  const busy = isBusyStatus(status);
  const opaEndpoint = getOpaEndpoint();
  const importantFindings = extractImportantFindings(policyResult);

  async function startScan() {
    abortControllerRef.current?.abort();

    const controller = new AbortController();
    abortControllerRef.current = controller;

    setError("");
    setPolicyError("");
    setCbom(null);
    setPolicyResult(null);

    if (!url.trim()) {
      setError("Enter a URL first.");
      abortControllerRef.current = null;
      return;
    }

    try {
      setStatus("Submitting scan...");

      const scanStartedAt = Date.now();
      const scanRequest = buildScanRequest({ url, scanPath, pat });

      const response = await fetch(`${HTTP_API_BASE}/api/v1/scan`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(scanRequest),
        signal: controller.signal,
      });

      if (response.status !== 202 && !response.ok) {
        const body = await response.text().catch(() => "");
        throw new Error(
          body || `Scan request failed with HTTP ${response.status}.`
        );
      }

      setStatus("Scan accepted. Waiting for new CBOM...");

      const generatedCbom = await pollForCbom({
        scanUrl: scanRequest.scanUrl,
        scanStartedAt,
        signal: controller.signal,
      });

      setCbom(generatedCbom);
      setStatus("Evaluating policy...");

      await evaluatePolicy(generatedCbom, controller.signal);

      setStatus("Finished");
    } catch (err) {
      if (err instanceof DOMException && err.name === "AbortError") {
        setStatus("Cancelled");
        return;
      }

      setStatus("Error");
      setError(err instanceof Error ? err.message : "Scan failed.");
    } finally {
      if (abortControllerRef.current === controller) {
        abortControllerRef.current = null;
      }
    }
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
    setPolicyResult(null);

    if (!cbomToEvaluate) {
      setPolicyError("No CBOM is available to evaluate.");
      return;
    }

    try {
      setStatus("Evaluating policy...");

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

      const body = await response.json().catch(() => null);

      if (!response.ok) {
        throw new Error(
          body?.message ||
            body?.error ||
            `OPA policy evaluation failed with HTTP ${response.status}.`
        );
      }

      setPolicyResult(body);
      setStatus("Finished");
    } catch (err) {
      if (err instanceof DOMException && err.name === "AbortError") {
        setStatus("Cancelled");
        return;
      }

      setPolicyError(
        err instanceof Error ? err.message : "Policy evaluation failed."
      );
      setStatus("Policy evaluation failed");
    }
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
    setPat("");
    setStatus("Ready");
    setError("");
    setPolicyError("");
    setCbom(null);
    setPolicyResult(null);
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
            <h1 style={{ ...styles.title, color: theme.title }}>CBOM scan</h1>

            <p style={{ ...styles.subtitle, color: theme.muted }}>
              REST scan using CBOMkit backend at
            </p>

            <div
              style={{
                ...styles.apiBadge,
                background: theme.badgeBg,
                color: theme.badgeText,
                borderColor: theme.badgeBorder,
              }}
              title={HTTP_API_BASE}
            >
              {HTTP_API_BASE}
            </div>

            <p style={{ ...styles.subtitle, color: theme.muted }}>
              OPA policy endpoint
            </p>

            <div
              style={{
                ...styles.apiBadge,
                background: theme.badgeBg,
                color: theme.badgeText,
                borderColor: theme.badgeBorder,
              }}
              title={opaEndpoint}
            >
              {opaEndpoint}
            </div>
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
          label="URL"
          placeholder="https://github.com/org/repo"
          value={url}
          onChange={setUrl}
          theme={theme}
        />

        <Field
          label="Scan path"
          placeholder="Optional, e.g. frontend"
          value={scanPath}
          onChange={setScanPath}
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
        {policyError && <p style={styles.error}>{policyError}</p>}

        <div style={styles.buttonRow}>
          <button
            onClick={startScan}
            disabled={busy}
            style={{
              ...styles.primaryButton,
              background: theme.primaryBg,
              color: theme.primaryText,
              opacity: busy ? 0.7 : 1,
              cursor: busy ? "not-allowed" : "pointer",
            }}
          >
            {busy ? "Working..." : "Scan + Evaluate"}
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

          {cbom && (
            <button
              onClick={() => evaluatePolicy(cbom)}
              disabled={busy}
              style={{
                ...styles.secondaryButton,
                borderColor: theme.border,
                color: theme.text,
                opacity: busy ? 0.7 : 1,
                cursor: busy ? "not-allowed" : "pointer",
              }}
            >
              Evaluate Policy
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
              Download Policy Result
            </button>
          )}
        </div>

        <p style={{ ...styles.status, color: theme.muted }}>Status: {status}</p>

        {policyResult && (
          <section
            style={{
              ...styles.resultBox,
              background: theme.resultBg,
              borderColor: theme.border,
            }}
          >
            <h2 style={{ ...styles.resultTitle, color: theme.title }}>
              High and critical findings
            </h2>

            <p style={{ ...styles.resultSummary, color: theme.muted }}>
              {importantFindings.length === 0
                ? "No high or critical policy findings were returned."
                : `${importantFindings.length} high/critical finding${
                    importantFindings.length === 1 ? "" : "s"
                  } returned.`}
            </p>

            {importantFindings.length > 0 && (
              <div style={styles.findingsList}>
                {importantFindings.map((finding, index) => (
                  <article
                    key={`${finding.severity}-${finding.algorithm}-${index}`}
                    style={{
                      ...styles.findingCard,
                      background: theme.findingBg,
                      borderColor: theme.border,
                    }}
                  >
                    <div style={styles.findingHeader}>
                      <strong
                        style={{
                          ...styles.findingAlgorithm,
                          color: theme.title,
                        }}
                      >
                        {finding.algorithm}
                      </strong>

                      <span
                        style={{
                          ...styles.severityBadge,
                          background:
                            finding.severity === "critical"
                              ? theme.criticalBg
                              : theme.highBg,
                          color:
                            finding.severity === "critical"
                              ? theme.criticalText
                              : theme.highText,
                          borderColor:
                            finding.severity === "critical"
                              ? theme.criticalBorder
                              : theme.highBorder,
                        }}
                      >
                        {finding.severity}
                      </span>
                    </div>

                    <p style={{ ...styles.findingInfo, color: theme.text }}>
                      {finding.info}
                    </p>
                  </article>
                ))}
              </div>
            )}
          </section>
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
  dangerBg: "#fef2f2",
  dangerText: "#991b1b",
  dangerBorder: "#fecaca",
  highBg: "#fff7ed",
  highText: "#9a3412",
  highBorder: "#fed7aa",
  criticalBg: "#fef2f2",
  criticalText: "#991b1b",
  criticalBorder: "#fecaca",
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
  dangerBg: "#450a0a",
  dangerText: "#fecaca",
  dangerBorder: "#7f1d1d",
  highBg: "#431407",
  highText: "#fed7aa",
  highBorder: "#9a3412",
  criticalBg: "#450a0a",
  criticalText: "#fecaca",
  criticalBorder: "#991b1b",
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
    maxWidth: 760,
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
    textAlign: "center",
  },
  subtitle: {
    margin: "14px 0 6px",
    fontSize: 14,
    textAlign: "center",
  },
  apiBadge: {
    display: "block",
    width: "fit-content",
    maxWidth: "100%",
    margin: "0 auto",
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
    textAlign: "center",
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
  },
  resultSummary: {
    margin: "8px 0 12px",
    fontSize: 14,
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
    alignItems: "center",
    justifyContent: "space-between",
    gap: 12,
    marginBottom: 8,
  },
  findingAlgorithm: {
    fontSize: 15,
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
  findingInfo: {
    margin: 0,
    fontSize: 14,
    lineHeight: 1.5,
    overflowWrap: "anywhere",
  },
};