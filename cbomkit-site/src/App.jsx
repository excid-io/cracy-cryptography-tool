import { useState } from "react";
import "./App.css";

import { Field } from "./components/Field";
import { FindingGroups } from "./components/FindingGroups";
import { useCbomScanner } from "./hooks/useCbomScanner";
import { extractImportantFindings, groupRegoFindings } from "./utils/findings";
import {
  getSemgrepFindings,
  groupSemgrepFindingsBySection,
} from "./utils/semgrepFindings";
import { lightTheme, darkTheme } from "./styles/themes";
import { styles } from "./styles/styles";

/**
 * Downloads a JSON value as a local file.
 */
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

/**
 * Main scanner UI.
 */
export default function App() {
  const [url, setUrl] = useState("");
  const [scanPath, setScanPath] = useState("");
  const [branch, setBranch] = useState("");
  const [commit, setCommit] = useState("");
  const [pat, setPat] = useState("");
  const [darkMode, setDarkMode] = useState(false);
  const [formError, setFormError] = useState("");

  const scanner = useCbomScanner();

  const theme = darkMode ? darkTheme : lightTheme;

  const importantFindings = extractImportantFindings(scanner.policyResult);
  const groupedRegoFindings = groupRegoFindings(importantFindings);

  const semgrepFindings = getSemgrepFindings(scanner.semgrepResult);
  const groupedSemgrepFindings = groupSemgrepFindingsBySection(semgrepFindings);

  const form = {
    url,
    scanPath,
    branch,
    commit,
    pat,
  };

  function requireUrl() {
    if (!url.trim()) {
      setFormError("Enter a URL first.");
      return false;
    }

    setFormError("");
    return true;
  }

  async function handleGenerateCbom() {
    if (!requireUrl()) return;

    await scanner.generateCbomOnly(form);
  }

  async function handleRegoEvaluation() {
    if (!requireUrl()) return;

    await scanner.runRego(form);
  }

  async function handleSemgrepEvaluation() {
    if (!requireUrl()) return;

    await scanner.runSemgrep(form);
  }

  function resetForm() {
    setUrl("");
    setScanPath("");
    setBranch("");
    setCommit("");
    setPat("");
    setFormError("");
    scanner.resetScannerState();
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

        {formError && <p style={styles.error}>{formError}</p>}
        {scanner.error && <p style={styles.error}>{scanner.error}</p>}
        {scanner.semgrepError && <p style={styles.error}>{scanner.semgrepError}</p>}

        {scanner.policyError && (
          <section
            style={{
              ...styles.errorPanel,
              background: theme.dangerBg,
              borderColor: theme.dangerBorder,
              color: theme.dangerText,
            }}
          >
            <h2 style={styles.errorPanelTitle}>REGO evaluation failed</h2>

            <p style={styles.errorPanelMessage}>{scanner.policyError}</p>

            {scanner.policyErrorDetails && (
              <pre
                style={{
                  ...styles.errorDetails,
                  background: theme.errorDetailsBg,
                  borderColor: theme.dangerBorder,
                  color: theme.dangerText,
                }}
              >
                {scanner.policyErrorDetails}
              </pre>
            )}
          </section>
        )}

        <div style={styles.buttonRow}>
          <button
            onClick={handleGenerateCbom}
            disabled={scanner.busy}
            style={{
              ...styles.primaryButton,
              background: theme.primaryBg,
              color: theme.primaryText,
              opacity: scanner.busy ? 0.7 : 1,
              cursor: scanner.busy ? "not-allowed" : "pointer",
            }}
          >
            Generate CBOM
          </button>

          <button
            onClick={handleRegoEvaluation}
            disabled={scanner.busy}
            style={{
              ...styles.secondaryButton,
              borderColor: theme.border,
              color: theme.text,
              opacity: scanner.busy ? 0.7 : 1,
              cursor: scanner.busy ? "not-allowed" : "pointer",
            }}
          >
            REGO Evaluation
          </button>

          <button
            onClick={handleSemgrepEvaluation}
            disabled={scanner.busy}
            style={{
              ...styles.secondaryButton,
              borderColor: theme.border,
              color: theme.text,
              opacity: scanner.busy ? 0.7 : 1,
              cursor: scanner.busy ? "not-allowed" : "pointer",
            }}
          >
            Semgrep Evaluation
          </button>

          {scanner.busy && (
            <button
              onClick={scanner.cancelProcess}
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
            disabled={scanner.busy}
            style={{
              ...styles.secondaryButton,
              borderColor: theme.border,
              color: theme.text,
              opacity: scanner.busy ? 0.7 : 1,
              cursor: scanner.busy ? "not-allowed" : "pointer",
            }}
          >
            Reset
          </button>

          {scanner.cbom && (
            <button
              onClick={() => downloadJson("cbom.json", scanner.cbom)}
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

          {scanner.policyResult && (
            <button
              onClick={() =>
                downloadJson("policy-evaluation.json", scanner.policyResult)
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

          {scanner.semgrepResult && (
            <button
              onClick={() =>
                downloadJson("semgrep-result.json", scanner.semgrepResult)
              }
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

        <p style={{ ...styles.status, color: theme.muted }}>
          Status: {scanner.status}
        </p>

        {scanner.semgrepResult && (
          <FindingGroups
            title="Semgrep findings"
            emptyText="No Semgrep findings were returned."
            resultText={`${semgrepFindings.length} finding${
              semgrepFindings.length === 1 ? "" : "s"
            } across ${groupedSemgrepFindings.length} group${
              groupedSemgrepFindings.length === 1 ? "" : "s"
            }.`}
            groups={groupedSemgrepFindings}
            theme={theme}
            showFindingConfidence={false}
          />
        )}

        {scanner.policyResult && (
          <FindingGroups
            title="REGO findings"
            emptyText="No REGO findings were returned."
            resultText={`${importantFindings.length} finding${
              importantFindings.length === 1 ? "" : "s"
            } across ${groupedRegoFindings.length} group${
              groupedRegoFindings.length === 1 ? "" : "s"
            }.`}
            groups={groupedRegoFindings}
            theme={theme}
            showFindingConfidence={false}
          />
        )}
      </section>
    </main>
  );
}