import {
  HTTP_API_BASE,
  getOpaEndpoint,
  getSemgrepEndpoint,
} from "./config/endpoints.js";

import {
  buildCbomScanRequest,
  buildSemgrepScanRequest,
  recordMatchesScanUrl,
} from "./utils/urls.js";

import { sleep } from "./utils/sleep.js";

import {
  extractImportantFindings,
  groupRegoFindings,
} from "./utils/regoFindings.js";

import {
  getSemgrepFindings,
  groupSemgrepFindingsBySection,
} from "./utils/semgrepFindings.js";

const elements = {
  darkModeToggle: document.getElementById("darkModeToggle"),
  form: document.getElementById("complianceForm"),
  repoUrl: document.getElementById("repoUrl"),
  scanPath: document.getElementById("scanPath"),
  branch: document.getElementById("branch"),
  commit: document.getElementById("commit"),
  pat: document.getElementById("pat"),
  checkButton: document.getElementById("checkButton"),
  resetButton: document.getElementById("resetButton"),
  status: document.getElementById("status"),
  errorBox: document.getElementById("errorBox"),
  results: document.getElementById("results"),
  summary: document.getElementById("summary"),
  regoResults: document.getElementById("regoResults"),
  semgrepResults: document.getElementById("semgrepResults"),
};

let abortController = null;

function getInitialTheme() {
  const savedTheme = window.localStorage.getItem("cra-compliance-theme");

  if (savedTheme === "dark") return true;
  if (savedTheme === "light") return false;

  return window.matchMedia?.("(prefers-color-scheme: dark)").matches ?? false;
}

function applyTheme(isDark) {
  document.documentElement.dataset.theme = isDark ? "dark" : "light";

  if (elements.darkModeToggle) {
    elements.darkModeToggle.checked = isDark;
  }

  window.localStorage.setItem("cra-compliance-theme", isDark ? "dark" : "light");
}

function setStatus(message) {
  elements.status.textContent = `Status: ${message}`;
}

function showError(message) {
  elements.errorBox.hidden = false;
  elements.errorBox.textContent = message;
}

function clearError() {
  elements.errorBox.hidden = true;
  elements.errorBox.textContent = "";
}

function clearResults() {
  elements.results.hidden = true;
  elements.summary.innerHTML = "";
  elements.regoResults.innerHTML = "";
  elements.semgrepResults.innerHTML = "";
}

function setBusy(isBusy) {
  elements.checkButton.disabled = isBusy;
  elements.resetButton.disabled = isBusy;
  elements.checkButton.textContent = isBusy ? "Checking..." : "Check compliance";
}

function makeErrorMessage(error) {
  if (!error) return "Unknown error.";

  if (error instanceof DOMException && error.name === "AbortError") {
    return "The compliance check was cancelled.";
  }

  if (error instanceof Error) return error.message;

  return String(error);
}

async function submitCbomScan({ form, signal }) {
  const scanRequest = buildCbomScanRequest(form);

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

    if (matches[0]?.bom) {
      return matches[0].bom;
    }

    setStatus(`Waiting for new CBOM... ${attempt}/${maxAttempts}`);

    await sleep(delayMs, signal);
  }

  throw new Error("Timed out waiting for a newly generated CBOM.");
}

async function generateCbom({ form, signal }) {
  setStatus("Submitting CBOM scan...");

  const scanStartedAt = Date.now();
  const scanRequest = await submitCbomScan({ form, signal });

  setStatus("Scan accepted. Waiting for CBOM...");

  return pollForCbom({
    scanUrl: scanRequest.scanUrl,
    scanStartedAt,
    signal,
  });
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

async function evaluateRegoPolicy({ cbom, signal }) {
  if (!cbom) {
    throw new Error("No CBOM is available to evaluate.");
  }

  setStatus("Evaluating REGO policy...");

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

  if (!response.ok) {
    const details = formatOpaErrors(body, responseText);

    throw new Error(
      details || `OPA policy evaluation failed with HTTP ${response.status}.`
    );
  }

  return body;
}

async function runSemgrep({ form, signal }) {
  setStatus("Running Semgrep evaluation...");

  const response = await fetch(getSemgrepEndpoint(), {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(buildSemgrepScanRequest(form)),
    signal,
  });

  const body = await response.json().catch(() => null);

  if (!response.ok || body?.ok === false) {
    throw new Error(
      body?.error || `Semgrep scan failed with HTTP ${response.status}.`
    );
  }

  return body;
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function getSeverityClass(severity) {
  const normalized = String(severity || "").trim().toLowerCase();

  if (["critical", "error", "high"].includes(normalized)) {
    return "badge badge--danger";
  }

  if (["medium", "warning"].includes(normalized)) {
    return "badge badge--warning";
  }

  return "badge badge--ok";
}

function formatReference(reference) {
  const location = reference.location || reference.path || "Unknown file";
  const line = reference.line ? `:${reference.line}` : "";
  const column = reference.column ? `:${reference.column}` : "";

  return `${location}${line}${column}`;
}

function countSeverities(findings) {
  const counts = {
    critical: 0,
    high: 0,
    medium: 0,
    warning: 0,
    low: 0,
    other: 0,
  };

  for (const finding of findings) {
    const severity = String(finding.severity || "").trim().toLowerCase();

    if (severity === "critical" || severity === "error") {
      counts.critical += 1;
    } else if (severity === "high") {
      counts.high += 1;
    } else if (severity === "medium") {
      counts.medium += 1;
    } else if (severity === "warning") {
      counts.warning += 1;
    } else if (severity === "low") {
      counts.low += 1;
    } else {
      counts.other += 1;
    }
  }

  return counts;
}

function renderSeverityPills(counts) {
  const wrapper = document.createElement("div");
  wrapper.className = "severity-pills";

  const pills = [
    ["critical", counts.critical],
    ["high", counts.high],
    ["medium", counts.medium],
    ["warning", counts.warning],
    ["low", counts.low],
    ["other", counts.other],
  ];

  for (const [severity, count] of pills) {
    if (count === 0) continue;

    const pill = document.createElement("span");
    pill.className = `severity-pill severity-pill--${severity}`;
    pill.textContent = `${count} ${severity}`;
    wrapper.appendChild(pill);
  }

  return wrapper;
}

function renderGroupedFindings(container, title, groups) {
  container.innerHTML = "";

  const section = document.createElement("section");
  section.className = "finding-panel";

  const headingRow = document.createElement("div");
  headingRow.className = "finding-panel__header";

  const heading = document.createElement("h3");
  heading.textContent = title;
  headingRow.appendChild(heading);

  const total = groups.reduce((sum, group) => sum + group.findings.length, 0);

  const totalBadge = document.createElement("span");
  totalBadge.className = "finding-panel__total";
  totalBadge.textContent = `${total} finding${total === 1 ? "" : "s"}`;
  headingRow.appendChild(totalBadge);

  section.appendChild(headingRow);

  if (!groups.length) {
    const empty = document.createElement("p");
    empty.className = "empty-state";
    empty.textContent = "No findings returned.";
    section.appendChild(empty);
    container.appendChild(section);
    return;
  }

  const groupList = document.createElement("div");
  groupList.className = "finding-group-list";

  for (const group of groups) {
    const counts = countSeverities(group.findings);

    const details = document.createElement("details");
    details.className = "finding-accordion";

    const summary = document.createElement("summary");
    summary.className = "finding-accordion__summary";

    const left = document.createElement("div");
    left.className = "finding-accordion__left";

    const groupTitle = document.createElement("strong");
    groupTitle.className = "finding-accordion__title";
    groupTitle.textContent = group.title;
    left.appendChild(groupTitle);

    const meta = document.createElement("span");
    meta.className = "finding-accordion__meta";
    meta.textContent = `${group.findings.length} finding${
      group.findings.length === 1 ? "" : "s"
    }`;
    left.appendChild(meta);

    const right = document.createElement("div");
    right.className = "finding-accordion__right";
    right.appendChild(renderSeverityPills(counts));

    summary.appendChild(left);
    summary.appendChild(right);
    details.appendChild(summary);

    const cards = document.createElement("div");
    cards.className = "finding-card-list";

    for (const finding of group.findings) {
      const card = document.createElement("article");
      card.className = "finding-card";

      const cardHeader = document.createElement("div");
      cardHeader.className = "finding-card__header";

      const findingTitle = document.createElement("strong");
      findingTitle.className = "finding-card__title";
      findingTitle.textContent = finding.title || finding.ruleId || "Finding";
      cardHeader.appendChild(findingTitle);

      if (finding.severity) {
        const badge = document.createElement("span");
        badge.className = getSeverityClass(finding.severity);
        badge.textContent = String(finding.severity).toUpperCase();
        cardHeader.appendChild(badge);
      }

      card.appendChild(cardHeader);

      const metaItems = [];

      if (finding.ruleId) {
        metaItems.push(`Rule: ${finding.ruleId}`);
      }

      if (finding.location) {
        metaItems.push(`Location: ${finding.location}`);
      }

      if (metaItems.length > 0) {
        const cardMeta = document.createElement("div");
        cardMeta.className = "finding-card__meta";
        cardMeta.textContent = metaItems.join(" · ");
        card.appendChild(cardMeta);
      }

      if (finding.message) {
        const message = document.createElement("p");
        message.className = "finding-card__message";
        message.textContent = finding.message;
        card.appendChild(message);
      }

      if (Array.isArray(finding.references) && finding.references.length > 0) {
        const references = document.createElement("details");
        references.className = "finding-card__references";

        const referencesSummary = document.createElement("summary");
        referencesSummary.textContent = `${finding.references.length} reference${
          finding.references.length === 1 ? "" : "s"
        }`;
        references.appendChild(referencesSummary);

        const referencesList = document.createElement("ul");

        for (const reference of finding.references) {
          const referenceItem = document.createElement("li");
          referenceItem.textContent = formatReference(reference);
          referencesList.appendChild(referenceItem);
        }

        references.appendChild(referencesList);
        card.appendChild(references);
      }

      cards.appendChild(card);
    }

    details.appendChild(cards);
    groupList.appendChild(details);
  }

  section.appendChild(groupList);
  container.appendChild(section);
}

function renderSummary({ regoFindings, semgrepFindings }) {
  const totalFindings = regoFindings.length + semgrepFindings.length;

  elements.summary.innerHTML = `
    <div class="summary-card">
      <strong>${escapeHtml(totalFindings)}</strong>
      <span>Total findings</span>
    </div>
    <div class="summary-card">
      <strong>${escapeHtml(regoFindings.length)}</strong>
      <span>REGO findings</span>
    </div>
    <div class="summary-card">
      <strong>${escapeHtml(semgrepFindings.length)}</strong>
      <span>Semgrep findings</span>
    </div>
  `;
}

function renderResults({ policyResult, semgrepResult }) {
  const regoFindings = extractImportantFindings(policyResult);
  const groupedRegoFindings = groupRegoFindings(regoFindings);

  const semgrepFindings = getSemgrepFindings(semgrepResult);
  const groupedSemgrepFindings =
    groupSemgrepFindingsBySection(semgrepFindings);

  elements.results.hidden = false;

  renderSummary({
    regoFindings,
    semgrepFindings,
  });

  renderGroupedFindings(
    elements.regoResults,
    "REGO findings",
    groupedRegoFindings
  );

  renderGroupedFindings(
    elements.semgrepResults,
    "Semgrep findings",
    groupedSemgrepFindings
  );
}

function getFormValues() {
  return {
    url: elements.repoUrl.value.trim(),
    scanPath: elements.scanPath.value.trim(),
    branch: elements.branch.value.trim(),
    commit: elements.commit.value.trim(),
    pat: elements.pat.value.trim(),
  };
}

async function handleComplianceCheck(event) {
  event.preventDefault();

  clearError();
  clearResults();

  const form = getFormValues();

  if (!form.url) {
    showError("Enter a Git URL first.");
    return;
  }

  abortController?.abort();
  abortController = new AbortController();

  setBusy(true);

  try {
    const cbom = await generateCbom({
      form,
      signal: abortController.signal,
    });

    const policyResult = await evaluateRegoPolicy({
      cbom,
      signal: abortController.signal,
    });

    const semgrepResult = await runSemgrep({
      form,
      signal: abortController.signal,
    });

    renderResults({
      policyResult,
      semgrepResult,
    });

    setStatus("Compliance check finished");
  } catch (error) {
    setStatus("Compliance check failed");
    showError(makeErrorMessage(error));
  } finally {
    abortController = null;
    setBusy(false);
  }
}

function resetForm() {
  abortController?.abort();
  abortController = null;

  elements.form.reset();
  clearError();
  clearResults();
  setStatus("Ready");
  setBusy(false);
}

elements.darkModeToggle.addEventListener("change", (event) => {
  applyTheme(event.target.checked);
});

elements.form.addEventListener("submit", handleComplianceCheck);
elements.resetButton.addEventListener("click", resetForm);

applyTheme(getInitialTheme());