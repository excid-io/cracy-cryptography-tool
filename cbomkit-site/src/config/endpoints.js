export const HTTP_API_BASE =
  import.meta.env.VITE_CBOMKIT_HTTP_API_BASE || "http://localhost:8081";

export const SEMGREP_API_BASE =
  import.meta.env.VITE_SEMGREP_API_BASE || "http://localhost:9091";

export const POLICY_API_BASE = import.meta.env.VITE_POLICY_API_BASE || "/opa";

export const OPA_DECISION_PATH =
  import.meta.env.VITE_OPA_DECISION_PATH || "/v1/data/cbom/eccg";

export function getOpaEndpoint() {
  const base = POLICY_API_BASE.replace(/\/$/, "");
  const path = OPA_DECISION_PATH.startsWith("/")
    ? OPA_DECISION_PATH
    : `/${OPA_DECISION_PATH}`;

  return `${base}${path}`;
}

export function getSemgrepEndpoint() {
  return `${SEMGREP_API_BASE.replace(/\/$/, "")}/scan`;
}