import { useRef, useState } from "react";
import { generateCbom } from "../api/cbomApi";
import { evaluatePolicy } from "../api/opaApi";
import { runSemgrepScan } from "../api/semgrepApi";

/**
 * Converts an unknown error object into a displayable error-details string.
 *
 * Some errors thrown by the API layer include a custom `details` field with
 * more useful diagnostic information. If that field exists, it is preferred.
 * Otherwise, normal Error objects use their `.message`, and non-Error values
 * are converted to strings.
 */
function makeErrorDetails(error) {
  if (!error) return "";
  if (error.details) return error.details;
  return error instanceof Error ? error.message : String(error);
}

/**
 * Determines whether the current status represents an active operation.
 *
 * The UI uses this to disable buttons while CBOM generation, REGO evaluation,
 * or Semgrep evaluation is running.
 */
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

/**
 * React hook that owns all scanner state and actions.
 *
 * This hook centralizes:
 * - CBOM generation state
 * - REGO evaluation state
 * - Semgrep evaluation state
 * - cancellation with AbortController
 * - status and error handling
 *
 * The UI component can call this hook and focus mostly on rendering.
 */
export function useCbomScanner() {
  /**
   * Human-readable scanner status shown in the UI.
   */
  const [status, setStatus] = useState("Ready");

  /**
   * General CBOM-generation error.
   */
  const [error, setError] = useState("");

  /**
   * Last generated CBOM object.
   */
  const [cbom, setCbom] = useState(null);

  /**
   * Raw OPA / REGO evaluation response.
   */
  const [policyResult, setPolicyResult] = useState(null);

  /**
   * Short REGO evaluation error message.
   */
  const [policyError, setPolicyError] = useState("");

  /**
   * Detailed REGO evaluation error information, usually from OPA.
   */
  const [policyErrorDetails, setPolicyErrorDetails] = useState("");

  /**
   * Raw Semgrep scan response.
   */
  const [semgrepResult, setSemgrepResult] = useState(null);

  /**
   * Semgrep evaluation error message.
   */
  const [semgrepError, setSemgrepError] = useState("");

  /**
   * Stores the currently running operation's AbortController.
   *
   * This allows:
   * - cancelling a running operation
   * - aborting a previous operation when a new one starts
   * - preventing stale requests from updating state after cancellation
   */
  const abortControllerRef = useRef(null);

  /**
   * True when the current status indicates that an async scan/evaluation is
   * currently running.
   */
  const busy = isBusyStatus(status);

  /**
   * Starts a new controlled async operation.
   *
   * Any previous operation is aborted before the new one starts. A fresh
   * AbortController is created and stored so that the new operation can be
   * cancelled later.
   */
  function startControlledRun() {
    abortControllerRef.current?.abort();

    const controller = new AbortController();
    abortControllerRef.current = controller;

    setError("");

    return controller;
  }

  /**
   * Clears the active AbortController after an operation finishes.
   *
   * The identity check prevents an older operation from clearing the controller
   * for a newer operation that may have started after it.
   */
  function finishControlledRun(controller) {
    if (abortControllerRef.current === controller) {
      abortControllerRef.current = null;
    }
  }

  /**
   * Clears REGO-specific state.
   */
  function clearRegoState() {
    setPolicyResult(null);
    setPolicyError("");
    setPolicyErrorDetails("");
  }

  /**
   * Clears Semgrep-specific state.
   */
  function clearSemgrepState() {
    setSemgrepResult(null);
    setSemgrepError("");
  }

  /**
   * Clears all evaluation results while leaving the form state outside this hook
   * untouched.
   */
  function clearEvaluationState() {
    clearRegoState();
    clearSemgrepState();
  }

  /**
   * Cancels the currently running operation.
   *
   * This aborts the active request/polling flow through AbortController and
   * updates the UI status to `Cancelled`.
   */
  function cancelProcess() {
    abortControllerRef.current?.abort();
    abortControllerRef.current = null;
    setStatus("Cancelled");
  }

  /**
   * Generates a CBOM only, without running REGO or Semgrep evaluation.
   *
   * Expected `form` shape:
   *
   * {
   *   url: string,
   *   scanPath: string,
   *   pat: string
   * }
   *
   * Returns the generated CBOM object on success, or `null` on failure or
   * cancellation.
   */
  async function generateCbomOnly(form) {
    const controller = startControlledRun();

    clearEvaluationState();

    try {
      setCbom(null);
      setStatus("Generating CBOM...");

      const generatedCbom = await generateCbom({
        ...form,
        signal: controller.signal,
        onStatus: setStatus,
      });

      setCbom(generatedCbom);
      setStatus("CBOM generated");

      return generatedCbom;
    } catch (err) {
      if (err instanceof DOMException && err.name === "AbortError") {
        setStatus("Cancelled");
        return null;
      }

      setStatus("CBOM generation failed");
      setError(err instanceof Error ? err.message : "CBOM generation failed.");

      return null;
    } finally {
      finishControlledRun(controller);
    }
  }

  /**
   * Generates a CBOM and then evaluates it with the REGO policy.
   *
   * This flow always creates a fresh CBOM before evaluation so that the REGO
   * result corresponds to the latest scan request.
   *
   * Expected `form` shape:
   *
   * {
   *   url: string,
   *   scanPath: string,
   *   pat: string
   * }
   *
   * Returns the OPA response on success, or `null` on failure or cancellation.
   */
  async function runRego(form) {
    const controller = startControlledRun();

    clearSemgrepState();
    clearRegoState();

    try {
      setCbom(null);
      setStatus("Generating CBOM for REGO evaluation...");

      const generatedCbom = await generateCbom({
        ...form,
        signal: controller.signal,
        onStatus: setStatus,
      });

      setCbom(generatedCbom);

      console.log("Generated CBOM for REGO evaluation:", generatedCbom);

      setStatus("Evaluating REGO policy...");

      const result = await evaluatePolicy({
        cbom: generatedCbom,
        signal: controller.signal,
      });

      setPolicyResult(result);
      setStatus("REGO evaluation finished");

      return result;
    } catch (err) {
      if (err instanceof DOMException && err.name === "AbortError") {
        setStatus("Cancelled");
        return null;
      }

      const details = makeErrorDetails(err);

      setStatus("REGO evaluation failed");
      setPolicyError(
        err instanceof Error ? err.message : "REGO evaluation failed."
      );
      setPolicyErrorDetails(details);

      return null;
    } finally {
      finishControlledRun(controller);
    }
  }

  /**
   * Runs the Semgrep evaluation flow.
   *
   * Unlike REGO evaluation, this does not generate or require a CBOM. It sends
   * the repository information directly to the local Semgrep scan service.
   *
   * Expected `form` shape:
   *
   * {
   *   url: string,
   *   branch: string,
   *   commit: string,
   *   scanPath: string,
   *   pat: string
   * }
   *
   * Returns the Semgrep response on success, or `null` on failure or
   * cancellation.
   */
  async function runSemgrep(form) {
    const controller = startControlledRun();

    clearRegoState();
    clearSemgrepState();

    try {
      setStatus("Running Semgrep evaluation...");

      const result = await runSemgrepScan({
        ...form,
        signal: controller.signal,
      });

      setSemgrepResult(result);
      setStatus("Semgrep evaluation finished");

      return result;
    } catch (err) {
      if (err instanceof DOMException && err.name === "AbortError") {
        setStatus("Cancelled");
        return null;
      }

      setStatus("Semgrep evaluation failed");
      setSemgrepError(
        err instanceof Error ? err.message : "Semgrep evaluation failed."
      );

      return null;
    } finally {
      finishControlledRun(controller);
    }
  }

  /**
   * Resets scanner-owned state to its initial values.
   *
   * This cancels any running operation and clears generated CBOMs, REGO results,
   * Semgrep results, and all scanner errors.
   */
  function resetScannerState() {
    abortControllerRef.current?.abort();
    abortControllerRef.current = null;

    setStatus("Ready");
    setError("");
    setCbom(null);
    clearEvaluationState();
  }

  /**
   * Public API exposed to the React component.
   */
  return {
    status,
    error,
    cbom,
    policyResult,
    policyError,
    policyErrorDetails,
    semgrepResult,
    semgrepError,
    busy,
    generateCbomOnly,
    runRego,
    runSemgrep,
    cancelProcess,
    resetScannerState,
  };
}