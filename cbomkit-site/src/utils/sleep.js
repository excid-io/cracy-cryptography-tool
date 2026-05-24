/**
 * Waits for a given number of milliseconds.
 *
 * If an AbortSignal is provided, the wait can be cancelled. This is used by the
 * CBOM polling loop so pressing Cancel stops the delay immediately instead of
 * waiting for the timeout to finish.
*/
export function sleep(ms, signal) {
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