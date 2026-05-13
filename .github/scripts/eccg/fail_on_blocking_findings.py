#!/usr/bin/env python3

import json
import sys
from pathlib import Path


BLOCKING_SEVERITIES = {"high", "critical"}


def main() -> int:
    if len(sys.argv) != 2:
        print("Usage: fail_on_blocking_findings.py <section>", file=sys.stderr)
        return 2

    section = sys.argv[1]

    findings = json.loads(
        Path(f"results/{section}-findings.json").read_text()
    )

    blocking_findings = [
        finding for finding in findings
        if finding.get("severity") in BLOCKING_SEVERITIES
    ]

    print(f"Blocking severities: {sorted(BLOCKING_SEVERITIES)}")
    print(f"Blocking findings: {len(blocking_findings)}")

    if blocking_findings:
        print("Blocking ECCG findings:")
        print(json.dumps(blocking_findings, indent=2))

        print("ECCG policy evaluation failed because blocking findings were detected.")
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())