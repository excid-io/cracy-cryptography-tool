#!/usr/bin/env python3

import json
import sys
from pathlib import Path


def main() -> int:
    if len(sys.argv) != 2:
        print("Usage: evaluate_compliance.py <section>", file=sys.stderr)
        return 2

    section = sys.argv[1]

    findings = json.loads(
        Path(f"results/{section}-findings.json").read_text()
    )

    compliant = len(findings) == 0

    Path(f"results/{section}-compliant.txt").write_text(
        "true\n" if compliant else "false\n"
    )

    print(f"Finding count: {len(findings)}")
    print("Compliant:")
    print("true" if compliant else "false")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())