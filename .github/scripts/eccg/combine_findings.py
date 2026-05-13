#!/usr/bin/env python3

import json
import sys
from pathlib import Path


def main() -> int:
    if len(sys.argv) != 2:
        print("Usage: combine_findings.py <section>", file=sys.stderr)
        return 2

    section = sys.argv[1]

    combined = []
    for path in sorted(Path("results/tmp").glob("*.json")):
        if path.name.endswith(".raw.json"):
            continue

        value = json.loads(path.read_text())
        if isinstance(value, list):
            combined.extend(value)
        else:
            print(f"Skipping non-list findings file: {path}", file=sys.stderr)

    out = Path(f"results/{section}-findings.json")
    out.write_text(json.dumps(combined, indent=2) + "\n")

    print("Combined findings:")
    print(out.read_text(), end="")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())