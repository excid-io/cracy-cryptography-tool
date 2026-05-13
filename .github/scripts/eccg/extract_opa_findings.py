#!/usr/bin/env python3

import json
import sys
from pathlib import Path


def main() -> int:
    if len(sys.argv) != 3:
        print(
            "Usage: extract_opa_findings.py <safe-name> <raw-json-path>",
            file=sys.stderr,
        )
        return 2

    safe_name = sys.argv[1]
    raw_path = Path(sys.argv[2])
    out_path = Path(f"results/tmp/{safe_name}.json")

    raw = json.loads(raw_path.read_text())

    if "result" not in raw or not raw["result"]:
        print(f"OPA query returned no result for {safe_name}.", file=sys.stderr)
        print("This usually means the data path/package name is wrong.", file=sys.stderr)
        print(json.dumps(raw, indent=2), file=sys.stderr)
        return 1

    try:
        value = raw["result"][0]["expressions"][0]["value"]
    except (KeyError, IndexError) as exc:
        print(f"Could not extract findings for {safe_name}.", file=sys.stderr)
        print(json.dumps(raw, indent=2), file=sys.stderr)
        raise SystemExit(1) from exc

    if not isinstance(value, list):
        print(
            f"Expected findings list for {safe_name}, got {type(value).__name__}.",
            file=sys.stderr,
        )
        print(json.dumps(value, indent=2), file=sys.stderr)
        return 1

    out_path.write_text(json.dumps(value, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())