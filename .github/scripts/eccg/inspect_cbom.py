#!/usr/bin/env python3

import json
import sys
from pathlib import Path


def main() -> int:
    if len(sys.argv) != 2:
        print("Usage: inspect_cbom.py <cbom-path>", file=sys.stderr)
        return 2

    path = Path(sys.argv[1])
    data = json.loads(path.read_text())

    components = data.get("components", [])

    print("CBOM component count:")
    print(len(components))

    print("CBOM component names:")
    for component in components:
        print(component.get("name", ""))

    print("CBOM components:")
    for component in components:
        algorithm = (
            component
            .get("cryptoProperties", {})
            .get("algorithmProperties", {})
        )

        print(json.dumps({
            "name": component.get("name"),
            "type": component.get("type"),
            "bom_ref": component.get("bom-ref"),
            "primitive": algorithm.get("primitive"),
            "parameterSetIdentifier": algorithm.get("parameterSetIdentifier"),
            "mode": algorithm.get("mode"),
            "padding": algorithm.get("padding"),
            "cryptoFunctions": algorithm.get("cryptoFunctions"),
            "evidence": component.get("evidence"),
        }, indent=2))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())