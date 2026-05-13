#!/usr/bin/env bash
set -euo pipefail

section="${1:?section is required}"

rm -rf cbom-scan
mkdir -p cbom-scan/src

cp -r "configs/${section}/tests/"*.py cbom-scan/src/

cat > cbom-scan/pyproject.toml <<EOF
[project]
name = "eccg-${section}"
version = "0.0.0"
dependencies = [
    "cryptography"
]
EOF

echo "Temporary project:"
find cbom-scan -maxdepth 3 -type f | sort