#!/usr/bin/env bash
set -euo pipefail

section="${1:?section is required}"

mkdir -p results/tmp

case "${section}" in
  symmetric-constructions)
    packages=(
      "cbom.eccg.symmetric_constructions.aes_modes"
      "cbom.eccg.symmetric_constructions.authenticated_encryption"
      "cbom.eccg.symmetric_constructions.disk_encryption"
      "cbom.eccg.symmetric_constructions.key_combiners"
      "cbom.eccg.symmetric_constructions.key_derivation"
      "cbom.eccg.symmetric_constructions.key_protection"
      "cbom.eccg.symmetric_constructions.mac"
      "cbom.eccg.symmetric_constructions.password_hashing"
    )
    ;;

  symmetric-atomic-primitives)
    packages=(
      "cbom.eccg.symmetric_atomic_primitives.block_ciphers"
      "cbom.eccg.symmetric_atomic_primitives.hash_primitives"
    )
    ;;

  asymmetric-atomic-primitives)
    packages=(
      "cbom.eccg.asymmetric_atomic_primitives.ec_dlog"
      "cbom.eccg.asymmetric_atomic_primitives.ff_dlog"
      "cbom.eccg.asymmetric_atomic_primitives.rsa_integer_factorization"
    )
    ;;

  *)
    echo "Unknown section: ${section}" >&2
    exit 1
    ;;
esac

for package in "${packages[@]}"; do
  safe_name="${package//./_}"

  echo "========================================"
  echo "Evaluating data.${package}.findings"
  echo "========================================"

  raw_path="results/tmp/${safe_name}.raw.json"

  opa eval \
    --format=json \
    --input "cboms/${section}.json" \
    --data policies/eccg \
    "data.${package}.findings" \
    > "${raw_path}"

  python3 .github/scripts/eccg/extract_opa_findings.py "${safe_name}" "${raw_path}"

  echo "Findings from ${package}:"
  cat "results/tmp/${safe_name}.json"
done

python3 .github/scripts/eccg/combine_findings.py "${section}"