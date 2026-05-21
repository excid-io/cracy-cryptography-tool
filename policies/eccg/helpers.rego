package cbom.eccg.helpers


#
# Helper: retrieve a note by its ID from the shared notes dataset.
#
# Loaded from:
# policies/eccg/eccg_notes.json
#
# Actual OPA path:
# data.eccg.eccg_notes.notes["Symmetric-Constructions"]["6-AddIntegrity"]
#
get_note(section, subsection, note_string_id) := note if {
    #note := data.eccg.notes[section][subsection][note_string_id]
    note := data.notes[section][subsection][note_string_id]

} else := {
    "title": "unknown",
    "text": "Note not found"
}

allowed_severities := {"warning", "info", "low", "medium", "high", "critical"}

is_valid_severity(sev) if {
    allowed_severities[sev]
}

#
# Find a component by bom-ref.
#
get_component_by_bomref(bom_ref) := component if {
    some i
    component := input.components[i]
    component["bom-ref"] == bom_ref
}

#
# True if src component depends on dst component according to CycloneDX dependencies.
#
depends_on_component(src_component, dst_component) if {
    some i
    dep := input.dependencies[i]
    dep.ref == src_component["bom-ref"]
    some j
    dep.dependsOn[j] == dst_component["bom-ref"]
}

#
# ---------------------------------------------------------
# Helper: get_evidence_occurrences
#
# Return the evidence occurrences array for a component.
# If evidence or occurrences is missing, return an empty array.
# ---------------------------------------------------------
#
get_evidence_occurrences(component) := occurrences if {
    occurrences := object.get(object.get(component, "evidence", {}), "occurrences", [])
}

#
# ---------------------------------------------------------
# Helper: get_occurrence_location_or_empty
#
# Return the source file path for one occurrence.
# If missing, return the empty string.
# ---------------------------------------------------------
#
get_occurrence_location_or_empty(occurrence) := location if {
    location := object.get(occurrence, "location", "")
}

#
# ---------------------------------------------------------
# Helper: get_occurrence_line_or_unknown
#
# Return the source line for one occurrence.
# If missing, return -1.
# ---------------------------------------------------------
#
get_occurrence_line_or_unknown(occurrence) := line if {
    line := object.get(occurrence, "line", -1)
}

#
# ---------------------------------------------------------
# Helper: same_source_file
#
# True if two components have at least one evidence occurrence
# in the same source file.
# ---------------------------------------------------------
#
same_source_file(component_a, component_b) if {
    some occurrence_a in get_evidence_occurrences(component_a)
    some occurrence_b in get_evidence_occurrences(component_b)

    location_a := get_occurrence_location_or_empty(occurrence_a)
    location_b := get_occurrence_location_or_empty(occurrence_b)

    location_a != ""
    location_a == location_b
}

#
# ---------------------------------------------------------
# Helper: shares_evidence_location_and_line
#
# True if two components share at least one evidence occurrence
# with the same source file and line number.
# ---------------------------------------------------------
#
shares_evidence_location_and_line(component_a, component_b) if {
    some occurrence_a in get_evidence_occurrences(component_a)
    some occurrence_b in get_evidence_occurrences(component_b)

    location_a := get_occurrence_location_or_empty(occurrence_a)
    line_a := get_occurrence_line_or_unknown(occurrence_a)

    location_b := get_occurrence_location_or_empty(occurrence_b)
    line_b := get_occurrence_line_or_unknown(occurrence_b)

    location_a != ""
    line_a != -1
    location_a == location_b
    line_a == line_b
}

#
# ---------------------------------------------------------
# Helper: get_shared_source_files
#
# Return all shared source files between two components.
# Returns an empty set if no shared source files exist.
# ---------------------------------------------------------
#
get_shared_source_files(component_a, component_b) := shared_locations if {
    shared_locations := {
        location |
        some occurrence_a in get_evidence_occurrences(component_a)
        some occurrence_b in get_evidence_occurrences(component_b)

        location_a := get_occurrence_location_or_empty(occurrence_a)
        location_b := get_occurrence_location_or_empty(occurrence_b)

        location_a != ""
        location_a == location_b

        location := location_a
    }
}

#
# ---------------------------------------------------------
# Helper: get_shared_source_file_or_unknown
#
# Return one deterministic shared source file for display.
# Otherwise return "unknown".
# ---------------------------------------------------------
#
get_shared_source_file_or_unknown(component_a, component_b) := location if {
    shared_locations := get_shared_source_files(component_a, component_b)
    count(shared_locations) > 0

    sorted_locations := sort(shared_locations)
    location := sorted_locations[0]
    #location := sorted_locations
} else := "unknown"

#
# ---------------------------------------------------------
# Helper: get_shared_source_location_and_line_or_unknown
#
# Return one shared file+line match between two components, if any.
# Otherwise return a default object.
# ---------------------------------------------------------
#
get_shared_source_location_and_line_or_unknown(component_a, component_b) := match if {
    some occurrence_a in get_evidence_occurrences(component_a)
    some occurrence_b in get_evidence_occurrences(component_b)

    location_a := get_occurrence_location_or_empty(occurrence_a)
    line_a := get_occurrence_line_or_unknown(occurrence_a)

    location_b := get_occurrence_location_or_empty(occurrence_b)
    line_b := get_occurrence_line_or_unknown(occurrence_b)

    location_a != ""
    line_a != -1
    location_a == location_b
    line_a == line_b

    match := {
        "location": location_a,
        "line": line_a
    }
} else := {
    "location": "unknown",
    "line": -1
}

#
# Explain whether two components matched by same-line or same-file.
#
get_composition_match_basis(component_a, component_b) := "same-line" if {
    shares_evidence_location_and_line(component_a, component_b)
} else := "same-file" if {
    same_source_file(component_a, component_b)
} else := "unknown"

#
# Helper: build a standardized finding object.
#
build_finding(rule_id, severity_level, message_text, component, extra_fields) := finding_object if {

    is_valid_severity(severity_level)

    base_finding := {
        "ruleId": rule_id,
        "severity": severity_level,
        "message": message_text,
        "component": component.name,
        "bomRef": component["bom-ref"],
        "references": get_source_references(component)
    }

    finding_object := object.union(base_finding, extra_fields)
}

#
# Helper: return all source-code references for a component.
# Each entry keeps the file path and line number together.
#
get_source_references(component) := source_references if {
    occurrences := object.get(object.get(component, "evidence", {}), "occurrences", [])

    source_references := [
        {
            "location": object.get(occurrence, "location", "unknown"),
            "line": object.get(occurrence, "line", -1),
            "offset": object.get(occurrence, "offset", -1),
            "additionalContext": object.get(occurrence, "additionalContext", "unknown")
        }
        | some i
          occurrence := occurrences[i]
    ]
} else := []

#
# Return the actual key size (in bits) if explicitly present.
# Otherwise return "unknown".
#
get_key_size_or_unknown(component) := key_size if {
    key_size_raw := object.get(component.cryptoProperties.algorithmProperties, "keySize", "")
    key_size_raw != ""
    key_size := to_number(key_size_raw)
} 

is_mac_primitive(component) if {
    component.cryptoProperties.assetType == "algorithm"
    object.get(component.cryptoProperties.algorithmProperties, "primitive", "") == "mac"
}

is_hash_primitive(component) if {
    component.cryptoProperties.assetType == "algorithm"
    object.get(component.cryptoProperties.algorithmProperties, "primitive", "") == "hash"
}

is_block_cipher_primitive(component) if {
    component.cryptoProperties.assetType == "algorithm"
    object.get(component.cryptoProperties.algorithmProperties, "primitive", "") == "block-cipher"
}

is_ae_primitive(component) if {
    component.cryptoProperties.assetType == "algorithm"
    object.get(component.cryptoProperties.algorithmProperties, "primitive", "") == "ae"
}

is_kdf_primitive(component) if {
    component.cryptoProperties.assetType == "algorithm"
    lower(object.get(component.cryptoProperties.algorithmProperties, "primitive", "")) == "kdf"
}

#
# ---------------------------------------------------------
# Helper: is_password_hashing_component
#
# Purpose:
# Identify components used for password hashing.
#
# Current behavior:
# - Treats all KDF primitives as potential password-hashing components.
#
# Rationale:
# - ECCG models PBKDF2 under password hashing, but CBOM currently
#   only exposes it as a KDF primitive.
# - This helper provides an abstraction layer so rules can target
#   password hashing without being tightly coupled to PBKDF2 or
#   specific naming patterns.
#
# Future improvements:
# - Restrict to PBKDF2 (and possibly Argon2, scrypt if added)
# - Add context-based detection (e.g., file paths, usage hints)
# - Use CBOM extensions like "usage": "password-hashing"
#
# Notes:
# - This is intentionally broad and may over-approximate.
# - Downstream rules should refine behavior if needed.
# ---------------------------------------------------------
#
is_password_hashing_primitive(component) if {
    is_kdf_primitive(component)
}

is_gcm_primitive(component) if {
    is_ae_primitive(component)
    get_mode_or_unknown(component) == "gcm"
}

is_ccm_primitive(component) if {
    is_ae_primitive(component)
    get_mode_or_unknown(component) == "ccm"
}

is_gcm_or_ccm(component) if {
    is_gcm_primitive(component)
} else if {
    is_ccm_primitive(component)
}

#
# ---------------------------------------------------------
# Helper: is_combiner_primitive
#
# Purpose:
# Detect components explicitly modeled by the CBOM specification
# as primitive = "combiner".
#
# CBOM specification:
# - "combiner": A combiner aggregates many candidates for a
#   cryptographic primitive and generates a new candidate for
#   the same primitive.
# ---------------------------------------------------------
#
is_combiner_primitive(component) if {
    component.cryptoProperties.assetType == "algorithm"
    lower(object.get(component.cryptoProperties.algorithmProperties, "primitive", "")) == "combiner"

}

is_explicit_combiner(component) if {
    is_combiner_primitive(component)
} else := false


#
# Helper: identify symmetric encryption components from the CBOM.
#
# We treat block-cipher modes and AE modes as relevant scheme components.
#
is_symmetric_encryption_scheme(component) if {
    component.cryptoProperties.assetType == "algorithm"
    is_block_cipher_primitive(component)
} else if {
    component.cryptoProperties.assetType == "algorithm"
    is_ae_primitive(component)
}

get_primitive_or_unknown(component) := primitive if {
    primitive := object.get(component.cryptoProperties.algorithmProperties, "primitive", "")
    primitive != ""
} else := "unknown"

get_mode_or_unknown(component) := mode if {
    mode := object.get(component.cryptoProperties.algorithmProperties, "mode", "")
    mode != ""
} else := "unknown"

get_name_or_unknown(component) := name if {
    name := object.get(component, "name", "")
    name != ""
} else := "unknown"

get_parameter_set_identifier_or_unknown(component) := p if {
    p := object.get(component.cryptoProperties.algorithmProperties, "parameterSetIdentifier", "")
    p != ""
} else := "unknown"

get_parameter_set_identifier_to_number_or_unknown(component) := n if {
    raw := get_parameter_set_identifier_or_unknown(component)
    raw != "unknown"
    n := to_number(raw)
} else := "unknown"

#
# ---------------------------------------------------------
# Helper: component_matches_primitive
#
# True if a component matches the requested abstract kind.
# Extend this helper as new component kinds are needed.
# ---------------------------------------------------------
#
component_matches_primitive(component, kind) if {
    kind == "hash"
    is_hash_primitive(component)
} else if {
    kind == "block-cipher"
    is_block_cipher_primitive(component)
} else if {
    kind == "mac"
    is_mac_primitive(component)
} else if {
    kind == "ae"
    is_ae_primitive(component)
} else if {
    kind == "kdf"
    is_kdf_primitive(component)
}


#
# ---------------------------------------------------------
# Helper: get_related_components_by_primitive
#
# Return all components related to a parent component, constrained
# by the expected primitive type of the candidate component.
#
# Strategy:
# 1. Prefer explicit CBOM dependency relationships.
# 2. If no dependency candidates exist, fall back to same file+line co-location.
# ---------------------------------------------------------
#
get_related_components_by_primitive(parent_component, candidate_primitive) := candidates if {
    dependency_candidates := [
        candidate |
        some i
        candidate := input.components[i]
        component_matches_primitive(candidate, candidate_primitive)
        depends_on_component(parent_component, candidate)
    ]

    count(dependency_candidates) > 0

    candidates := dependency_candidates
} else := candidates if {
    dependency_candidates := [
        candidate |
        some i
        candidate := input.components[i]
        component_matches_primitive(candidate, candidate_primitive)
        depends_on_component(parent_component, candidate)
    ]

    count(dependency_candidates) == 0

    candidates := [
        candidate |
        some i
        candidate := input.components[i]
        component_matches_primitive(candidate, candidate_primitive)
        shares_evidence_location_and_line(parent_component, candidate)
    ]
}

#
# ---------------------------------------------------------
# Helper: get_related_component_by_primitive
#
# Compatibility wrapper.
# Return one deterministic related component.
# Prefer get_related_components_by_primitive(...) for new rules.
# ---------------------------------------------------------
#
get_related_component_by_primitive(parent_component, candidate_primitive) := candidate_component if {
    candidates := get_related_components_by_primitive(parent_component, candidate_primitive)
    count(candidates) > 0

    sorted_candidates := sort(candidates)
    candidate_component := sorted_candidates[0]
    #candidate_component := sorted_candidates
}

#
# ---------------------------------------------------------
# Helper: is_possible_encryption_mac_composition
#
# Heuristic detection of a possible composed authenticated-
# encryption construction.
#
# Returns true when:
# - one component is a symmetric encryption scheme, and
# - another component is a MAC scheme, and
# - both share the same source location and line or more weakly the same source location.
#
# This represents a strong heuristic that both operations may
# belong to the same logical construction (e.g., Encrypt-then-MAC,
# MAC-then-Encrypt, or Encrypt-and-MAC).
#
# Limitations:
# - This helper does NOT determine the order of operations.
# - It does NOT distinguish between different composition patterns.
# - It relies on CBOM evidence granularity; if extraction does not
#   align components to the same line, this may produce false negatives.
#
# Intended use:
# - trigger higher-level findings indicating possible composed AE
#   constructions where exact classification is not possible.
# ---------------------------------------------------------
#
is_possible_encryption_mac_composition(enc_component, mac_component) if {
    is_symmetric_encryption_scheme(enc_component)
    is_mac_primitive(mac_component)
    shares_evidence_location_and_line(enc_component, mac_component)
} else if {
    is_symmetric_encryption_scheme(enc_component)
    is_mac_primitive(mac_component)
    same_source_file(enc_component, mac_component)
}

#
# ---------------------------------------------------------
# Helper: component_has_evidence_path_containing
#
# Purpose:
# Check whether a component has at least one evidence occurrence
# whose source file path contains a given substring.
#
# Strategy:
# - Iterate over all evidence occurrences attached to the component.
# - Extract the "location" field (file path).
# - Perform a case-insensitive substring match.
#
# Notes:
# - Matching is case-insensitive.
# - Only the file path is considered (line numbers are ignored).
# - Returns true on the first matching occurrence.
# - Returns false if no occurrences exist or no match is found.
#
# Example:
# component_has_evidence_path_containing(component, "test")
# → true if any occurrence path contains "test"
#
# Use cases:
# - Heuristic classification (e.g., test code vs production code)
# - Filtering findings based on file location
# - Context-aware policy rules
# ---------------------------------------------------------
#
component_has_evidence_path_containing(component, needle) if {
    some i
    occ := object.get(object.get(component, "evidence", {}), "occurrences", [])[i]
    loc := lower(object.get(occ, "location", ""))
    loc != ""
    contains(loc, lower(needle))
}

#
# ---------------------------------------------------------
# Helper: normalize_crypto_name
#
# Purpose:
# Normalize a cryptographic component name to improve
# robustness of pattern matching across CBOM outputs.
#
# Transformations applied:
# - Convert to lowercase
# - Remove whitespace
# - Remove hyphens "-"
# - Remove parentheses "(" and ")"
#
# Example transformations:
# - "KMAC-256"      → "kmac256"
# - "KMAC (256)"    → "kmac256"
# - "KMACXOF(128)"  → "kmacxof128"
#
# Rationale:
# CBOM tools emit inconsistent naming formats. Normalization
# ensures detection logic is stable across:
#     • different toolchains
#     • formatting variations
#     • specification styles
#
# Notes:
# - This helper is intentionally lossy (formatting removed).
# - Designed for substring matching, not exact equality.
# ---------------------------------------------------------
#
normalize_crypto_name(name) := normalized if {
    lower_name := lower(name)
    no_spaces := replace(lower_name, " ", "")
    no_hyphens := replace(no_spaces, "-", "")
    no_open_parens := replace(no_hyphens, "(", "")
    normalized := replace(no_open_parens, ")", "")
}


is_public_key_primitive(component) if {
    component.cryptoProperties.assetType == "algorithm"
    lower(object.get(component.cryptoProperties.algorithmProperties, "primitive", "")) == "pke"
}

#
# ---------------------------------------------------------
# Helper: is_asymmetric_algorithm
#
# Purpose:
# Identify asymmetric cryptographic algorithm components in a CBOM.
#
# Detection strategy:
# This helper treats a component as asymmetric if it is modeled as
# an algorithm and satisfies at least one of the following conditions:
#
# 1. The algorithm primitive is public-key encryption:
#      primitive == "pke"
#
# 2. The algorithm exposes a key-agreement function:
#      cryptoFunctions contains "key-agree"
#
# 3. The algorithm exposes a signature function:
#      cryptoFunctions contains "signature"
#
# Rationale:
# CycloneDX / CBOM representations may not encode all asymmetric
# algorithms using the same primitive value.
#
# For example:
# - RSA encryption may appear as primitive = "pke"
# - ECDH / FFDHE / X25519 may appear through cryptoFunctions = "key-agree"
# - ECDSA / EdDSA / RSA signatures may appear through cryptoFunctions = "signature"
#
# Therefore, checking only primitive == "pke" would miss many
# asymmetric algorithms, especially key-agreement and signature schemes.
#
# Intended use:
# - Shared precondition for asymmetric primitive rules.
# - Useful before applying RSA, FF-DLOG, EC-DLOG, signature, or
#   key-agreement specific classification logic.
#
# Notes:
# - This helper does not classify the exact asymmetric family.
# - It only determines that the component belongs to the broader
#   asymmetric/public-key cryptography space.
# - Family-specific helpers such as is_rsa_primitive(),
#   is_ffdlog_primitive(), and is_ecdlog_primitive() should perform
#   more precise matching.
# ---------------------------------------------------------
#
is_asymmetric_algorithm(component) if {
    component.cryptoProperties.assetType == "algorithm"

    primitive := lower(object.get(component.cryptoProperties.algorithmProperties, "primitive", ""))

    primitive == "pke"
} else if {
    component.cryptoProperties.assetType == "algorithm"

    some fn in object.get(component.cryptoProperties.algorithmProperties, "cryptoFunctions", [])

    lower(fn) == "key-agree"
} else if {
    component.cryptoProperties.assetType == "algorithm"

    some fn in object.get(component.cryptoProperties.algorithmProperties, "cryptoFunctions", [])

    lower(fn) == "signature"
}

#
# ---------------------------------------------------------
# Helper: normalize_ec_curve_name
#
# Purpose:
# Normalize elliptic curve names so that ECCG curve aliases can
# be matched reliably across CycloneDX registry names, library
# names, and common standard aliases.
#
# Transformations:
# - Use normalize_crypto_name()
# - Remove slash "/"
# - Remove underscore "_"
#
# Example transformations:
# - "nist/P-256"                 -> "nistp256"
# - "secg/secp256r1"             -> "secgsecp256r1"
# - "x962/prime256v1"            -> "x962prime256v1"
# - "brainpool/brainpoolP384r1"  -> "brainpoolbrainpoolp384r1"
# - "anssi/FRP256v1"             -> "anssifrp256v1"
# ---------------------------------------------------------
#
normalize_ec_curve_name(curve) := normalized if {
    base := normalize_crypto_name(curve)
    no_slash := replace(base, "/", "")
    normalized := replace(no_slash, "_", "")
}

#
# ---------------------------------------------------------
# Helper: get_ec_curve_or_unknown
#
# Purpose:
# Extract the elliptic curve identifier from a CBOM component.
#
# Detection order:
# 1. cryptoProperties.algorithmProperties.ellipticCurve
# 2. component.name fallback
#
# Rationale:
# CycloneDX 1.7 provides algorithmProperties.ellipticCurve,
# but CBOM tools may serialize curve information inconsistently.
# This helper therefore checks multiple possible locations.
# ---------------------------------------------------------
#
get_ec_curve_or_unknown(component) := curve if {
    props := component.cryptoProperties.algorithmProperties
    curve := object.get(component.cryptoProperties.algorithmProperties, "ellipticCurve", "")
    curve != ""
} else := name if {
    name := get_name_or_unknown(component)
    name != "unknown"
} else := "unknown"


#
# Return the policy evaluation timestamp in nanoseconds.
#
# Preferred deterministic input:
# {
#   "policyEvaluationDate": "2026-05-05T00:00:00Z"
# }
#
# Fallback:
# - wall-clock time from OPA.
#
evaluation_time_ns := ns if {
    date := input.policyEvaluationDate
    ns := time.parse_rfc3339_ns(date)
} else := ns if {
    ns := time.now_ns()
}

#
# Extract the year from the evaluation date.
#
evaluation_year := year if {
    parts := time.date(evaluation_time_ns)
    year := parts[0]
}

#
# Returns true when the current/evaluation year is less than or equal to
# the final accepted legacy year.
#
# Example:
#   is_legacy_until_year(2030)
#
# Means:
#   valid as legacy through calendar year 2030.
#
is_legacy_until_year(final_legacy_year) if {
    evaluation_year <= final_legacy_year
}

#
# Returns true once a legacy mechanism has expired.
#
# Example:
#   is_legacy_expired_after_year(2030)
#
# Means:
#   expired starting in 2031.
#
is_legacy_expired_after_year(final_legacy_year) if {
    evaluation_year > final_legacy_year
}

#
# Convert an ECCG legacy marker like L[2030] into a year.
#
legacy_marker_year(marker) := year if {
    startswith(marker, "L[")
    endswith(marker, "]")

    year_text := trim_suffix(trim_prefix(marker, "L["), "]")
    year := to_number(year_text)
}

#
# True if the legacy marker is still active.
#
# Example:
#   is_legacy_marker_active("L[2030]")
#
is_legacy_marker_active(marker) if {
    year := legacy_marker_year(marker)
    is_legacy_until_year(year)
}

#
# True if the legacy marker has expired.
#
# Example:
#   is_legacy_marker_expired("L[2030]")
#
is_legacy_marker_expired(marker) if {
    year := legacy_marker_year(marker)
    is_legacy_expired_after_year(year)
}

#
# Produce a status string for a legacy marker.
#
# Returns:
# - "legacy" if still inside the legacy period
# - "expired-legacy" if the legacy period has passed
#
legacy_marker_status(marker) := "legacy" if {
    is_legacy_marker_active(marker)
} else := "expired-legacy" if {
    is_legacy_marker_expired(marker)
}

legacy_status_severity(status) := "high" if {
    status == "legacy"
} else := "critical" if {
    status == "expired-legacy"
}

legacy_status_message(name, marker, status) := message if {
    status == "legacy"
    message := sprintf("%s is considered acceptable only as a legacy mechanism %s and should be phased out.", [name, marker])
} else := message if {
    status == "expired-legacy"
    message := sprintf("%s was acceptable only as a legacy mechanism %s, but that legacy period has expired.", [name, marker])
}

#
# Return the full cryptoProperties object for a component.
#
# This wrapper avoids unsafe direct access to component.cryptoProperties.
# If the field is missing, it returns an empty object so downstream helpers
# can safely continue using object.get.
#
get_crypto_properties(component) := object.get(component, "cryptoProperties", {})

#
# Return relatedCryptoMaterialProperties for a component.
#
# This object is present when cryptoProperties.assetType is
# "related-crypto-material". It contains metadata for cryptographic material
# such as private keys, public keys, secret keys, ciphertext, signatures,
# digests, or initialization vectors.
#
# If the component is not related crypto material, or if the field is missing,
# this returns an empty object.
#
get_related_crypto_material_properties(component) := object.get(
    get_crypto_properties(component),
    "relatedCryptoMaterialProperties",
    {}
)

#
# Return the CycloneDX crypto asset type for a component.
#
# Expected values include:
# - "algorithm"
# - "certificate"
# - "protocol"
# - "related-crypto-material"
#
# If the assetType field is missing, this returns "unknown".
#
get_asset_type(component) := object.get(
    get_crypto_properties(component),
    "assetType",
    "unknown"
)

#
# Return the type of related cryptographic material.
#
# This reads:
#
#   component.cryptoProperties.relatedCryptoMaterialProperties.type
#
# Expected values include:
# - "private-key"
# - "public-key"
# - "secret-key"
# - "key"
# - "ciphertext"
# - "signature"
# - "digest"
# - "initialization-vector"
#
# If the component is not related crypto material, or if the type field is
# missing, this returns "unknown".
#
get_related_crypto_material_type(component) := object.get(
    get_related_crypto_material_properties(component),
    "type",
    "unknown"
)

#
# Return the size of related cryptographic material.
#
# For RSA key material, CBOMkit may emit this as the key size in bits, for
# example:
#
#   "size": 2048
#
# If the size field is missing, this returns "unknown".
#
get_related_crypto_material_size(component) := object.get(
    get_related_crypto_material_properties(component),
    "size",
    "unknown"
)

#
# True when the component represents related cryptographic material.
#
# This identifies CBOM components where:
#
#   cryptoProperties.assetType == "related-crypto-material"
#
# These components are not algorithms themselves. They represent material
# associated with cryptographic algorithms, such as keys, signatures,
# ciphertexts, digests, or IVs.
#
is_related_crypto_material(component) if {
    get_asset_type(component) == "related-crypto-material"
}

#
# True when the component represents private key material.
#
# This identifies components such as:
#
#   {
#     "cryptoProperties": {
#       "assetType": "related-crypto-material",
#       "relatedCryptoMaterialProperties": {
#         "type": "private-key"
#       }
#     }
#   }
#
# This is useful for flagging generated, embedded, stored, or otherwise
# exposed asymmetric private keys.
#
is_private_key_material(component) if {
    is_related_crypto_material(component)
    get_related_crypto_material_type(component) == "private-key"
}

#
# True when the component represents public key material.
#
# This identifies components such as:
#
#   {
#     "cryptoProperties": {
#       "assetType": "related-crypto-material",
#       "relatedCryptoMaterialProperties": {
#         "type": "public-key"
#       }
#     }
#   }
#
# Public keys are not confidential, but they may still need policy review for
# trust, lifecycle, algorithm family, and key-size requirements.
#
is_public_key_material(component) if {
    is_related_crypto_material(component)
    get_related_crypto_material_type(component) == "public-key"
}

#
# Return the first source file location recorded for a component.
#
# CBOM components can contain evidence occurrences that point back to
# source-code locations. This helper returns the "location" value from the
# first occurrence.
#
# If the component has no evidence occurrences, or if the location field is
# missing, this returns "unknown".
#
get_first_source_location(component) := location if {
    occurrences := get_evidence_occurrences(component)
    count(occurrences) > 0
    location := object.get(occurrences[0], "location", "unknown")
} else := "unknown"

#
# Return the first source line recorded for a component.
#
# This helper reads the "line" value from the first evidence occurrence
# attached to the component.
#
# If the component has no evidence occurrences, or if the line field is
# missing, this returns -1.
#
get_first_source_line(component) := line if {
    occurrences := get_evidence_occurrences(component)
    count(occurrences) > 0
    line := object.get(occurrences[0], "line", -1)
} else := -1

#
# Return the algorithm component associated with a key-material component.
#
# CBOMkit may represent generated or related key material as a separate
# component with assetType = "related-crypto-material". The relationship
# between the key material and the algorithm is represented through the
# CycloneDX dependencies array.
#
# Example:
#
#   private-key@... dependsOn RSA-2048
#
# This helper follows that dependency edge and returns the related algorithm
# component.
#
related_algorithm_for_key_material(key_component) := algorithm_component if {
    key_ref := key_component["bom-ref"]

    dependency := input.dependencies[_]
    dependency.ref == key_ref

    algorithm_ref := dependency.dependsOn[_]

    algorithm_component := input.components[_]
    algorithm_component["bom-ref"] == algorithm_ref
}

#
# Return the name of the algorithm associated with a key-material component.
#
# This uses related_algorithm_for_key_material(...) to follow the CBOM
# dependency from the key-material component to its related algorithm.
#
# If no related algorithm can be found, this returns "unknown".
#
related_algorithm_name_or_unknown(key_component) := name if {
    algorithm_component := related_algorithm_for_key_material(key_component)
    name := object.get(algorithm_component, "name", "unknown")
} else := "unknown"

#
# Return the bom-ref of the algorithm associated with a key-material component.
#
# This is useful for including a stable reference to the related algorithm in
# finding metadata.
#
# If no related algorithm can be found, this returns "unknown".
#
related_algorithm_bom_ref_or_unknown(key_component) := ref if {
    algorithm_component := related_algorithm_for_key_material(key_component)
    ref := object.get(algorithm_component, "bom-ref", "unknown")
} else := "unknown"

#
# Return the parameterSetIdentifier of the algorithm associated with
# a key-material component.
#
# For RSA key material, this often represents the RSA modulus size, for example:
#
#   "parameterSetIdentifier": "2048"
#
# This helper follows the dependency from the key-material component to the
# related algorithm component, then reads:
#
#   cryptoProperties.algorithmProperties.parameterSetIdentifier
#
# If no related algorithm or parameter set identifier can be found, this
# returns "unknown".
#
related_algorithm_parameter_set_or_unknown(key_component) := parameter_set if {
    algorithm_component := related_algorithm_for_key_material(key_component)

    algorithm_properties := object.get(
        object.get(algorithm_component, "cryptoProperties", {}),
        "algorithmProperties",
        {}
    )

    parameter_set := object.get(algorithm_properties, "parameterSetIdentifier", "unknown")
} else := "unknown"

#
# Return standardized metadata for related cryptographic material.
#
# This is intended for components where:
#
#   cryptoProperties.assetType == "related-crypto-material"
#
# It captures the material type, size, related algorithm, bom-ref, and
# source-code evidence in one reusable object so private-key, public-key,
# secret-key, and other key-material rules can share the same finding shape.
#
get_related_crypto_material_finding_details(component) := details if {
    details := {
        "assetType": get_asset_type(component),
        "materialType": get_related_crypto_material_type(component),
        "size": get_related_crypto_material_size(component),
        "relatedAlgorithm": related_algorithm_name_or_unknown(component),
        "relatedAlgorithmBomRef": related_algorithm_bom_ref_or_unknown(component),
        "relatedAlgorithmParameterSetIdentifier": related_algorithm_parameter_set_or_unknown(component),
        "bomRef": get_bom_ref(component),
        "sourceReferences": get_source_references(component),
        "sourceLocation": get_first_source_location(component),
        "sourceLine": get_first_source_line(component)
    }
}

#
# Return the bom-ref for a component.
#
# If the component does not contain a bom-ref field, this returns "unknown".
#
get_bom_ref(component) := bom_ref if {
    bom_ref := object.get(component, "bom-ref", "unknown")
}

#
# Return the display name for a CBOM component.
#
# This is a compatibility helper for rules that need a human-readable
# component name in finding messages.
#
# If the component does not contain a name field, this returns "unknown".
#
get_component_name(component) := name if {
    name := object.get(component, "name", "unknown")
}