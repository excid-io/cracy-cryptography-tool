package cbom.eccg.symmetric_constructions.helpers

import data.cbom.eccg.helpers.is_mac_primitive
import data.cbom.eccg.helpers.is_ae_primitive
import data.cbom.eccg.helpers.is_block_cipher_primitive
import data.cbom.eccg.helpers.get_mode_or_unknown
import data.cbom.eccg.helpers.is_kdf_primitive
import data.cbom.eccg.helpers.is_combiner_primitive
import data.cbom.eccg.helpers.is_hash_primitive
import data.cbom.eccg.helpers.is_symmetric_encryption_scheme
import data.cbom.eccg.helpers.same_source_file
import data.cbom.eccg.helpers.depends_on_component
import data.cbom.eccg.helpers.shares_evidence_location_and_line
import data.cbom.eccg.helpers.get_related_component_by_primitive
import data.cbom.eccg.helpers.get_parameter_set_identifier_to_number_or_unknown
import data.cbom.eccg.helpers.normalize_crypto_name
import data.cbom.eccg.helpers.is_gcm_primitive


#
# HMAC Scheme detection.
#
is_hmac_scheme(component) if {
    name := lower(object.get(component, "name", ""))
    name == "hmac"
} else if {
    name := lower(object.get(component, "name", ""))
    contains(name, "hmac")
}

#
# HMAC-SHA-1 detection.
# This may appear directly in the component name or indirectly depending on extraction.
#
is_hmac_sha1_scheme(component) if {
    name := lower(object.get(component, "name", ""))
    contains(name, "hmac-sha1")
} 

#
# HMAC-SHA256 detection.
# This may appear directly in the component name or indirectly depending on extraction.
#
is_hmac_sha256_scheme(component) if {
    name := lower(object.get(component, "name", ""))
    contains(name, "hmac-sha256")
} 

#
# CMAC Scheme detection.
#
is_cmac_scheme(component) if {
    name := lower(object.get(component, "name", ""))
    name == "cmac"
} else if {
    name := lower(object.get(component, "name", ""))
    contains(name, "aes-cmac")
}


#
# GMAC detection.
# Depending on extraction, this may appear directly as GMAC,
# AES-GMAC, or indirectly as AES-GCM used for authentication only.
#
is_gmac_scheme(component) if {
    name := lower(object.get(component, "name", ""))
    name == "gmac"
} else if {
    name := lower(object.get(component, "name", ""))
    contains(name, "aes-gmac")
} else if {
    name := lower(object.get(component, "name", ""))
    contains(name, "gmac")
}

#
# Helpers for the agreed list.
#
is_ctr_scheme(component) if {
    lower(get_mode_or_unknown(component)) == "ctr"
} else if {
    contains(get_mode_or_unknown(component), "ctr")
}


is_ofb_scheme(component) if {
    lower(get_mode_or_unknown(component)) == "ofb"
} else if {
    contains(get_mode_or_unknown(component), "ofb")
}

is_cbc_scheme(component) if {
    lower(get_mode_or_unknown(component)) == "cbc"
} else if {
    contains(get_mode_or_unknown(component), "cbc")
}


#TODO does seem to be defined in the CBOM specification, but it's recommended without any notes for now
is_cbc_cs_scheme(component) if {
    lower(component.name) == "cbc-cs"
} else if {
    lower(component.name) == "aes-cbc-cs"
}

is_cfb_scheme(component) if {
    lower(get_mode_or_unknown(component)) == "cfb"
}

#
# ---------------------------------------------------------
# Helper: is_agreed_or_legacy_mac_scheme
#
# Purpose:
# Identify MAC schemes that are explicitly mentioned in the
# ECCG MAC tables.
#
# Covered schemes:
# - CMAC
# - CBC-MAC
# - HMAC
# - HMAC-SHA1
# - KMAC128
# - KMAC256
# - GMAC
#
# Notes:
# - This helper only checks whether the scheme family is mentioned.
# - It does NOT validate key sizes, truncation, nonce requirements,
#   or other note-based conditions.
# ---------------------------------------------------------
#
is_agreed_or_legacy_mac_scheme(component) if {
    is_cmac_scheme(component)
} else if {
    is_cbc_scheme(component)
} else if {
    is_hmac_scheme(component)
} else if {
    is_hmac_sha1_scheme(component)
} else if {
    is_kmac128_scheme(component)
} else if {
    is_kmac256_scheme(component)
} else if {
    is_gmac_scheme(component)
}

#
# ---------------------------------------------------------
# Helper: is_unlisted_mac_scheme
#
# Purpose:
# Detect MAC components that are not mentioned in the ECCG
# MAC recommendation tables.
# ---------------------------------------------------------
#
is_unlisted_mac_scheme(component) if {
    is_mac_primitive(component)
    not is_agreed_or_legacy_mac_scheme(component)
}

#
# ---------------------------------------------------------
# Helper: is_agreed_symmetric_encryption_scheme
#
# Purpose:
# Identify whether a component implements a symmetric encryption
# scheme that is considered "agreed" according to the ECCG
# recommendation tables.
#
# Covered schemes:
# - CTR (Counter mode)
# - OFB (Output Feedback mode)
# - CBC (Cipher Block Chaining)
# - CBC-CS (CBC with Ciphertext Stealing)
# - CFB (Cipher Feedback mode)
#
# Strategy:
# - Delegate detection to mode-specific helpers.
# - Returns true if the component matches any agreed mode.
#
# Notes:
# - This helper performs classification only.
# - It does NOT validate security requirements such as:
#     • IV randomness / uniqueness
#     • integrity protection (e.g., AEAD vs encryption-only)
#     • correct parameter usage
# - Some of these schemes are only conditionally recommended
#   and may require additional checks in other rules.
#
# Usage example:
#
# if is_agreed_symmetric_encryption_scheme(component) {
#     # mark as compliant (subject to additional validation)
# }
#
# Precondition:
# - component represents a symmetric encryption scheme
#   (not strictly enforced here).
# ---------------------------------------------------------
#
is_agreed_symmetric_encryption_scheme(component) if {
    is_ctr_scheme(component)
} else if {
    is_ofb_scheme(component)
} else if {
    is_cbc_scheme(component)
} else if {
    is_cbc_cs_scheme(component)
} else if {
    is_cfb_scheme(component)
} 

#else if {
#    is_xts_scheme(component)
#} else if {
#    is_gcm_primitive(component)
#}


#
# ---------------------------------------------------------
# Helper: is_conditionally_agreed_symmetric_encryption_scheme
#
# Purpose:
# Identify symmetric encryption schemes that are marked as
# "R*" (conditionally recommended) in the ECCG tables.
#
# Covered schemes (R*):
# - CTR (Counter mode)
# - OFB (Output Feedback mode)
# - CBC (Cipher Block Chaining)
# - CBC-CS (CBC with Ciphertext Stealing)
# - CFB (Cipher Feedback mode)
#
# Meaning of R*:
# - These schemes are recommended only under specific conditions.
# - Most importantly, they MUST be combined with additional
#   integrity protection (e.g., MAC or AEAD construction).
# - If used standalone (encryption-only), they are considered legacy.
#
# Strategy:
# - Delegate detection to mode-specific helpers.
# - Returns true if the component matches any R* scheme.
#
# Notes:
# - This helper performs classification only.
# - It does NOT check whether integrity protection is actually present.
# - Additional rules must enforce:
#     • use of AEAD or MAC
#     • correct IV/nonce handling
#
# Usage example:
#
# if is_conditionally_agreed_symmetric_encryption_scheme(component) {
#     # require integrity checks or flag as legacy usage
# }
#
# Precondition:
# - component represents a symmetric encryption scheme
#   (not strictly enforced here).
# ---------------------------------------------------------
#
is_conditionally_agreed_symmetric_encryption_scheme(component) if {
    is_ctr_scheme(component)
} else if {
    is_ofb_scheme(component)
} else if {
    is_cbc_scheme(component)
} else if {
    is_cbc_cs_scheme(component)
} else if {
    is_cfb_scheme(component)
}

#
# Padding-sensitive modes from the notes.
# CBC definitely belongs here; CFB is included conservatively based on the note block.
#
is_padding_sensitive_scheme(component) if {
    is_cbc_scheme(component)
} else if {
    is_cfb_scheme(component)
}

#
# Heuristic:
# AES-GCM may correspond to GMAC-style usage when used as an authentication-only construction.
# CBOM usually cannot prove that plaintext was empty, so this is only heuristic.
#
is_possible_gmac_scheme(component) if {
    lower(get_mode_or_unknown(component)) == "gcm"
}

#
# ---------------------------------------------------------
# Helper: is_stream_mode_scheme
#
# Purpose:
# Identify symmetric encryption modes that operate as
# stream-like constructions according to ECCG Note 7 (StreamMode).
#
# Covered modes:
# - CTR (Counter mode)
# - OFB (Output Feedback mode)
#
# Characteristics:
# - These modes generate a keystream that is XORed with the plaintext.
# - Security critically depends on ensuring that keystreams never overlap.
# - Reuse of the same key + IV/nonce can lead to catastrophic failures
#   (e.g., plaintext recovery).
#
# Strategy:
# - Delegate detection to mode-specific helpers.
#
# Notes:
# - This helper performs classification only.
# - It does NOT verify correct nonce/IV usage or uniqueness.
# - Additional rules should enforce:
#     • nonce uniqueness (CTR)
#     • IV non-reuse (OFB)
#
# Usage example:
#
# if is_stream_mode_scheme(component) {
#     # enforce nonce/IV uniqueness checks
# }
#
# Precondition:
# - component represents a symmetric encryption scheme
#   (not strictly enforced here).
# ---------------------------------------------------------
#
is_stream_mode_scheme(component) if {
    is_ctr_scheme(component)
} else if {
    is_ofb_scheme(component)
}

#
# XTS detection.
# Depending on CBOM extraction, this may appear via mode, name, or both.
#
is_xts_scheme(component) if {
    lower(get_mode_or_unknown(component)) == "xts"
} else if {
    lower(component.name) == "aes-xts"
} else if {
    lower(component.name) == "xts"
}

#
# CBC-ESSIV detection.
# This is likely to depend on how CBOMkit models manual ESSIV construction.
#
is_cbc_essiv_scheme(component) if {
    lower(component.name) == "cbc"
} else if {
    lower(component.name) == "aes-cbc"
}

#
# ---------------------------------------------------------
# Helper: is_stream_mode_for_disk
#
# Purpose:
# Identify modes that behave as stream modes and are
# considered improper for disk encryption.
#
# Rationale:
# - Disk encryption is deterministic (IV/tweak derived from location).
# - Stream modes reuse keystream if IV is reused.
# - This leads to leakage: C1 ⊕ C2 = P1 ⊕ P2.
#
# Based on ECCG Note 9 (DiskEncStreamMode).
#
# Modes included:
# - CTR
# - OFB
#
# Notes:
# - GCM is NOT included:
#   Although it uses CTR internally, it is an AEAD mode and
#   provides integrity protection, so it is treated separately.
# ---------------------------------------------------------
#
is_stream_mode_for_disk(component) if {
    is_ctr_scheme(component)
} else if {
    is_ofb_scheme(component)
} else if {
    is_cfb_scheme(component)
}


#
# Treat XTS explicitly as a disk-encryption component.
# Also allow manually named CBC-ESSIV components if CBOM contains them.
#
is_disk_encryption_component(component) if {
    is_xts_scheme(component)
} else if {
    is_cbc_essiv_scheme(component)
} else if {
    is_stream_mode_for_disk(component)
}

#
# Detect AES-SIV / SIV authenticated-encryption schemes.
#
# CBOM naming patterns:
# - AES-128-SIV
# - AES-192-SIV
# - AES-256-SIV
# - AES-SIV
#
# Expected primitive:
# - ae
#
is_siv_scheme(component) if {
    is_ae_primitive(component)
    name := normalize_crypto_name(object.get(component, "name", ""))
    contains(name, "aessiv")
} else if {
    is_ae_primitive(component)
    lower(get_mode_or_unknown(component)) == "siv"
}

#
# ---------------------------------------------------------
# Helper: is_aes_key_wrap_scheme
#
# Purpose:
# Detect AES Key Wrap schemes (KW, KWP, PKCS7 variants)
# from CBOM naming.
#
# Covered patterns:
# - AES-128-KW
# - AES-192-KW
# - AES-256-KW
# - AES-*-KWP
# - AES-*-Wrap-PKCS7
#
# Expected primitive:
# - key-wrap
# ---------------------------------------------------------
#
is_aes_key_wrap_scheme(component) if {
    component.cryptoProperties.assetType == "algorithm"

    lower(object.get(component.cryptoProperties.algorithmProperties, "primitive", "")) == "key-wrap"

    name := normalize_crypto_name(object.get(component, "name", ""))

    contains(name, "aes") 
    contains(name, "kw")
} else if {
    component.cryptoProperties.assetType == "algorithm"

    lower(object.get(component.cryptoProperties.algorithmProperties, "primitive", "")) == "key-wrap"

    name := normalize_crypto_name(object.get(component, "name", ""))

    contains(name, "wrap")
}

#
# ---------------------------------------------------------
# Helper: is_ansi_x963_kdf_scheme
#
# Purpose:
# Detect KDF components that implement the ANSI X9.63
# key derivation function.
#
# Practical CBOM signals:
# - Names may appear as:
#     "ANSI X9.63"
#     "ANSI-X9.63"
#     "X9.63"
# - Variations in formatting (spaces, hyphens, casing)
#   are common depending on the toolchain.
#
# Strategy:
# - Normalize the component name to lowercase.
# - Match known representations of X9.63-based KDFs.
#
# Notes:
# - Detection is name-based due to lack of structured
#   standard identifiers in the CBOM.
# - Only applies to KDF primitives.
# - Equality is used (not contains) to avoid false positives.
# ---------------------------------------------------------
#
is_ansi_x963_kdf_scheme(component) if {
    is_kdf_primitive(component)

    name := lower(object.get(component, "name", ""))
    name == "ansi x9.63"
} else if {
    is_kdf_primitive(component)

    name := lower(object.get(component, "name", ""))
    name == "ansi-x9.63"
} else if {
    is_kdf_primitive(component)

    name := lower(object.get(component, "name", ""))
    name == "x9.63"
}

#
# Fallback: normalized matching
#
is_ansi_x963_kdf_scheme(component) if {
    is_kdf_primitive(component)

    name := normalize_crypto_name(object.get(component, "name", ""))

    contains(name, "ansix963")
} else if {
    is_kdf_primitive(component)

    name := normalize_crypto_name(object.get(component, "name", ""))

    contains(name, "x963")
}

#
# ---------------------------------------------------------
# Helper: is_hkdf_scheme
#
# Purpose:
# Detect HKDF (HMAC-based Key Derivation Function) constructions.
#
# Practical CBOM signals:
# - Names typically include "HKDF", often with the underlying hash:
#     "HKDF"
#     "HKDF-SHA256"
#     "HKDF-SHA512"
#
# Strategy:
# - Normalize the component name to lowercase.
# - Use substring matching to detect "hkdf".
#
# Notes:
# - Detection is name-based due to lack of structured KDF metadata.
# - This is a coarse-grained detector (does not identify the hash).
# - Only applies to KDF components.
# ---------------------------------------------------------
#
is_hkdf_scheme(component) if {
    is_kdf_primitive(component)

    name := lower(object.get(component, "name", ""))
    contains(name, "hkdf")
}

#
# ---------------------------------------------------------
# Helper: is_pbkdf2_scheme
#
# Purpose:
# Detect PBKDF2-based key derivation functions.
#
# Practical CBOM signals:
# - Names typically include "PBKDF2", often with the PRF:
#     "PBKDF2"
#     "PBKDF2-SHA256"
#     "PBKDF2-SHA1"
#
# Strategy:
# - Normalize the component name to lowercase.
# - Use substring matching to detect "pbkdf2".
#
# Notes:
# - Detection is name-based due to lack of structured KDF metadata.
# - This is a coarse-grained detector (does not identify the PRF).
# - Use more specific helpers if PRF-level validation is needed.
# - Only applies to KDF components.
# ---------------------------------------------------------
#
is_pbkdf2_scheme(component) if {
    is_kdf_primitive(component)

    name := lower(object.get(component, "name", ""))
    contains(name, "pbkdf2")
}


#
# ---------------------------------------------------------
# Helper: is_nist_sp800_56_abc_scheme
#
# Purpose:
# Detect KDF components that appear to implement one of the
# NIST SP 800-56A/B/C key-derivation constructions.
#
# Practical CBOM signals:
# - pyca/cryptography's ConcatKDFHash / ConcatKDFHMAC may be
#   emitted by CBOMkit as "ConcatenationKDF".
# - Other tools may emit names containing "ConcatKDF".
# - Some CBOMs may encode the standard directly, e.g. "SP800-56".
#
# Notes:
# - This is name-based because the current CBOM does not expose a
#   dedicated standard identifier for SP 800-56 KDFs.
# - This helper only applies to KDF primitives.
# - Matching is case-insensitive.
# ---------------------------------------------------------
#
is_nist_sp800_56_abc_scheme(component) if {
    is_kdf_primitive(component)
    _is_sp800_56_name(component)
}

#
# Internal matcher
#
_is_sp800_56_name(component) if {
    name := lower(object.get(component, "name", ""))
    contains(name, "concatenationkdf")
} else if {
    name := lower(object.get(component, "name", ""))
    contains(name, "concatkdf")
} else if {
    name := lower(object.get(component, "name", ""))
    contains(name, "sp800-56")
} else if {
    name := lower(object.get(component, "name", ""))
    contains(name, "sp80056")
}

#
# Fallback: normalized matching
#
_is_sp800_56_name(component) if {
    name := normalize_crypto_name(object.get(component, "name", ""))
    contains(name, "sp80056")
} else if {
    name := normalize_crypto_name(object.get(component, "name", ""))
    contains(name, "concatkdf")
} else if {
    name := normalize_crypto_name(object.get(component, "name", ""))
    contains(name, "concatenationkdf")
}

#
# ---------------------------------------------------------
# Helper: is_pbkdf2_component
#
# Purpose:
# Detect PBKDF2-based key derivation functions by name.
#
# Strategy:
# - Normalize the component name to lowercase.
# - Match any name that starts with "pbkdf2".
#
# Examples matched:
# - "PBKDF2"
# - "PBKDF2-SHA256"
# - "PBKDF2-SHA1"
#
# Notes:
# - This is a coarse-grained detector (family-level).
# - More specific helpers should be used to distinguish
#   underlying hash functions.
# ---------------------------------------------------------
#
is_pbkdf2_component(component) if {
    name := lower(object.get(component, "name", ""))
    startswith(name, "pbkdf2")
}


#
# ---------------------------------------------------------
# Helper: is_pbkdf2_sha256_component
#
# Purpose:
# Detect PBKDF2 configured with SHA-256 as the PRF.
#
# Strategy:
# - Exact match on normalized name.
#
# Notes:
# - This is stricter than is_pbkdf2_component.
# - Assumes the CBOM encodes the hash in the name.
# ---------------------------------------------------------
#
is_pbkdf2_sha256_component(component) if {
    name := lower(object.get(component, "name", ""))
    name == "pbkdf2-sha256"
} else if {
    normalized := normalize_crypto_name(object.get(component, "name", ""))
    contains(normalized, "pbkdf2sha256")
}


#
# ---------------------------------------------------------
# Helper: is_pbkdf2_sha1_component
#
# Purpose:
# Detect PBKDF2 configured with SHA-1 as the PRF.
#
# Strategy:
# - Exact match on normalized name.
#
# Notes:
# - Useful for flagging legacy/weak configurations.
# - Assumes naming convention includes the hash.
# ---------------------------------------------------------
#
is_pbkdf2_sha1_component(component) if {
    name := lower(object.get(component, "name", ""))
    name == "pbkdf2-sha1"
} else if {
    normalized := normalize_crypto_name(object.get(component, "name", ""))
    contains(normalized, "pbkdf2sha1")
}

#
# ---------------------------------------------------------
# Helper: is_agreed_kdf_scheme
#
# Purpose:
# Identify whether a component implements a Key Derivation
# Function (KDF) that is considered "agreed" according to
# the ECCG recommendation tables.
#
# Covered schemes:
# - NIST SP 800-56 A/B/C (e.g., ConcatKDF variants)
# - ANSI X9.63 KDF
# - PBKDF2
# - HKDF
#
# Strategy:
# - Delegate detection to scheme-specific helpers.
# - Returns true if the component matches any agreed KDF.
#
# Notes:
# - This helper provides a high-level classification only.
# - It does NOT validate parameters (e.g., hash choice,
#   iteration count, salt usage).
# - Detection is primarily name-based and depends on CBOM
#   extraction quality.
#
# Usage example:
#
# if is_agreed_kdf_scheme(component) {
#     # mark as compliant (subject to parameter checks)
# }
#
# Precondition:
# - component should represent a KDF (not strictly required,
#   but recommended for correct usage).
# ---------------------------------------------------------
#
is_agreed_kdf_scheme(component) if {
    is_nist_sp800_56_abc_scheme(component)
} else if {
    is_ansi_x963_kdf_scheme(component)
} else if {
    is_pbkdf2_scheme(component)
} else if {
    is_hkdf_scheme(component)
}

#
# ---------------------------------------------------------
# Helper: is_kmac_scheme
#
# Purpose:
# Detect any KMAC-based MAC construction from CBOM naming.
#
# Covered variants:
# - KMAC
# - KMAC128
# - KMAC256
# - KMAC-128
# - KMAC-256
# - KMAC(128)
# - KMAC(256)
# - KMACXOF128
# - KMACXOF256
#
# Strategy:
# - Normalize component name
# - Check whether the normalized name contains "kmac"
#
# Notes:
# - This is a broad KMAC detector.
# - It matches both fixed-output KMAC and KMACXOF variants.
# - It does not distinguish KMAC128 from KMAC256.
# - It does not validate key size requirements.
# - Use is_kmac128_scheme or is_kmac256_scheme when the rule
#   needs parameter-specific ECCG validation.
#
# ECCG relevance:
# - KMAC128 is agreed for key size >= 125 bits.
# - KMAC256 is agreed for key size >= 250 bits.
# - This helper only identifies that the scheme appears to be KMAC.
# ---------------------------------------------------------
#
is_kmac_scheme(component) if {
    name := normalize_crypto_name(object.get(component, "name", ""))
    contains(name, "kmac")
}

#
# ---------------------------------------------------------
# Helper: is_kmac128_scheme
#
# Purpose:
# Detect KMAC128-based MAC constructions from CBOM naming.
#
# Covered variants:
# - KMAC128
# - KMAC-128
# - KMAC(128)
# - KMAC (128)
# - KMACXOF128
# - KMACXOF-128
# - KMACXOF(128)
#
# Strategy:
# - Normalize component name
# - Perform substring matching
#
# Notes:
# - Works for both MAC and XOF variants (KMACXOF)
# - Detection is name-based due to lack of structured CBOM metadata
# - Does NOT validate key size requirements
#
# ECCG relevance:
# - KMAC128 is agreed for key size ≥ 125 bits
# - Parameter validation must be done in separate rules
# ---------------------------------------------------------
#
is_kmac128_scheme(component) if {
    name := normalize_crypto_name(object.get(component, "name", ""))
    contains(name, "kmac128")
} else if {
    name := normalize_crypto_name(object.get(component, "name", ""))
    contains(name, "kmacxof128")
}


#
# ---------------------------------------------------------
# Helper: is_kmac256_scheme
#
# Purpose:
# Detect KMAC256-based MAC constructions from CBOM naming.
#
# Covered variants:
# - KMAC256
# - KMAC-256
# - KMAC(256)
# - KMAC (256)
# - KMACXOF256
# - KMACXOF-256
# - KMACXOF(256)
#
# Strategy:
# - Normalize component name
# - Perform substring matching
#
# Notes:
# - Works for both MAC and XOF variants (KMACXOF)
# - Detection is name-based due to lack of structured CBOM metadata
# - Does NOT validate key size requirements
#
# ECCG relevance:
# - KMAC256 is agreed for key size ≥ 250 bits
# - Parameter validation must be handled separately
# ---------------------------------------------------------
#
is_kmac256_scheme(component) if {
    name := normalize_crypto_name(object.get(component, "name", ""))
    contains(name, "kmac256")
} else if {
    name := normalize_crypto_name(object.get(component, "name", ""))
    contains(name, "kmacxof256")
}


#
# EAX detection.
# Depending on CBOM extraction, this may appear via AE mode, name, or both.
# TODO: this is currently not detected by the CBOM kit
#
is_eax(component) if {
    is_ae_primitive(component)
    lower(get_mode_or_unknown(component)) == "eax"
} else if {
    lower(object.get(component, "name", "")) == "eax"
} else if {
    contains(lower(object.get(component, "name", "")), "eax")
}

#
# ---------------------------------------------------------
# Helper: is_catkdf_name
#
# Purpose:
# Detect CatKDF / Concatenate-then-KDF style names.
#
# Practical signals:
# - CatKDF
# - ConcatenateKDF
# - ConcatenationKDF
# - ConcatKDF
# - ConcatKDFHash
# - ConcatKDFHMAC
#
# pyca/cryptography:
# - ConcatKDFHash
# - ConcatKDFHMAC
#
# Notes:
# - CatKDF itself is usually not emitted directly by CBOMkit.
# - ConcatKDFHash / ConcatKDFHMAC are practical CBOM signals.
# ---------------------------------------------------------
#
is_catkdf_name(component) if {
    name := normalize_crypto_name(object.get(component, "name", ""))
    contains(name, "concatkdf")
} else if {
    name := normalize_crypto_name(object.get(component, "name", ""))
    contains(name, "concatenationkdf")
} else if {
    name := normalize_crypto_name(object.get(component, "name", ""))
    contains(name, "concatenatekdf")
} else if {
    name := normalize_crypto_name(object.get(component, "name", ""))
    contains(name, "catkdf")
}

#
# ---------------------------------------------------------
# Helper: is_caskdf_name
#
# Purpose:
# Detect CasKDF / Cascade-KDF style names.
#
# Practical signals:
# - CasKDF
# - CascadeKDF
#
# Notes:
# - CasKDF is unlikely to be emitted directly by CBOMkit.
# - Detection is therefore primarily name-based and best-effort.
# ---------------------------------------------------------
#
is_caskdf_name(component) if {
    name := normalize_crypto_name(object.get(component, "name", ""))
    contains(name, "caskdf")
} else if {
    name := normalize_crypto_name(object.get(component, "name", ""))
    contains(name, "cascadekdf")
}

#
# ---------------------------------------------------------
# Helper: is_catkdf_scheme
#
# Purpose:
# Detect CatKDF either as:
# - a first-class CBOM combiner primitive, or
# - a KDF primitive such as ConcatKDFHash / ConcatKDFHMAC.
# ---------------------------------------------------------
#
is_catkdf_scheme(component) if {
    is_combiner_primitive(component)
    is_catkdf_name(component)
} else if {
    is_kdf_primitive(component)
    is_catkdf_name(component)
}

#
# ---------------------------------------------------------
# Helper: is_caskdf_scheme
#
# Purpose:
# Detect CasKDF either as:
# - a first-class CBOM combiner primitive, or
# - a KDF-like component whose name indicates cascade behavior.
# ---------------------------------------------------------
#
is_caskdf_scheme(component) if {
    is_combiner_primitive(component)
    is_caskdf_name(component)
} else if {
    is_kdf_primitive(component)
    is_caskdf_name(component)
}

#
# ---------------------------------------------------------
# Helper: is_possible_caskdf_composition
#
# Purpose:
# Heuristically detect CasKDF-style composition.
#
# Rationale:
# - CasKDF is a cascade construction.
# - CBOM usually does not expose data-flow/order between KDF calls.
# - Multiple KDF components in the same source context may indicate
#   a cascade-style key combiner.
#
# Limitations:
# - This is heuristic.
# - Same-file matching is weaker than same-line matching.
# - Manual review is required.
# ---------------------------------------------------------
#
is_possible_caskdf_composition(kdf_component_a, kdf_component_b) if {
    is_kdf_primitive(kdf_component_a)
    is_kdf_primitive(kdf_component_b)
    kdf_component_a["bom-ref"] != kdf_component_b["bom-ref"]
    shares_evidence_location_and_line(kdf_component_a, kdf_component_b)
} else if {
    is_kdf_primitive(kdf_component_a)
    is_kdf_primitive(kdf_component_b)
    kdf_component_a["bom-ref"] != kdf_component_b["bom-ref"]
    same_source_file(kdf_component_a, kdf_component_b)
}

#
# ---------------------------------------------------------
# Helper: is_agreed_key_combiner_scheme
#
# Purpose:
# Identify key combiner schemes listed as agreed by ECCG.
#
# ECCG agreed key combiners:
# - CatKDF [ETSI]
# - CasKDF [ETSI]
#
# Notes:
# - This checks scheme family only.
# - It does not prove that the construction is implemented correctly.
# ---------------------------------------------------------
#
is_agreed_key_combiner_scheme(component) if {
    is_catkdf_scheme(component)
} else if {
    is_caskdf_scheme(component)
}

#
# ---------------------------------------------------------
# Helper: component_matches_scheme
#
# True if a component matches the requested higher-level scheme.
# Extend this helper as new scheme families are needed.
# ---------------------------------------------------------
#
component_matches_scheme(component, scheme) if {
    scheme == "hmac"
    is_hmac_scheme(component)
} else if {
    scheme == "cmac"
    is_cmac_scheme(component)
} else if {
    scheme == "hkdf"
    is_hkdf_scheme(component)
} else if {
    scheme == "pbkdf2"
    is_pbkdf2_scheme(component)
}

#
# ---------------------------------------------------------
# Helper: get_underlying_hash_component
#
# Purpose:
# Resolve the hash function used inside an HMAC-like construction.
#
# Behavior:
# - Delegates to get_related_component_by_primitive to locate
#   a related hash component.
#
# Notes:
# - This helper assumes the caller is working with an HMAC-like MAC.
# - Relationship resolution is heuristic (dependency edges first,
#   then source co-location).
# - Returns undefined if no matching component is found.
#
# ---------------------------------------------------------
# Usage example:
#
# hash := get_underlying_hash_component(component)
#
# if hash.name == "SHA1" {
#     # flag legacy HMAC-SHA1 usage
# }
#
# Precondition:
# - component is a MAC primitive
# - component implements an HMAC-like scheme
# ---------------------------------------------------------
#
get_underlying_hash_component(mac_component) := hash_component if {
    is_mac_primitive(mac_component)
    is_hmac_scheme(mac_component)

    hash_component := get_related_component_by_primitive(mac_component, "hash")
}


#
# ---------------------------------------------------------
# Helper: get_underlying_block_cipher_component
#
# Purpose:
# Resolve the block cipher used inside a CMAC-like construction.
#
# Behavior:
# - Delegates to get_related_component_by_primitive to locate
#   a related block cipher component.
#
# Notes:
# - This helper assumes the caller is working with a CMAC-like MAC.
# - Relationship resolution depends on CBOM quality.
# - Returns undefined if no matching component is found.
#
# ---------------------------------------------------------
# Usage example:
#
# cipher := get_underlying_block_cipher_component(component)
#
# if cipher.name != "AES" {
#     # flag non-agreed CMAC construction
# }
#
# Precondition:
# - component is a MAC primitive
# - component implements a CMAC-like scheme
# ---------------------------------------------------------
#
get_underlying_block_cipher_component(mac_component) := cipher_component if {
    is_mac_primitive(mac_component)
    is_cmac_scheme(mac_component)

    cipher_component := get_related_component_by_primitive(mac_component, "block-cipher")
}


#
# ---------------------------------------------------------
# Helper: get_underlying_hash_for_hkdf
#
# Purpose:
# Resolve the hash function used inside an HKDF construction.
#
# Behavior:
# - Delegates to get_related_component_by_primitive to locate
#   a related hash component.
#
# Notes:
# - This helper is specific to HKDF-like KDF constructions.
# - CBOM extraction may not always capture dependencies,
#   so fallback heuristics may apply.
#
# ---------------------------------------------------------
# Usage example:
#
# hash := get_underlying_hash_for_hkdf(component)
#
# if hash.name == "SHA1" {
#     # flag weak HKDF configuration
# }
#
# Precondition:
# - component is a KDF primitive
# - component implements HKDF
# ---------------------------------------------------------
#
get_underlying_hash_for_hkdf(kdf_component) := hash_component if {
    is_kdf_primitive(kdf_component)
    is_hkdf_scheme(kdf_component)

    hash_component := get_related_component_by_primitive(kdf_component, "hash")
}

#
# ---------------------------------------------------------
# Helper: get_inner_algorithm_parameter_size_or_unknown
#
# Purpose:
# Return the parameter size of the underlying primitive used
# inside a MAC construction.
#
# Examples:
# - HMAC-SHA256 → 256   (derived from SHA-256 output size)
# - HMAC-SHA1   → 160   (derived from SHA-1 output size)
# - AES-CMAC    → 128   (derived from AES block size)
#
# Important:
# - This is NOT the runtime MAC key size.
# - This reflects the security parameter of the underlying
#   primitive (hash output size or block size).
# - The result depends on correctly resolving the underlying
#   component via CBOM relationships.
#
# Behavior:
# - If the MAC is HMAC-like → resolve underlying hash
# - If the MAC is CMAC-like → resolve underlying block cipher
# - Otherwise → return "unknown"
#
# ---------------------------------------------------------
# Usage example:
#
# size := get_inner_algorithm_parameter_size_or_unknown(component)
#
# if size < 128 {
#     # flag weak underlying primitive
# }
#
# Precondition:
# - component should be a MAC construction (e.g., HMAC, CMAC)
# ---------------------------------------------------------
#
get_inner_algorithm_parameter_size_or_unknown(mac_component) := size if {
    is_hmac_scheme(mac_component)
    hash_component := get_underlying_hash_component(mac_component)
    size := get_parameter_set_identifier_to_number_or_unknown(hash_component)
} else := size if {
    is_cmac_scheme(mac_component)
    cipher_component := get_underlying_block_cipher_component(mac_component)
    size := get_parameter_set_identifier_to_number_or_unknown(cipher_component)
} else := "unknown"


#
# ---------------------------------------------------------
# Helper: get_inner_algorithm_name_or_unknown
#
# Purpose:
# Return the name of the underlying primitive used inside
# a MAC construction.
#
# Examples:
# - HMAC-SHA256 → "SHA256"
# - HMAC-SHA1   → "SHA1"
# - AES-CMAC    → "AES"
#
# Behavior:
# - If the MAC is HMAC-like → return underlying hash name
# - If the MAC is CMAC-like → return underlying block cipher name
# - Otherwise → return "unknown"
#
# Notes:
# - The result depends on CBOM relationship resolution.
# - This helper does not validate correctness of the scheme;
#   callers should ensure the component is a valid MAC.
#
# ---------------------------------------------------------
# Usage example:
#
# alg := get_inner_algorithm_name_or_unknown(component)
#
# if alg == "SHA1" {
#     # flag legacy HMAC usage
# }
#
# Precondition:
# - component should be a MAC construction (e.g., HMAC, CMAC)
# ---------------------------------------------------------
#
get_inner_algorithm_name_or_unknown(mac_component) := name if {
    is_hmac_scheme(mac_component)
    hash_component := get_underlying_hash_component(mac_component)
    name := hash_component.name
} else := name if {
    is_cmac_scheme(mac_component)
    cipher_component := get_underlying_block_cipher_component(mac_component)
    name := cipher_component.name
} else := "unknown"


#
# ---------------------------------------------------------
# Helper: is_possible_cbc_hmac_composition
#
# Heuristic detection of a CBC + HMAC-based construction.
#
# Returns true when:
# - a CBC-mode encryption component is present, and
# - an HMAC-based MAC component is present, and
# - both share the same source location and line.
#
# This pattern corresponds to the common building blocks used in:
# - Encrypt-then-MAC (agreed, ECCG R)
# - MAC-then-Encrypt (legacy, ECCG L[2025])
# - Encrypt-and-MAC (legacy, ECCG L[2025])
#
# Limitations:
# - This helper only detects the presence of the building blocks.
# - It cannot determine which composition pattern is implemented.
# - It assumes CBOM evidence aligns both operations to the same line,
#   which may not always be the case in real code.
#
# Intended use:
# - support heuristic findings about ambiguous or possible AE
#   constructions involving CBC and HMAC.
# ---------------------------------------------------------
#
is_possible_cbc_hmac_composition(enc_component, mac_component) if {
    is_cbc_scheme(enc_component)
    is_hmac_scheme(mac_component)
    shares_evidence_location_and_line(enc_component, mac_component)
} else if {
    is_symmetric_encryption_scheme(enc_component)
    is_mac_primitive(mac_component)
    same_source_file(enc_component, mac_component)
}

#
# Resolve the hash function used by a KDF component.
#
# Preconditions:
# - kdf_component is a KDF primitive.
#
# Relationship resolution is delegated to get_related_component_by_primitive,
# which prefers CBOM dependency edges and falls back to same file+line evidence.
#
get_underlying_hash_component_for_kdf(kdf_component) := hash_component if {
    is_kdf_primitive(kdf_component)

    hash_component := get_related_component_by_primitive(kdf_component, "hash")
}

#
# Return the underlying hash name for a KDF component if known.
#
get_kdf_underlying_hash_name_or_unknown(kdf_component) := name if {
    hash_component := get_underlying_hash_component_for_kdf(kdf_component)
    name := hash_component.name
} else := "unknown"

#
# Return the underlying hash parameter size for a KDF component if known.
#
get_kdf_underlying_hash_parameter_size_or_unknown(kdf_component) := size if {
    hash_component := get_underlying_hash_component_for_kdf(kdf_component)
    size := get_parameter_set_identifier_to_number_or_unknown(hash_component)
} else := "unknown"

#
# PBKDF2 PRF inference helper.
#
# In the current CBOM, PBKDF2 appears as "PBKDF2-SHA256" and depends on SHA256.
# We conservatively infer the PRF as HMAC-<hash>.
#
get_pbkdf2_prf_or_unknown(component) := prf if {
    is_pbkdf2_scheme(component)

    hash_name := get_kdf_underlying_hash_name_or_unknown(component)
    hash_name != "unknown"

    prf := sprintf("HMAC-%s", [hash_name])
} else := "unknown"

