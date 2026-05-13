package cbom.eccg.asymmetric_atomic_primitives.helpers

import data.cbom.eccg.helpers.is_public_key_primitive
import data.cbom.eccg.helpers.get_name_or_unknown
import data.cbom.eccg.helpers.normalize_crypto_name
import data.cbom.eccg.helpers.normalize_ec_curve_name

#
# ---------------------------------------------------------
# Helper: eccg_recommended_ec_curve_names
#
# Purpose:
# Set of normalized curve identifiers accepted by ECCG for the
# EC-DLOG parameter table.
#
# Includes:
# - Direct CycloneDX registry names
# - Common aliases for the same recommended curves
#
# NIST aliases:
# - nist/P-256       == secg/secp256r1 == x962/prime256v1 == prime256v1
# - nist/P-384       == secg/secp384r1
# - nist/P-521       == secg/secp521r1
#
# Brainpool aliases:
# - brainpool/brainpoolP256r1
# - brainpool/brainpoolP384r1
# - brainpool/brainpoolP512r1
#
# FR aliases:
# - anssi/FRP256v1
# - FRP256v1
# ---------------------------------------------------------
#
eccg_recommended_ec_curve_names contains "brainpoolbrainpoolp256r1"
eccg_recommended_ec_curve_names contains "brainpoolp256r1"

eccg_recommended_ec_curve_names contains "brainpoolbrainpoolp384r1"
eccg_recommended_ec_curve_names contains "brainpoolp384r1"

eccg_recommended_ec_curve_names contains "brainpoolbrainpoolp512r1"
eccg_recommended_ec_curve_names contains "brainpoolp512r1"

eccg_recommended_ec_curve_names contains "nistp256"
eccg_recommended_ec_curve_names contains "p256"
eccg_recommended_ec_curve_names contains "secgsecp256r1"
eccg_recommended_ec_curve_names contains "secp256r1"
eccg_recommended_ec_curve_names contains "x962prime256v1"
eccg_recommended_ec_curve_names contains "prime256v1"

eccg_recommended_ec_curve_names contains "nistp384"
eccg_recommended_ec_curve_names contains "p384"
eccg_recommended_ec_curve_names contains "secgsecp384r1"
eccg_recommended_ec_curve_names contains "secp384r1"

eccg_recommended_ec_curve_names contains "nistp521"
eccg_recommended_ec_curve_names contains "p521"
eccg_recommended_ec_curve_names contains "secgsecp521r1"
eccg_recommended_ec_curve_names contains "secp521r1"

eccg_recommended_ec_curve_names contains "anssifrp256v1"
eccg_recommended_ec_curve_names contains "frp256v1"

is_rsa_primitive(component) if {
    is_public_key_primitive(component)
    name := get_name_or_unknown(component)
    normalized_name := normalize_crypto_name(name)
    contains(normalized_name, "rsa")
}



classify_rsa_modulus(n) = "recommended" if {
    n >= 3000
} else = "legacy" if {
    n >= 1900
} else = "disallowed" if {
    true
}

#
# ---------------------------------------------------------
# Helper: is_ffdlog_primitive
#
# Purpose:
# Detect finite-field discrete logarithm (FF-DLOG) primitives
# and closely related finite-field Diffie-Hellman groups.
#
# ECCG context:
# - FF-DLOG refers to the finite-field discrete logarithm
#   hardness assumption.
# - MODP groups [RFC3526] and FFDHE groups [RFC7919] are
#   finite-field groups used by Diffie-Hellman-style schemes.
#
# Key clarification:
# - FFDHE (Finite Field Diffie-Hellman Ephemeral) operates in
#   the multiplicative group of a finite field:
#       X = g^x mod p
# - Therefore:
#       FFDHE ⇒ FF-DLOG primitive
#
# Detection strategy:
# - Prefer explicit FF-DLOG indicators when present.
# - Detect standardized group names such as:
#     • FFDHE (including TLS named groups like ffdhe2048)
#     • MODP
# - Fall back to finite-field Diffie-Hellman naming:
#     • DH
#
# Rationale:
# CycloneDX / CBOM tools may not emit "FF-DLOG" directly.
# In practice, finite-field DH components represent usage of
# the FF-DLOG primitive/assumption.
#
# Notes:
# - This helper explicitly treats FFDHE as FF-DLOG.
# - This helper must NOT match elliptic-curve Diffie-Hellman:
#     • ECDH, ECDHE
#     • X25519, X448
# - Name matching is normalized to tolerate formatting differences.
# ---------------------------------------------------------
#
is_ffdlog_primitive(component) if {
    name := get_name_or_unknown(component)
    normalized_name := normalize_crypto_name(name)

    # Explicit FF-DLOG naming
    contains(normalized_name, "ffdlog")
} else if {
    name := get_name_or_unknown(component)
    normalized_name := normalize_crypto_name(name)

    # FFDHE groups (e.g., ffdhe2048, ffdhe3072)
    # → Direct mapping to FF-DLOG
    contains(normalized_name, "ffdhe")
} else if {
    name := get_name_or_unknown(component)
    normalized_name := normalize_crypto_name(name)

    # MODP groups (RFC3526)
    contains(normalized_name, "modp")
} else if {
    props := component.cryptoProperties.algorithmProperties

    family := object.get(props, "algorithmFamily", "")
    normalized_family := normalize_crypto_name(family)

    contains(normalized_family, "ffdlog")
} else if {
    props := component.cryptoProperties.algorithmProperties

    primitive := object.get(props, "primitive", "")
    normalized_primitive := normalize_crypto_name(primitive)

    contains(normalized_primitive, "ffdlog")
} else if {
    #
    # Fallback: finite-field Diffie-Hellman.
    #
    # Only match DH after excluding elliptic-curve variants.
    #
    name := get_name_or_unknown(component)
    normalized_name := normalize_crypto_name(name)

    not contains(normalized_name, "ecdh")
    not contains(normalized_name, "ecdhe")
    not contains(normalized_name, "x25519")
    not contains(normalized_name, "x448")

    contains(normalized_name, "dh")
} else if {
    #
    # Fallback: finite-field Diffie-Hellman.
    #
    # Only match DH after excluding elliptic-curve variants.
    #
    name := get_name_or_unknown(component)
    normalized_name := normalize_crypto_name(name)

    not contains(normalized_name, "ecdh")
    not contains(normalized_name, "ecdhe")
    not contains(normalized_name, "x25519")
    not contains(normalized_name, "x448")

    contains(normalized_name, "dhe")
}

#
# ---------------------------------------------------------
# Helper: is_ecdlog_primitive
#
# Purpose:
# Detect elliptic-curve discrete logarithm (EC-DLOG) primitives
# and elliptic-curve constructions that rely on EC-DLOG.
#
# ECCG context:
# - EC-DLOG refers to the discrete logarithm problem in the group
#   of rational points of an elliptic curve over a finite field.
# - ECCG agrees only elliptic curves over prime fields.
#
# Detection strategy:
# - Detect EC key-agreement algorithms:
#     • ECDH
#     • ECDHE
#     • X25519
#     • X448
# - Detect EC signature algorithms:
#     • ECDSA
#     • Ed25519
#     • Ed448
#     • EdDSA
# - Detect EC encryption schemes:
#     • ECIES
#     • EC-ElGamal
#
# Notes:
# - X3DH is a protocol built on EC key agreement, not itself an
#   atomic primitive. It should normally be handled at protocol level.
# - This helper detects EC-DLOG usage; curve compliance is checked
#   separately by is_eccg_recommended_ec_curve().
# ---------------------------------------------------------
#
is_ecdlog_primitive(component) if {
    name := get_name_or_unknown(component)
    normalized_name := normalize_crypto_name(name)

    contains(normalized_name, "ecdh")
} else if {
    name := get_name_or_unknown(component)
    normalized_name := normalize_crypto_name(name)

    contains(normalized_name, "ecdhe")
} else if {
    name := get_name_or_unknown(component)
    normalized_name := normalize_crypto_name(name)

    contains(normalized_name, "x25519")
} else if {
    name := get_name_or_unknown(component)
    normalized_name := normalize_crypto_name(name)

    contains(normalized_name, "x448")
} else if {
    name := get_name_or_unknown(component)
    normalized_name := normalize_crypto_name(name)

    contains(normalized_name, "ecdsa")
} else if {
    name := get_name_or_unknown(component)
    normalized_name := normalize_crypto_name(name)

    contains(normalized_name, "eddsa")
} else if {
    name := get_name_or_unknown(component)
    normalized_name := normalize_crypto_name(name)

    contains(normalized_name, "ed25519")
} else if {
    name := get_name_or_unknown(component)
    normalized_name := normalize_crypto_name(name)

    contains(normalized_name, "ed448")
} else if {
    name := get_name_or_unknown(component)
    normalized_name := normalize_crypto_name(name)

    contains(normalized_name, "ecies")
} else if {
    name := get_name_or_unknown(component)
    normalized_name := normalize_crypto_name(name)

    contains(normalized_name, "ecelgamal")
}

#
# ---------------------------------------------------------
# Helper: is_eccg_recommended_ec_curve
#
# Purpose:
# Match elliptic curves against the ECCG recommended EC-DLOG
# parameter table.
#
# ECCG recommended curves:
#
# Brainpool [RFC5639]
# - BrainpoolP256r1
# - BrainpoolP384r1
# - BrainpoolP512r1
#
# NIST [FIPS 186-4, Appendix D.1.2]
# - NIST P-256
# - NIST P-384
# - NIST P-521
#
# FR [JORF]
# - FRP256v1
#
# Important:
# - ECCG recommends the above named curves.
# - Other curves in the CycloneDX registry, such as BLS, BN,
#   secp256k1, binary NIST B/K curves, GOST, SM2, NUMS, and
#   miscellaneous curves, are not matched here.
# ---------------------------------------------------------
#
is_eccg_recommended_ec_curve(curve) if {
    normalized := normalize_ec_curve_name(curve)
    normalized in eccg_recommended_ec_curve_names
}


#
# ---------------------------------------------------------
# Helper: get_eccg_ec_curve_family_or_unknown
#
# Purpose:
# Return the ECCG curve family for a recommended curve.
#
# Families from ECCG:
# - Brainpool [RFC5639]
# - NIST [FIPS186-4, Appendix D.1.2]
# - FR [JORF]
# ---------------------------------------------------------
#
get_eccg_ec_curve_family_or_unknown(curve) := "Brainpool [RFC5639]" if {
    normalized := normalize_ec_curve_name(curve)
    startswith(normalized, "brainpool")
} else := "NIST [FIPS186-4, Appendix D.1.2]" if {
    normalized := normalize_ec_curve_name(curve)

    some alias in {
        "nistp256",
        "p256",
        "secgsecp256r1",
        "secp256r1",
        "x962prime256v1",
        "prime256v1",
        "nistp384",
        "p384",
        "secgsecp384r1",
        "secp384r1",
        "nistp521",
        "p521",
        "secgsecp521r1",
        "secp521r1"
    }

    normalized == alias
} else := "FR [JORF]" if {
    normalized := normalize_ec_curve_name(curve)

    some alias in {
        "anssifrp256v1",
        "frp256v1"
    }

    normalized == alias
} else := "unknown"

#
# ---------------------------------------------------------
# Helper: get_eccg_canonical_ec_curve_or_unknown
#
# Purpose:
# Map registry/library aliases to the canonical curve names used
# in the ECCG table.
#
# ECCG canonical names:
# - BrainpoolP256r1
# - BrainpoolP384r1
# - BrainpoolP512r1
# - NIST P-256
# - NIST P-384
# - NIST P-521
# - FRP256v1
# ---------------------------------------------------------
#
get_eccg_canonical_ec_curve_or_unknown(curve) := "BrainpoolP256r1" if {
    normalized := normalize_ec_curve_name(curve)

    some alias in {
        "brainpoolbrainpoolp256r1",
        "brainpoolp256r1"
    }

    normalized == alias
} else := "BrainpoolP384r1" if {
    normalized := normalize_ec_curve_name(curve)

    some alias in {
        "brainpoolbrainpoolp384r1",
        "brainpoolp384r1"
    }

    normalized == alias
} else := "BrainpoolP512r1" if {
    normalized := normalize_ec_curve_name(curve)

    some alias in {
        "brainpoolbrainpoolp512r1",
        "brainpoolp512r1"
    }

    normalized == alias
} else := "NIST P-256" if {
    normalized := normalize_ec_curve_name(curve)

    some alias in {
        "nistp256",
        "p256",
        "secgsecp256r1",
        "secp256r1",
        "x962prime256v1",
        "prime256v1"
    }

    normalized == alias
} else := "NIST P-384" if {
    normalized := normalize_ec_curve_name(curve)

    some alias in {
        "nistp384",
        "p384",
        "secgsecp384r1",
        "secp384r1"
    }

    normalized == alias
} else := "NIST P-521" if {
    normalized := normalize_ec_curve_name(curve)

    some alias in {
        "nistp521",
        "p521",
        "secgsecp521r1",
        "secp521r1"
    }

    normalized == alias
} else := "FRP256v1" if {
    normalized := normalize_ec_curve_name(curve)

    some alias in {
        "anssifrp256v1",
        "frp256v1"
    }

    normalized == alias
} else := "unknown"

#
# ---------------------------------------------------------
# Helper: is_eccg_nist_special_p_curve
#
# Purpose:
# Identify ECCG-recommended NIST prime curves that are subject
# to ECCG note 39-SpecialP.
#
# ECCG context:
# In the EC-DLOG parameter table, the following NIST curves are
# recommended, but are associated with the specific note:
#
#   - NIST P-256
#   - NIST P-384
#   - NIST P-521
#
# ECCG note:
# - 39-SpecialP
#
# Rationale:
# The prime number p used by these curves has a special form.
# ECCG notes that this can make side-channel attacks more efficient
# than with a random prime, and not only because finite-field
# arithmetic is faster.
#
# Detection strategy:
# - First normalize/map the input curve identifier to the canonical
#   ECCG curve name using get_eccg_canonical_ec_curve_or_unknown().
# - Then check whether the canonical curve is one of the NIST curves
#   that carry the SpecialP note.
#
# Examples matched:
# - nist/P-256
# - secg/secp256r1
# - x962/prime256v1
# - nist/P-384
# - secg/secp384r1
# - nist/P-521
# - secg/secp521r1
#
# Notes:
# - This helper does not determine whether a curve is recommended.
#   Use is_eccg_recommended_ec_curve() for recommendation status.
# - This helper only indicates whether note 39-SpecialP should be
#   attached to the finding.
# ---------------------------------------------------------
#
is_eccg_nist_special_p_curve(curve) if {
    canonical := get_eccg_canonical_ec_curve_or_unknown(curve)

    some c in {
        "NIST P-256",
        "NIST P-384",
        "NIST P-521"
    }

    canonical == c
}