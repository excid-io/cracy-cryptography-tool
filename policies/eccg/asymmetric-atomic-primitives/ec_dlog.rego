package cbom.eccg.asymmetric_atomic_primitives.ec_dlog

import data.cbom.eccg.helpers.get_note
import data.cbom.eccg.helpers.build_finding
import data.cbom.eccg.helpers.get_ec_curve_or_unknown

import data.cbom.eccg.asymmetric_atomic_primitives.helpers.is_ecdlog_primitive
import data.cbom.eccg.asymmetric_atomic_primitives.helpers.is_eccg_recommended_ec_curve
import data.cbom.eccg.asymmetric_atomic_primitives.helpers.get_eccg_ec_curve_family_or_unknown
import data.cbom.eccg.asymmetric_atomic_primitives.helpers.get_eccg_canonical_ec_curve_or_unknown
import data.cbom.eccg.asymmetric_atomic_primitives.helpers.is_eccg_nist_special_p_curve

SECTION = "Asymmetric-Atomic-Primitives"
SUBSECTION = "EC-DLOG"

#
# ---------------------------------------------------------
# ECCG-ECDLOG-001
# EC-DLOG primitive uses an agreed elliptic curve.
#
# ECCG classification: R
#
# Applies to:
# - BrainpoolP256r1
# - BrainpoolP384r1
# - BrainpoolP512r1
# - NIST P-256
# - NIST P-384
# - NIST P-521
# - FRP256v1
#
# Notes:
# - NIST curves carry ECCG note 39-SpecialP.
#
# Implementation note:
# - This rule excludes NIST SpecialP curves so that those curves
#   are reported only once by ECCG-ECDLOG-002.
# ---------------------------------------------------------
#
findings contains finding if {
    component := input.components[_]

    is_ecdlog_primitive(component)

    curve := get_ec_curve_or_unknown(component)
    curve != "unknown"

    is_eccg_recommended_ec_curve(curve)
    not is_eccg_nist_special_p_curve(curve)

    canonical_curve := get_eccg_canonical_ec_curve_or_unknown(curve)
    curve_family := get_eccg_ec_curve_family_or_unknown(curve)

    finding := build_finding(
        "ECCG-ECDLOG-001",
        "info",
        sprintf(
            "EC-DLOG primitive detected with agreed elliptic curve %s. Classified as recommended.",
            [canonical_curve]
        ),
        component,
        {
            "scheme": "EC-DLOG",
            "curve": canonical_curve,
            "curveFamily": curve_family,
            "status": "recommended",
            "classification": "R"
        }
    )
}

#
# ---------------------------------------------------------
# ECCG-ECDLOG-002
# EC-DLOG primitive uses an agreed NIST elliptic curve with
# SpecialP note.
#
# ECCG classification: R
#
# Applies to:
# - NIST P-256
# - NIST P-384
# - NIST P-521
#
# ECCG note:
# - 39-SpecialP
#
# Rationale:
# The NIST curves are recommended, but ECCG attaches a specific
# side-channel note because the prime p has a special form.
# ---------------------------------------------------------
#
findings contains finding if {
    component := input.components[_]

    is_ecdlog_primitive(component)

    curve := get_ec_curve_or_unknown(component)
    curve != "unknown"

    is_eccg_recommended_ec_curve(curve)
    is_eccg_nist_special_p_curve(curve)

    canonical_curve := get_eccg_canonical_ec_curve_or_unknown(curve)
    curve_family := get_eccg_ec_curve_family_or_unknown(curve)
    special_p_note := get_note(SECTION, SUBSECTION, "39-SpecialP")

    finding := build_finding(
        "ECCG-ECDLOG-002",
        "info",
        sprintf(
            "EC-DLOG primitive detected with agreed NIST elliptic curve %s. Classified as recommended; ECCG note 39-SpecialP applies.",
            [canonical_curve]
        ),
        component,
        {
            "scheme": "EC-DLOG",
            "curve": canonical_curve,
            "curveFamily": curve_family,
            "status": "recommended",
            "classification": "R",
            "note": special_p_note
        }
    )
}

#
# ---------------------------------------------------------
# ECCG-ECDLOG-003
# EC-DLOG primitive uses an elliptic curve that is not listed
# as agreed in the ECCG EC-DLOG parameter table.
#
# ECCG classification: Not agreed / non-compliant
#
# Important:
# - This does NOT necessarily mean the curve is cryptographically unsafe.
# - It means the curve is not part of the ECCG agreed EC-DLOG
#   parameter set shown in the table.
#
# Examples of curves that may be valid elsewhere but are not in
# this ECCG table:
# - secp256k1
# - X25519 / Curve25519
# - X448 / Curve448
# - Ed25519
# - Ed448
# - SM2
# - GOST curves
# - BLS / BN pairing curves
# - NIST binary curves B-* / K-*
#
# ECCG agreed curves are only:
# - BrainpoolP256r1
# - BrainpoolP384r1
# - BrainpoolP512r1
# - NIST P-256
# - NIST P-384
# - NIST P-521
# - FRP256v1
# ---------------------------------------------------------
#
findings contains finding if {
    component := input.components[_]

    is_ecdlog_primitive(component)

    curve := get_ec_curve_or_unknown(component)
    curve != "unknown"

    not is_eccg_recommended_ec_curve(curve)

    finding := build_finding(
        "ECCG-ECDLOG-003",
        "warning",
        sprintf(
            "EC-DLOG primitive detected with elliptic curve %s, which is not listed as an agreed ECCG curve.",
            [curve]
        ),
        component,
        {
            "scheme": "EC-DLOG",
            "curve": curve,
            "status": "not_agreed",
            "classification": "non_compliant",
            "complianceImpact": "Curve is not listed in the ECCG agreed EC-DLOG parameter table.",
            "safetyAssessment": "Not necessarily unsafe; requires compliance review."
        }
    )
}

#
# ---------------------------------------------------------
# ECCG-ECDLOG-004
# EC-DLOG primitive detected, but the elliptic curve could not
# be extracted from the CBOM component.
#
# ECCG classification: Inconclusive
#
# Important:
# - This does not mean the algorithm is unsafe.
# - It means the CBOM does not expose enough curve information
#   to decide whether the EC-DLOG parameters are ECCG-agreed.
#
# Typical causes:
# - algorithmProperties.ellipticCurve is missing.
# - The curve is not encoded in the component name.
# - The CBOM extractor did not preserve curve metadata.
# ---------------------------------------------------------
#
findings contains finding if {
    component := input.components[_]

    is_ecdlog_primitive(component)

    curve := get_ec_curve_or_unknown(component)
    curve == "unknown"

    finding := build_finding(
        "ECCG-ECDLOG-004",
        "warning",
        "EC-DLOG primitive detected, but the elliptic curve could not be determined from the CBOM. ECCG curve compliance could not be verified.",
        component,
        {
            "scheme": "EC-DLOG",
            "curve": "unknown",
            "status": "unknown",
            "classification": "inconclusive",
            "complianceImpact": "Unable to verify whether the curve is listed in the ECCG agreed EC-DLOG parameter table.",
            "safetyAssessment": "Not necessarily unsafe; requires CBOM enrichment or manual review."
        }
    )
}