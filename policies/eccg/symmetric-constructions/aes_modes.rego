package cbom.eccg.symmetric_constructions.aes_modes

import data.eccg.eccg_notes.notes

import data.cbom.eccg.helpers.get_mode_or_unknown
import data.cbom.eccg.helpers.get_primitive_or_unknown
import data.cbom.eccg.helpers.get_note
import data.cbom.eccg.helpers.is_symmetric_encryption_scheme
import data.cbom.eccg.helpers.build_finding
import data.cbom.eccg.helpers.is_gcm_primitive

import data.cbom.eccg.symmetric_constructions.helpers.is_agreed_symmetric_encryption_scheme
import data.cbom.eccg.symmetric_constructions.helpers.is_conditionally_agreed_symmetric_encryption_scheme
import data.cbom.eccg.symmetric_constructions.helpers.is_padding_sensitive_scheme
import data.cbom.eccg.symmetric_constructions.helpers.is_stream_mode_scheme
import data.cbom.eccg.symmetric_constructions.helpers.is_cbc_scheme
import data.cbom.eccg.symmetric_constructions.helpers.agreed_symmetric_encryption_scheme_names
import data.cbom.eccg.symmetric_constructions.helpers.is_symmetric_encryption_scheme_requiring_iv
import data.cbom.eccg.symmetric_constructions.helpers.is_symmetric_encryption_scheme_requiring_unpredictable_iv
import data.cbom.eccg.symmetric_constructions.helpers.iv_requirement_message

default compliant := true

compliant if count(findings) == 0

SECTION := "Symmetric-Constructions"
SUBSECTION := "Symmetric-Encryption-Schemes"

#
# Rule ECCG-SYM-ENC-001
# Flag schemes not in the agreed symmetric encryption scheme list.
#
findings contains finding if {
    some component_index
    component := input.components[component_index]

    is_symmetric_encryption_scheme(component)
    not is_agreed_symmetric_encryption_scheme(component)

    finding := build_finding(
        "ECCG-SYM-ENC-001",
        "critical",
        sprintf(
            "Symmetric encryption scheme '%s' is not in the agreed scheme list %s. ",
            [component.name, agreed_symmetric_encryption_scheme_names]
        ),
        component,
        {
            "mode": get_mode_or_unknown(component),
            "primitive": get_primitive_or_unknown(component)
        }
    )
}

#
# Rule ECCG-SYM-ENC-002
# All R* schemes are only conditionally recommended.
# Without additional integrity, standalone use is considered legacy.
# TODO cover through semgrep?
#
findings contains finding if {
    some component_index
    component := input.components[component_index]

    is_symmetric_encryption_scheme(component)
    is_conditionally_agreed_symmetric_encryption_scheme(component)

    note := get_note(SECTION, SUBSECTION, "6-AddIntegrity")

    finding := build_finding(
        "ECCG-SYM-ENC-002",
        "warning",
        sprintf(
            "Scheme '%s' is only conditionally recommended; standalone use is legacy unless additional integrity is provided. The recommended integrity scheme Encrypt-then-MAC.",
            [component.name]
        ),
        component,
        {
            "notes": note,
            "mode": get_mode_or_unknown(component),
            "status": "conditional"
        }
    )
}

#
# Rule ECCG-SYM-ENC-003
# IV / nonce requirement.
#
# ECCG-SYM-ENC-003 applies to the subset of agreed symmetric encryption
# schemes that require an Initialization Vector (IV) or nonce-like input.
#
# Covered schemes:
# - CBC
# - CFB
# - OFB
# - GCM
#
# For CBC, CFB, OFB, and GCM, the IV / nonce input must be unique for each
# execution of the encryption operation under a given key.
#
# CBC and CFB have an additional stronger requirement:
# - the IV must also be unpredictable before the encryption operation.
#
# This corresponds to Note 5-IVType:
# - some schemes can use a nonce, meaning a value that is unique for a given key;
# - CBC and CFB require a random / unpredictable IV;
# - constant IVs are not accepted;
# - predictable IVs are not accepted for CBC and CFB.
#
# This rule is intentionally classification-based. It flags that the component
# is a mode where IV / nonce handling must be checked. It does not prove from
# the CBOM that the IV is unique, random, unpredictable, or correctly generated.
# TODO cover through semgrep
#
findings contains finding if {
    component := input.components[_]

    is_symmetric_encryption_scheme(component)
    is_symmetric_encryption_scheme_requiring_iv(component)

    note := get_note(SECTION, SUBSECTION, "5-IVType")

    finding := build_finding(
        "ECCG-SYM-ENC-003",
        "warning",
        iv_requirement_message(component),
        component,
        {
            "notes": note,
            "mode": get_mode_or_unknown(component),
            "requiresUniqueIv": true,
            "requiresUnpredictableIv": is_symmetric_encryption_scheme_requiring_unpredictable_iv(component)
        }
    )
}

#
# Rule ECCG-SYM-ENC-004
# GCM IV construction requirement.
#
# In GCM mode, the IV must be either:
# - a random 96-bit value; or
# - generated using the deterministic construction described in
#   NIST SP 800-38D section 8.2.
#
# This rule applies only to GCM. It is separate from the general IV / nonce
# uniqueness rule because GCM has a specific IV length and construction
# recommendation.
#
# This rule is classification-based. It flags that a GCM component requires
# additional IV validation. It does not prove from the CBOM that the IV is
# random, 96 bits, or constructed according to NIST SP 800-38D section 8.2.
# TODO detect it through SEMGREP 
#
findings contains finding if {
    component := input.components[_]

    is_symmetric_encryption_scheme(component)
    is_gcm_primitive(component)

    finding := build_finding(
        "ECCG-SYM-ENC-004",
        "warning",
        "In GCM mode, the IV must be either a random 96-bit value, or generated using the construction described in NIST SP 800-38D section 8.2.",
        component,
        {
            "mode": get_mode_or_unknown(component),
            "requiredIvBits": 96,
            "acceptedIvConstructions": [
                "random-96-bit",
                "nist-sp-800-38d-section-8.2"
            ]
        }
    )
}


#
# Rule ECCG-SYM-ENC-005
# GCM plaintext length limit.
#
# In GCM mode, the length of the plaintext must be at most 2^32 - 2 blocks.
#
# This is a GCM-specific operational limit. It is separate from the general
# IV / nonce uniqueness rule and from the GCM IV construction rule.
#
# This rule is classification-based because the CBOM usually identifies that
# GCM is used, but does not prove how much plaintext is encrypted under a
# single key / IV usage domain.
# TODO have not found a way through the CBOM detect it through semgrep
#
findings contains finding if {
    component := input.components[_]

    is_symmetric_encryption_scheme(component)
    is_gcm_primitive(component)

    finding := build_finding(
        "ECCG-SYM-ENC-005",
        "warning",
        "In GCM mode, the length of the plaintext must be at most 2^32 - 2 blocks.",
        component,
        {
            "mode": get_mode_or_unknown(component),
            "maximumPlaintextBlocks": 4294967294,
            "maximumPlaintextBlocksExpression": "2^32 - 2"
        }
    )
}

#
# Rule ECCG-SYM-ENC-006
# GCM MAC / authentication tag length requirement.
#
# In GCM mode, the length of the MAC, also called the authentication tag, must
# be at least 128 bits.
#
# GCM is an authenticated encryption mode. It produces an authentication tag
# rather than requiring a separate external MAC such as HMAC.
#
# This rule applies only to GCM. It flags that the GCM tag length must be
# validated by implementation review or by richer metadata if the CBOM contains
# tag-length information.
#
# This rule is classification-based. It does not prove from the CBOM that the
# MAC / tag length is below 128 bits.
#
findings contains finding if {
    component := input.components[_]

    is_symmetric_encryption_scheme(component)
    is_gcm_primitive(component)

    finding := build_finding(
        "ECCG-SYM-ENC-006",
        "warning",
        "In GCM mode, the length of the MAC/authentication tag must be at least 128 bits.",
        component,
        {
            "mode": get_mode_or_unknown(component),
            "minimumMacBits": 128,
            "minimumAuthenticationTagBits": 128,
            "macType": "GCM authentication tag"
        }
    )
}

#
# Rule ECCG-SYM-ENC-004
# Stream-mode warning for CTR and OFB.
# The note says IV-key reuse must not cause keystream overlap.
#
#findings contains finding if {
#    some component_index
#    component := input.components[component_index]
#
#    is_symmetric_encryption_scheme(component)
#    is_stream_mode_scheme(component)
#
#    note := get_note(SECTION, SUBSECTION, "7-StreamMode")
#
#    finding := build_finding(
#        "ECCG-SYM-ENC-004",
#        "warning",
#        sprintf(
#            "Scheme '%s' is a stream-mode construction; IV-key reuse must not cause keystream overlap",
#            [component.name]
#        ),
#        component,
#        {
#            "notes": note,
#            "mode": get_mode_or_unknown(component)
#        }
#    )
#}

#
# Rule ECCG-SYM-ENC-005
# Padding-related warning for padding-sensitive schemes.
#
#findings contains finding if {
#    some component_index
#    component := input.components[component_index]
#
#    is_symmetric_encryption_scheme(component)
#    is_padding_sensitive_scheme(component)
#
#    note := get_note(SECTION, SUBSECTION, "8-Padding")
#
#    finding := build_finding(
#        "ECCG-SYM-ENC-005",
#        "warning",
#        sprintf(
#            "Scheme '%s' requires careful padding handling; implementations should not expose padding-oracle behavior",
#            [component.name]
#        ),
#        component,
#        {
#            "notes": note,
#            "mode": get_mode_or_unknown(component)
#        }
#    )
#}