# ECCG Cryptographic Requirements 

## Symmetric Atomic Primitives 

### Block Ciphers 
 
- ECCG-BLOCK-001: 
    - Severity: critical
    - Block cipher [cipher] is not in the agreed block cipher list. That does mean that your code is unsafe, but should probably be marked as non compliant.
- ECCG-BLOCK-002: 
    - Severity: high
    - AES uses a non-agreed key size: [x] bits. Allowed sizes are 128, 192, or 256 bits
- ECCG-BLOCK-003:
    - Severity: high
    - 3DES uses a non-agreed key size: [x] bits. Required size is 168 bits
- ECCG-BLOCK-004: 
    - Severity: high
    - 3DES will become legacy-only in 2027 and carries a small-block-size limitation (64-bit block) and a quantum-threat note    
- ECCG-BLOCK-005:
    Severity: medium
    - Cipher [cipher] uses [x]-bit keying, which is below 192 bits and should be avoided where resistance to quantum attacks is required

### Hashes 

- ECCG-HASH-001:
    - Hash function SHA224 is legacy-only (L[2025]) and is not an agreed hash function
- ECCG-HASH-002:
    - Hash function SHA512/224 is legacy-only (L[2025]) and is not an agreed hash function
- ECCG-HASH-003:
    - Hash function [hash-function] is not in the agreed hash function list. This does not mean that your code is unsafe, but this should probably be flagged as non compliant.
- ECCG-HASH-004: 
    - Hash function [hash-function] has output length [x] bits, which is below the recommended 384 bits for quantum-sensitive contexts

## Symmetric Constructions 

### Agreed Symmetric Encryption Schemes
- ECCG-SYM-ENC-001: 
    - Severity: critical
    - Symmetric encryption scheme [scheme] is not in the agreed scheme list (CTR, OFB, CBC, CBC-CS, CFB). This does not necessarily mean that your code is unsafe, but should be flagged for a warning.
- ECCG-SYM-ENC-002:
    - Severity: warning
    - Scheme [scheme] is only conditionally recommended; standalone use is legacy unless additional integrity is provided
- ECCG-SYM-ENC-003: 
    - Severity: warning
    - Modes require a non-predictable IV
- ECCG-SYM-ENC-004: 
    - Severity: warning
    - Scheme [scheme] is a stream-mode construction; IV-key reuse must not cause keystream overlap
- ECCG-SYM-ENC-005: 
    - Severity: warning
    - Scheme [scheme] requires careful padding handling; implementations should not expose padding-oracle behavior

### Agreed Disk Encryption Schemes

- ECCG-DISK-001:
    - Severity: warning
    - Disk encryption scheme [scheme] is not in the accepted disk-encryption list. XTS is agreed, while CBC-ESSIV is legacy. CBOM-based detection may be heuristic and can produce false positives.
- ECCG-DISK-002:
    - Severity: warning
    - Scheme [scheme] is a stream-mode construction and is improper for disk encryption. CBOM-based detection may be heuristic and can produce false positives.
- ECCG-DISK-003:
    - Severity: warning
    - XTS requires a unique tweak value for each encrypted block position.
- ECCG-DISK-004:
    - Severity: warning
    - CBC-ESSIV is legacy in the agreed disk encryption scheme list. CBOM-based detection may be heuristic and can produce false positives.
- ECCG-DISK-005:
    - Severity: warning
    - CBC-ESSIV requires each disk sector to use a unique sector number under a given key. CBOM-based detection may be heuristic and can produce false positives.

### Message Authentication Codes 

- ECCG-MAC-000:
    - Severity: high
    - MAC scheme [scheme] is not listed in the ECCG agreed or legacy MAC tables. This does not mean that your code is unsafe, but it should probably be flagged as non-compliant.

- ECCG-MAC-001:
    - Severity: info
    - CMAC is an agreed MAC scheme.

- ECCG-MAC-002:
    - Severity: warning
    - CBC-based construction [scheme] may correspond to manually implemented CBC-MAC. CBC-MAC is agreed only when all inputs computed under the same key have identical size.

- ECCG-HMAC-001:
    - Severity: warning
    - HMAC is listed by ECCG, but the runtime MAC key size is not available in the current CBOM, so the agreement threshold cannot be fully assessed.

- ECCG-HMAC-002:
    - Severity: high and critical after 2030
    - HMAC-SHA1 is legacy-only, L[2030]. Severity depends on the current evaluation year and legacy marker status.

- ECCG-KMAC-001:
    - Severity: warning
    - KMAC128 is listed by ECCG, but the runtime MAC key size is not available in the current CBOM, so the agreement threshold cannot be fully assessed.

- ECCG-KMAC-002:
    - Severity: warning
    - KMAC256 is listed by ECCG, but the runtime MAC key size is not available in the current CBOM, so the agreement threshold cannot be fully assessed.

- ECCG-KMAC-003:
    - Severity: warning
    - KMAC was detected, but the variant could not be determined as KMAC128 or KMAC256.

- ECCG-GMAC-001:
    - Severity: info
    - GMAC is an agreed universal-hash-function-based MAC scheme, subject to GCM/GMAC operational constraints.

- ECCG-GMAC-002:
    - Severity: warning
    - GCM-based construction [scheme] may correspond to GMAC-style authentication-only usage. This cannot be fully determined from CBOM alone.

- ECCG-MAC-003:
    - Severity: warning
    - MAC truncation requirements may apply. The current CBOM does not expose the final MAC/tag length, so truncation compliance cannot be fully assessed.

### Agreed Symmetric Authenticated Encryption Schemes

- ECCG-AE-001:
    - Severity: warning
    - GCM is an agreed authenticated-encryption scheme, if the relevant notes are followed accordingly.

- ECCG-AE-002:
    - Severity: warning
    - CCM is an agreed authenticated-encryption scheme, if the relevant notes are followed.

- ECCG-AE-003:
    - Severity: warning
    - Integrity of the ciphertext must be verified before any plaintext is released or processed, as required by Note 21-DecryptionOrder.

- ECCG-AE-004
    - Not implemented
    - EAX is not currently modeled as a first-class CBOM mode.

- ECCG-AE-005:
    - Severity: warning
    - A symmetric-encryption and MAC composition was detected. This may correspond to Encrypt-then-MAC, MAC-then-Encrypt, or Encrypt-and-MAC. Under ECCG, Encrypt-then-MAC is agreed, while MAC-then-Encrypt and Encrypt-and-MAC are legacy. Manual review is required.

### Agreed Key Protection Schemes


- ECCG-KP-001:
    - Severity: info
    - AES Key Wrap, including AES-KW and AES-KWP, is an agreed key-protection scheme.

- ECCG-KP-002:
    - Severity: info
    - SIV, RFC5297, is an agreed key-protection scheme.

### Agreed Key Derivation Functions


- ECCG-KDF-001:
    - Severity: info
    - NIST SP800-56 ABC is an agreed key derivation function.

- ECCG-KDF-002:
    - Severity: info
    - ANSI-X9.63-KDF is an agreed key derivation function.

- ECCG-KDF-003:
    - Severity: info
    - PBKDF2 is an agreed key derivation function. The detected PRF basis is [pseudo-random-function].

- ECCG-KDF-004:
    - Severity: info
    - HKDF is an agreed key derivation function.

- ECCG-KDF-006:
    - Severity: info
    - An agreed key derivation function [scheme] was detected.

- ECCG-KDF-006:
    - Severity: critical
    - A key derivation function component was detected but is not currently classified as an agreed ECCG KDF by this policy. This does not mean that your code is unsafe, but it should be flagged as non-compliant.

### Agreed Password Hashing Mechanisms


- ECCG-PWH-001:
    - Severity: info
    - Password hashing mechanism [scheme] is based on PBKDF2, which is the agreed password hashing mechanism.
- ECCG-PWH-002:
    - Severity: high
    - PBKDF2 is the agreed password hashing scheme, but PBKDF2-SHA1 relies on legacy SHA-1 and should not be used.
- ECCG-PWH-003
    - Not implemented
    - Non-agreed password hashing schemes should be flagged. CBOMkit currently represents password hashing mechanisms only as generic key-derivation components. The CBOM does not reliably expose whether a KDF is being used specifically for password hashing, password verification, or general-purpose key derivation.

### Agreed Key Combiners

### Key Combiners

- ECCG-KC-001:
    - Severity: info
    - CatKDF / Concatenate-then-KDF is an agreed key combiner mechanism. Detection may be based on ConcatKDFHash or ConcatKDFHMAC because CBOMkit may not model CatKDF as a first-class combiner.

- ECCG-KC-002:
    - Severity: info
    - CasKDF / Cascade-KDF is an agreed key combiner mechanism. Direct detection is unlikely unless the CBOM explicitly names the construction.

- ECCG-KC-003:
    - Severity: info
    - Multiple KDF components were detected in a shared source context. This may correspond to a CasKDF / Cascade-KDF key combiner, but CBOM does not expose ordering or data-flow semantics. Manual review is required.

- ECCG-KC-004:
    - Severity: critical
    - Key combiner scheme [scheme] is not listed in the ECCG agreed key combiner table. This does not mean that your code is unsafe, but it should probably be flagged as non-compliant.

## Asymmetric Atomic Primitives 

### RSA Integer Factorization

- ECCG-RSA-001:
    - Severity: info
    - RSA primitive was detected with modulus size n=[x] bits and is classified as recommended. The ECCG exponent condition log2(e) > 16 could not be verified from CycloneDX data.

- ECCG-RSA-002:
    - Severity: critical
    - RSA primitive was detected with Legacy[2025] modulus size n=[x] bits ( 1900 <= bits < 3000 ). The ECCG exponent condition log2(e) > 16 could not be verified from CycloneDX data.

### Agreed FF-DLOG Parameters

- ECCG-FFDLOG-001:
    - Severity: info
    - FF-DLOG primitive was detected with group size p=[x] bits and is classified as recommended.

- ECCG-FFDLOG-002:
    - Severity: critical
    - FF-DLOG primitive was detected with legacy group size p=[x] bits and is classified as Legacy[2025].

### Agreed Elliptic Curve Parameters

- ECCG-ECDLOG-001:
    - Severity: info
    - EC-DLOG primitive was detected with agreed elliptic curve [curve] and is classified as recommended.

- ECCG-ECDLOG-002:
    - Severity: info
    - EC-DLOG primitive was detected with agreed NIST elliptic curve [curve] and is classified as recommended. ECCG note 39-SpecialP applies.

- ECCG-ECDLOG-003:
    - Severity: warning
    - EC-DLOG primitive was detected with elliptic curve [curve], which is not listed as an agreed ECCG curve. This does not necessarily mean the code is unsafe, but it should be reviewed for ECCG compliance.

- ECCG-ECDLOG-004:
    - Severity: warning
    - EC-DLOG primitive was detected, but the elliptic curve could not be determined from the CBOM. ECCG curve compliance could not be verified.