"""
Test corpus: Python code paths that invoke AES.

Use this to validate Semgrep rules that detect AES usage,
including key sizes, modes, import styles, and TLS cipher strings.
"""

# -------------------------
# PyCryptodome / PyCrypto
# -------------------------
def pycryptodome_aes_examples():
    # Common import styles
    from Crypto.Cipher import AES
    from Crypto.Cipher.AES import new as aes_new

    key128 = b"0123456789abcdef"                  # 16 bytes = AES-128
    key192 = b"0123456789abcdef01234567"          # 24 bytes = AES-192
    key256 = b"0123456789abcdef0123456789abcdef"  # 32 bytes = AES-256

    iv = b"1234567890abcdef"
    nonce = b"unique_nonce1234"
    data = b"hello world!!!!!"  # 16 bytes for block mode demo

    test = AES.MODE_CBC
    # AES-CBC
    # cipher = AES.new(key128, AES.MODE_CBC, iv=iv)
    cipher = AES.new(key128, test, iv=iv)
    ct = cipher.encrypt(data)

    # AES-ECB
    cipher2 = AES.new(key192, AES.MODE_ECB)
    ct2 = cipher2.encrypt(data)

    # AES-GCM
    cipher3 = AES.new(key256, AES.MODE_GCM, nonce=nonce)
    ct3, tag3 = cipher3.encrypt_and_digest(b"authenticated encryption")

    # Qualified name usage
    import Crypto.Cipher.AES as AES_mod
    cipher4 = AES_mod.new(key128, AES_mod.MODE_CBC, iv=iv)
    ct4 = cipher4.encrypt(data)

    # Imported alias / different symbol name
    cipher5 = aes_new(key256, AES.MODE_CBC, iv=iv)
    ct5 = cipher5.encrypt(data)

    return ct, ct2, ct3, tag3, ct4, ct5


# -------------------------
# pyca/cryptography
# -------------------------
def cryptography_aes_examples():
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    key64 = b"01234567"
    key128 = b"0123456789abcdef"
    key192 = b"0123456789abcdef01234567"
    key256 = b"0123456789abcdef0123456789abcdef"

    iv = b"1234567890abcdef"
    nonce = b"123456789012"
    data = b"hello world!!!!!"

    # AES-CBC (invalid 64-bit key — should fail at runtime, but useful for static detection testing)
    algo_small = algorithms.AES(key64)
    c_small = Cipher(algo_small, modes.CBC(iv))
    encryptor_small = c_small.encryptor()
    ct_small = encryptor_small.update(data) + encryptor_small.finalize()

    # AES-CBC (128-bit)
    algo_128 = algorithms.AES(key128)
    c_128 = Cipher(algo_128, modes.CBC(iv))
    encryptor_128 = c_128.encryptor()
    ct_128 = encryptor_128.update(data) + encryptor_128.finalize()

    # AES-CBC (192-bit)
    algo_192 = algorithms.AES(key192)
    c_192 = Cipher(algo_192, modes.CBC(iv))
    encryptor_192 = c_192.encryptor()
    ct_192 = encryptor_192.update(data) + encryptor_192.finalize()

    # AES-CBC (256-bit)
    algo_256 = algorithms.AES(key256)
    c_256 = Cipher(algo_256, modes.CBC(iv))
    encryptor_256 = c_256.encryptor()
    ct_256 = encryptor_256.update(data) + encryptor_256.finalize()


    # AES-CBC
    algo = algorithms.AES(key128)
    c = Cipher(algo, modes.CBC(iv))
    encryptor = c.encryptor()
    ct = encryptor.update(data) + encryptor.finalize()

    # AES-ECB
    c2 = Cipher(algorithms.AES(key192), modes.ECB())
    encryptor2 = c2.encryptor()
    ct2 = encryptor2.update(data) + encryptor2.finalize()

    # AES-GCM
    c3 = Cipher(algorithms.AES(key256), modes.GCM(nonce))
    encryptor3 = c3.encryptor()
    ct3 = encryptor3.update(b"authenticated encryption") + encryptor3.finalize()

    # Alternate import style
    from cryptography.hazmat.primitives.ciphers.algorithms import AES

    c4 = Cipher(AES(key256), modes.CBC(iv))
    encryptor4 = c4.encryptor()
    ct4 = encryptor4.update(data) + encryptor4.finalize()

    return ct, ct2, ct3, ct4


# -------------------------
# stdlib ssl / OpenSSL cipher-suite strings
# -------------------------
def ssl_cipher_suite_aes_examples():
    import ssl

    ctx = ssl.create_default_context()

    # Explicit AES cipher suites
    ctx.set_ciphers(
        "ECDHE-RSA-AES128-GCM-SHA256:"
        "ECDHE-RSA-AES256-GCM-SHA384:"
        "AES128-SHA:AES256-SHA"
    )

    # Another common shorthand using AES
    ctx2 = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx2.set_ciphers("HIGH:!aNULL:!eNULL:AES")

    # Variable-based usage
    ciphers = "DEFAULT:AES256-SHA"
    ctx3 = ssl.create_default_context()
    ctx3.set_ciphers(ciphers)

    return ctx, ctx2, ctx3


# -------------------------
# Edge cases / patterns to ensure coverage
# -------------------------
def tricky_imports_and_calls():
    # Alias module import
    import cryptography.hazmat.primitives.ciphers.algorithms as algs
    aes_obj = algs.AES(b"0123456789abcdef")  # should be detectable

    # From-import alias
    from Crypto.Cipher import AES as AESCompat
    cipher = AESCompat.new(
        b"0123456789abcdef",
        AESCompat.MODE_CBC,
        iv=b"1234567890abcdef"
    )

    # Dynamic selection
    from Crypto.Cipher import AES
    mode = AES.MODE_CBC
    key = b"0123456789abcdef"
    iv = b"1234567890abcdef"
    _ = AES.new(key, mode, iv=iv)

    return aes_obj, cipher


if __name__ == "__main__":
    # Runtime smoke test only; some modes require exact input sizes.
    print("Defined AES test corpus.")