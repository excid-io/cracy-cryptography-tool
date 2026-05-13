"""
Test corpus: Python code paths that invoke 3DES (TripleDES / DES3).

Use this to validate Semgrep rules that flag 3DES usage as legacy.
"""

# -------------------------
# 1) PyCryptodome / PyCrypto
# -------------------------
def pycryptodome_des3_examples():
    # Common import styles
    from Crypto.Cipher import DES3
    from Crypto.Cipher.DES3 import new as des3_new

    key = b"Sixteen byte key"  # NOTE: real 3DES keys have specific parity/length rules
    iv = b"12345678"
    data = b"hello!!!"  # 3DES is a 64-bit block cipher; plaintext must be padded for CBC

    # Direct constructor call
    cipher = DES3.new(key, DES3.MODE_CBC, iv=iv)
    ct = cipher.encrypt(data)

    # Qualified name usage
    import Crypto.Cipher.DES3 as DES3_mod
    cipher2 = DES3_mod.new(key, DES3_mod.MODE_CBC, iv)
    ct2 = cipher2.encrypt(data)

    # Imported alias / different symbol name
    cipher3 = des3_new(key, DES3.MODE_CBC, iv=iv)
    ct3 = cipher3.encrypt(data)

    return ct, ct2, ct3


# -------------------------
# 2) pyca/cryptography
# -------------------------
def cryptography_triple_des_examples():
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    key = b"Sixteen byte key"  # demo-only
    iv = b"12345678"
    data = b"hello!!!"

    # Fully-qualified algorithm type
    algo = algorithms.TripleDES(key)
    c = Cipher(algo, modes.CBC(iv))
    encryptor = c.encryptor()
    ct = encryptor.update(data) + encryptor.finalize()

    # Alternate import style (direct TripleDES symbol)
    from cryptography.hazmat.primitives.ciphers.algorithms import TripleDES

    c2 = Cipher(TripleDES(key), modes.CBC(iv))
    encryptor2 = c2.encryptor()
    ct2 = encryptor2.update(data) + encryptor2.finalize()

    return ct, ct2


# -------------------------
# 3) stdlib ssl / OpenSSL cipher-suite strings
# -------------------------
def ssl_cipher_suite_3des_examples():
    import ssl

    ctx = ssl.create_default_context()

    # Explicitly enabling 3DES via cipher string
    ctx.set_ciphers("ECDHE-RSA-DES-CBC3-SHA:EDH-RSA-DES-CBC3-SHA:DES-CBC3-SHA")

    # Another common shorthand that includes 3DES
    ctx2 = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx2.set_ciphers("HIGH:!aNULL:!eNULL:3DES")

    # Using a variable (common in real codebases)
    ciphers = "DEFAULT:3DES"
    ctx3 = ssl.create_default_context()
    ctx3.set_ciphers(ciphers)

    return ctx, ctx2, ctx3


# -------------------------
# 4) Edge cases / patterns to ensure coverage
# -------------------------
def tricky_imports_and_calls():
    # Alias module import
    import cryptography.hazmat.primitives.ciphers.algorithms as algs
    td = algs.TripleDES(b"Sixteen byte key")  # should still be flagged

    # From-import alias
    from Crypto.Cipher import DES3 as TripleDESCompat
    _ = TripleDESCompat.new(b"Sixteen byte key", TripleDESCompat.MODE_CBC, iv=b"12345678")

    return td


if __name__ == "__main__":
    # Run functions so this file can also serve as a quick runtime smoke test
    # (though it may fail if libraries aren't installed / padding not applied).
    print("Defined 3DES test corpus.")
