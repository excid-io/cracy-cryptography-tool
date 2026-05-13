"""
Test corpus: Python ssl/TLS code paths that are non-compliant with ECCG TLS rules.

ECCG rule used for this corpus:
- TLSv1.3 -> Recommended
- TLSv1.2 -> Legacy

Use this to validate Semgrep rules that flag legacy TLS usage,
especially explicit TLS 1.2 configuration and legacy protocol constants.
"""


# -------------------------
# Explicit TLS 1.2 only
# -------------------------
def tls12_only_client_examples():
    import ssl

    # Direct TLS 1.2 only configuration
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2

    # Same idea with create_default_context
    ctx2 = ssl.create_default_context()
    ctx2.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx2.maximum_version = ssl.TLSVersion.TLSv1_2

    # Using variable indirection
    legacy_version = ssl.TLSVersion.TLSv1_2
    ctx3 = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx3.minimum_version = legacy_version
    ctx3.maximum_version = legacy_version

    return ctx, ctx2, ctx3


def tls12_only_server_examples():
    import ssl

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2

    ctx2 = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ctx2.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx2.maximum_version = ssl.TLSVersion.TLSv1_2

    return ctx, ctx2


# -------------------------
# Allows legacy TLS 1.2 in a range
# -------------------------
def tls13_but_allows_tls12_examples():
    import ssl

    # Looks modern, but still allows TLS 1.2
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3

    # Same pattern in a slightly different form
    ctx2 = ssl.create_default_context()
    ctx2.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx2.maximum_version = ssl.TLSVersion.TLSv1_3

    # Via variables
    min_ver = ssl.TLSVersion.TLSv1_2
    max_ver = ssl.TLSVersion.TLSv1_3
    ctx3 = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx3.minimum_version = min_ver
    ctx3.maximum_version = max_ver

    return ctx, ctx2, ctx3


# -------------------------
# Legacy protocol constants
# -------------------------
def legacy_protocol_constant_examples():
    import ssl

    # Explicit legacy protocol constants
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)

    # Older deprecated constants that are even worse
    ctx2 = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
    ctx3 = ssl.SSLContext(ssl.PROTOCOL_TLSv1_1)

    # Via alias / variable
    proto = ssl.PROTOCOL_TLSv1_2
    ctx4 = ssl.SSLContext(proto)

    return ctx, ctx2, ctx3, ctx4


# -------------------------
# Generic contexts not pinned to TLS 1.3
# -------------------------
def unpinned_context_examples():
    import ssl

    # No explicit version enforcement at all
    ctx = ssl.create_default_context()

    # Another common style
    ctx2 = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

    # Server context also not pinned
    ctx3 = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

    return ctx, ctx2, ctx3


# -------------------------
# Wrapped sockets with legacy configuration
# -------------------------
def wrapped_socket_legacy_examples():
    import socket
    import ssl

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # TLS 1.2 only client socket
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    wrapped = ctx.wrap_socket(sock, server_hostname="example.com")

    # Legacy protocol constant directly in context
    sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ctx2 = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    wrapped2 = ctx2.wrap_socket(sock2, server_hostname="example.com")

    return wrapped, wrapped2


# -------------------------
# create_default_context + later downgrade
# -------------------------
def default_context_then_downgrade_examples():
    import ssl

    ctx = ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2

    ctx2 = ssl.create_default_context()
    ctx2.maximum_version = ssl.TLSVersion.TLSv1_2

    ctx3 = ssl.create_default_context()
    legacy = ssl.TLSVersion.TLSv1_2
    ctx3.minimum_version = legacy
    ctx3.maximum_version = ssl.TLSVersion.TLSv1_3

    return ctx, ctx2, ctx3


# -------------------------
# Tricky imports / aliases
# -------------------------
def tricky_imports_and_aliases():
    import ssl as tlslib
    from ssl import SSLContext, TLSVersion, PROTOCOL_TLS_CLIENT, PROTOCOL_TLSv1_2

    # Alias module usage
    ctx = tlslib.SSLContext(tlslib.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = tlslib.TLSVersion.TLSv1_2
    ctx.maximum_version = tlslib.TLSVersion.TLSv1_3

    # Direct symbol import usage
    ctx2 = SSLContext(PROTOCOL_TLS_CLIENT)
    ctx2.minimum_version = TLSVersion.TLSv1_2
    ctx2.maximum_version = TLSVersion.TLSv1_2

    # Direct use of legacy protocol constant
    ctx3 = SSLContext(PROTOCOL_TLSv1_2)

    return ctx, ctx2, ctx3


# -------------------------
# Helper function patterns
# -------------------------
def make_legacy_client_context():
    import ssl

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    return ctx


def make_legacy_server_context():
    import ssl

    version = ssl.TLSVersion.TLSv1_2
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = version
    ctx.maximum_version = version
    return ctx


def helper_function_usage_examples():
    c1 = make_legacy_client_context()
    c2 = make_legacy_server_context()
    return c1, c2


# -------------------------
# Conditional legacy configuration
# -------------------------
def conditional_legacy_examples(force_legacy=True):
    import ssl

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

    if force_legacy:
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    else:
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.maximum_version = ssl.TLSVersion.TLSv1_3

    return ctx


# -------------------------
# Dictionary / config-driven legacy assignment
# -------------------------
def config_driven_legacy_examples():
    import ssl

    config = {
        "min_version": ssl.TLSVersion.TLSv1_2,
        "max_version": ssl.TLSVersion.TLSv1_2,
    }

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = config["min_version"]
    ctx.maximum_version = config["max_version"]

    return ctx


if __name__ == "__main__":
    print("Defined ECCG non-compliant Python ssl/TLS test corpus.")