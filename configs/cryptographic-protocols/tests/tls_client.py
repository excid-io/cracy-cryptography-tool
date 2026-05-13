import socket
import ssl


def tls_client(host: str, port: int = 443) -> None:
    # Create a default TLS client context
    context = ssl.create_default_context()

    # Require certificate validation and hostname checking
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED

    # Create a normal TCP connection first
    with socket.create_connection((host, port)) as sock:
        # Upgrade the TCP socket to TLS
        with context.wrap_socket(sock, server_hostname=host) as tls_sock:
            print("TLS established")
            print("Protocol version:", tls_sock.version())
            print("Cipher:", tls_sock.cipher())
            print("Peer certificate subject:", tls_sock.getpeercert().get("subject"))

            # Send a basic HTTP request over the TLS channel
            request = (
                f"GET / HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"Connection: close\r\n\r\n"
            )
            tls_sock.sendall(request.encode("ascii"))

            response = b""
            while True:
                chunk = tls_sock.recv(4096)
                if not chunk:
                    break
                response += chunk

    print("\n--- Response ---")
    print(response.decode("utf-8", errors="replace"))


if __name__ == "__main__":
    tls_client("example.com")