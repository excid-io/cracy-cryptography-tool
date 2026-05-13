import socket
import ssl


def tls_server(certfile: str, keyfile: str, host: str = "127.0.0.1", port: int = 8443) -> None:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=certfile, keyfile=keyfile)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
        sock.bind((host, port))
        sock.listen(5)
        print(f"Listening on {host}:{port}")

        with context.wrap_socket(sock, server_side=True) as tls_sock:
            conn, addr = tls_sock.accept()
            with conn:
                print("Client connected:", addr)
                print("TLS version:", conn.version())
                print("Cipher:", conn.cipher())

                data = conn.recv(4096)
                print("Received:")
                print(data.decode("utf-8", errors="replace"))

                response = (
                    "HTTP/1.1 200 OK\r\n"
                    "Content-Type: text/plain\r\n"
                    "Content-Length: 12\r\n"
                    "Connection: close\r\n\r\n"
                    "Hello world!"
                )
                conn.sendall(response.encode("utf-8"))


if __name__ == "__main__":
    tls_server("server.crt", "server.key")