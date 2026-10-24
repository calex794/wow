#!/usr/bin/env python3
"""CI-only TCP proxy: forward S3 PUT, then destroy response socket after MinIO 200.

This tests a genuine network-level lost ACK *after* server-side commit.
Never deploy this helper in production; loopback addresses are intentional.
"""
import os
import socket
import socketserver
import threading

# No arbitrary upstream addresses are accepted. The second mode is used
# solely by the isolated CI Docker network, never an externally exposed port.
if os.environ.get("WOW_PROXY_DOCKER_LAB") == "1":
    UPSTREAM = ("wow-cloud02-minio", 9000)
    LISTEN = ("0.0.0.0", 9001)
else:
    UPSTREAM = ("127.0.0.1", 9000)
    LISTEN = ("127.0.0.1", 9001)
CHUNK = 65536
HEADER_LIMIT = 65536


def send_request(client, upstream):
    try:
        while True:
            buf = client.recv(CHUNK)
            if not buf:
                break
            upstream.sendall(buf)
    except (OSError, TimeoutError):
        pass


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        client = self.request
        client.settimeout(15)
        with socket.create_connection(UPSTREAM, timeout=15) as upstream:
            upstream.settimeout(15)
            try:
                first = client.recv(CHUNK)
                if not first:
                    return
                is_put = first.startswith(b"PUT ")
                upstream.sendall(first)
                threading.Thread(
                    target=send_request, args=(client, upstream), daemon=True
                ).start()
                if not is_put:
                    self.forward_response(client, upstream)
                    return

                # Forward interim 100 Continue, but not a final successful PUT.
                received = bytearray()
                while True:
                    piece = upstream.recv(CHUNK)
                    if not piece:
                        return
                    received.extend(piece)
                    if len(received) > HEADER_LIMIT:
                        raise ValueError("oversized upstream response headers")
                    sep = received.find(b"\r\n\r\n")
                    if sep < 0:
                        continue
                    sep += 4
                    header = bytes(received[:sep])
                    rest = received[sep:]
                    try:
                        status = int(header.split(b"\r\n", 1)[0].split()[1])
                    except (IndexError, ValueError):
                        raise ValueError("invalid upstream HTTP status") from None
                    if status == 100:
                        client.sendall(header)
                        received = bytearray(rest)
                        continue
                    if 200 <= status < 300:
                        # The object is committed; deny ONLY the final response.
                        # No application data, signatures, or credentials logged.
                        try:
                            client.shutdown(socket.SHUT_RDWR)
                        except OSError:
                            pass
                        return
                    # Failed PUT: do not claim a committed object.
                    client.sendall(received)
                    self.forward_response(client, upstream)
                    return
            except (OSError, TimeoutError):
                return

    @staticmethod
    def forward_response(client, upstream):
        try:
            while True:
                buf = upstream.recv(CHUNK)
                if not buf:
                    break
                client.sendall(buf)
        except (OSError, TimeoutError):
            pass


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


if __name__ == "__main__":
    with Server(LISTEN, Handler) as server:
        server.serve_forever(poll_interval=0.1)
