"""Websocket backend behind the allowed upstream: completes the handshake, sends one text frame
naming the upstream, then a close frame. Standard library only."""
import base64
import hashlib
import socketserver

GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        key = None
        while True:
            line = self.rfile.readline()
            if line in (b"\r\n", b"\n", b""):
                break
            name, _, value = line.decode("latin-1").partition(":")
            if name.strip().lower() == "sec-websocket-key":
                key = value.strip()
        if key is None:
            self.wfile.write(b"HTTP/1.1 400 Bad Request\r\ncontent-length: 0\r\n\r\n")
            return
        accept = base64.b64encode(hashlib.sha1((key + GUID).encode()).digest()).decode()
        self.wfile.write(
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
            f"Sec-WebSocket-Accept: {accept}\r\n\r\n".encode()
        )
        payload = b"ws-hello upstream=allowed"
        self.wfile.write(bytes([0x81, len(payload)]) + payload)
        self.wfile.write(bytes([0x88, 0x00]))


socketserver.ThreadingTCPServer.allow_reuse_address = True
socketserver.ThreadingTCPServer(("127.0.0.1", 9000), Handler).serve_forever()
