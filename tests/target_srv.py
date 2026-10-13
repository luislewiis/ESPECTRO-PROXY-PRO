import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit


class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _ruta(self):
        # Acepta forma absoluta (GET http://host:port/ruta): es lo que manda
        # un proxy bien configurado en la linea de peticion (RFC 7230 5.3.2)
        # y los servidores reales la aceptan. http.server no lo hace solo.
        return urlsplit(self.path).path or "/"

    def _ok(self, body, ctype="text/plain"):
        data = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self._ruta() == "/big":
            self._ok("X" * 50000)
        else:
            self._ok("PROXY-GATEWAY-OK")

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(n).decode("utf-8", "replace")
        echo = self.headers.get("X-Test", "no-header")
        self._ok(f"POST-ECHO:{body}:H={echo}")

    def log_message(self, *a):
        pass

ThreadingHTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
