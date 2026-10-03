import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _ok(self, body, ctype="text/plain"):
        data = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path == "/big":
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

HTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
