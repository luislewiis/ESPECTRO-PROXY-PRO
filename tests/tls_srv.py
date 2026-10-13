import os
import ssl
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

# tls_cert.pem / tls_key.pem: par autofirmado DESECHABLE generado solo
# para los tests locales (S3/S14). No usar jamas fuera de tests ni en
# produccion; regenerar con:
#   openssl req -x509 -newkey rsa:2048 -nodes -keyout tls_key.pem -out tls_cert.pem -days 365 -subj "/CN=localhost"

HERE = os.path.dirname(os.path.abspath(__file__))


class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _ok(self, body):
        data = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        self._ok("TLS-OK")

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        self.rfile.read(n)
        self._ok("TLS-POST-OK")

    def log_message(self, *a):
        pass


httpd = HTTPServer(("127.0.0.1", int(sys.argv[1])), H)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(os.path.join(HERE, "tls_cert.pem"),
                    os.path.join(HERE, "tls_key.pem"))
httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
print(f"tls server on {sys.argv[1]}", flush=True)
httpd.serve_forever()
