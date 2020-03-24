import shutil
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class ProxyRequestHandler(BaseHTTPRequestHandler):
    def __getattr__(self, key):
        if key.startswith("do_"):
            return self.handle_arbitrary_request

        raise AttributeError

    def handle_arbitrary_request(self):
        host = self.headers["Host"]
        if host == None:
            self.send_error(400, "The 'Host' header is missing")
            return

        self.log_message(f"{self.command} http://{host}{self.path}")

        content_length = self.headers["Content-Length"]
        if content_length == None:
            content_length = "0"

        try:
            content_length = int(content_length)
            if content_length < 0:
                raise ValueError
        except ValueError:
            self.send_error(400, "'Content-Length' is not a nonnegative integer")
            return

        body = self.rfile.read(content_length)

        conn = HTTPConnection(host)
        conn.request(
            self.command, self.path, headers=self.headers, body=body,
        )
        r = conn.getresponse()

        self.wfile.write(
            bytes(f"HTTP/{r.version / 10} {r.status} {r.reason}\r\n", "ascii")
        )

        self.wfile.write(bytes(r.msg))
        shutil.copyfileobj(r, self.wfile)

        self.log_request(code=r.status, size=r.msg["Content-Length"])


httpd = ThreadingHTTPServer(("", 10080), ProxyRequestHandler)
httpd.serve_forever()
