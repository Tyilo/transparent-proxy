import http.server
import socket
import struct
from selectors import EVENT_READ, DefaultSelector
from socketserver import StreamRequestHandler, ThreadingTCPServer

from scapy.layers.tls.extensions import TLS_Ext_ServerName
from scapy.layers.tls.record import TLS


class ReadError(Exception):
    pass


def read(f, size):
    read_f = getattr(f, "read", None) or getattr(f, "recv")

    res = b""
    while len(res) < size:
        s = read_f(size - len(res))
        if not s:
            raise ReadError(f"Got {len(res)} instead of {size} bytes")

        res += s

    return res


def read_tls_record(f):
    record_header = read(f, 5)
    body_size = struct.unpack("!H", record_header[3:])[0]
    record_body = read(f, body_size)

    return record_header + record_body


class ProxyTLSHandler(StreamRequestHandler):
    # Hack to make log_message from BaseHTTPRequestHandler available
    def __getattr__(self, key):
        v = getattr(http.server.BaseHTTPRequestHandler, key)
        if hasattr(v, "__call__"):
            v = v.__get__(self, self.__class__)

        return v

    def handle(self):
        record_bytes = read_tls_record(self.rfile)
        record = TLS(record_bytes)

        ext_server_name = record.getlayer(TLS_Ext_ServerName)
        if ext_server_name == None:
            self.log_message("ServerName is missing from TLS record")
            return

        server_names = [str(s.servername, "ascii") for s in ext_server_name.servernames]
        self.log_message(f"Server names: {server_names}")

        if len(server_names) == 0:
            self.log_message("List of server names is empty")
            return

        host = server_names[0]

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((host, 443))

        s.send(record_bytes)

        def read_client():
            s.send(read_tls_record(self.rfile))

        def read_remote():
            self.wfile.write(read_tls_record(s))

        sel = DefaultSelector()
        sel.register(self.rfile, EVENT_READ, read_client)
        sel.register(s, EVENT_READ, read_remote)

        got_read_error = False
        while not got_read_error:
            events = sel.select()
            for key, mask in events:
                try:
                    key.data()
                except ReadError:
                    got_read_error = True
                    break

        s.close()


tcpd = ThreadingTCPServer(("", 443), ProxyTLSHandler)
tcpd.serve_forever()
