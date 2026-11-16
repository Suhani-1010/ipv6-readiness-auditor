"""Controlled benchmark site with deliberately seeded IPv6 breakages.

Everything runs on your own machine:
  * a tiny authoritative DNS server for the fake zone  bench.test  (127.0.0.1:5354)
  * one HTTPS server per test host, each on its own port, with TWO listeners:
        IPv4 listener on 127.0.0.1  -> always behaves normally
        IPv6 listener on ::1        -> behaves badly in the way that case requires
The browser discovers the page over IPv4; the auditor then probes each host
over IPv6 and must find the exact seeded failure.

Run:  python3 -m ipv6audit.bench serve
"""
from __future__ import annotations

import json
import os
import socket
import socketserver
import ssl
import struct
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import dnswire

ZONE = "bench.test"
DNS_PORT = 5354
BENCH_DIR = os.path.join(os.getcwd(), "bench")
SHIM_V6_ADDR = "127.0.6.1"         # stand-in for ::1 when the machine has no IPv6 stack
NAT64_ADDR = "64:ff9b::7f00:1"     # 64:ff9b::/96 + 127.0.0.1  -> looks DNS64-synthesized

# --------------------------------------------------------------------------- #
# The test cases.  v6 = how the IPv6 listener behaves.
#   aaaa: "::1" | "nat64" | None (no AAAA record) | "cname:<target>"
#   v6:   "ok" | "none" (nothing listening) | "badcert" | "403" | "redirect" | "500"
# expect = what a correct auditor must report (verdict, stage, code)
# --------------------------------------------------------------------------- #
CASES = {
    "www":         dict(port=8440, aaaa="::1",   v6="ok",       expect=("READY", None, None),
                        why="root page, healthy"),
    "static":      dict(port=8441, aaaa="::1",   v6="ok",       expect=("READY", None, None),
                        why="first-party CSS/JS, healthy"),
    "fonts":       dict(port=8442, aaaa="::1",   v6="ok",       expect=("READY", None, None),
                        why="font loaded from CSS (nested), healthy"),
    "v4only":      dict(port=8443, aaaa=None,    v6="none",     expect=("IPV4_ONLY", "dns", "DNS_NO_AAAA"),
                        why="DNS: no AAAA record"),
    "cdn":         dict(port=8444, aaaa="cname:origin-v4.bench.test", v6="none",
                        expect=("IPV4_ONLY", "dns", "DNS_NO_AAAA"),
                        why="DNS: CNAME to an IPv4-only origin"),
    "tcpdrop":     dict(port=8445, aaaa="::1",   v6="none",     expect=("IPV6_TCP_FAIL", "tcp", "TCP_REFUSED"),
                        why="TCP: AAAA exists but nothing listens on IPv6"),
    "tlsbad":      dict(port=8446, aaaa="::1",   v6="badcert",  expect=("IPV6_TLS_FAIL", "tls", "TLS_CERT_NAME_MISMATCH"),
                        why="TLS: IPv6 server presents a certificate for the wrong name"),
    "forbid6":     dict(port=8447, aaaa="::1",   v6="403",      expect=("IPV6_HTTP_FAIL", "http", "HTTP_403"),
                        why="HTTP: 403 Forbidden only over IPv6 (fetched by a script)"),
    "redir6":      dict(port=8448, aaaa="::1",   v6="redirect", expect=("IPV6_HTTP_FAIL", "http", "HTTP_REDIRECT_TO_IPV4_ONLY"),
                        why="HTTP: IPv6 clients redirected to an IPv4-only host"),
    "api-v4":      dict(port=8449, aaaa=None,    v6="none",     expect=("IPV4_ONLY", "dns", "DNS_NO_AAAA"),
                        why="DNS: API called by JavaScript has no AAAA (nested dependency)"),
    "broken-both": dict(port=8450, aaaa="::1",   v6="500",      expect=("BROKEN_BOTH", "http", "HTTP_500"),
                        why="control: 500 on IPv4 AND IPv6, must NOT be blamed on IPv6"),
    "synth":       dict(port=8451, aaaa="nat64", v6="none",     expect=("IPV4_ONLY_NAT64", "dns", "DNS_ONLY_SYNTHESIZED_AAAA"),
                        why="DNS: only a NAT64-synthesized AAAA (64:ff9b::/96)"),
}
EXTRA_A_ONLY = {"origin-v4"}       # CNAME target, A record only


def u(host: str, path: str) -> str:
    return f"https://{host}.{ZONE}:{CASES[host]['port']}{path}"


INDEX_HTML = f"""<!doctype html><html><head><meta charset="utf-8"><title>IPv6 benchmark</title>
<link rel="stylesheet" href="{u('static', '/style.css')}">
<link rel="stylesheet" href="{u('tcpdrop', '/broken.css')}">
<script src="{u('static', '/app.js')}"></script>
<script src="{u('cdn', '/lib.js')}"></script>
<script src="{u('tlsbad', '/widget.js')}"></script>
</head><body><h1>IPv6 benchmark page</h1>
<img src="{u('v4only', '/logo.png')}">
<img src="{u('redir6', '/banner.png')}">
<img src="{u('synth', '/pixel.png')}">
<img src="{u('broken-both', '/missing.png')}">
</body></html>"""

FILES = {
    "/style.css": ("text/css", f"@font-face{{font-family:bf;src:url({u('fonts', '/bench.woff2')})}}"
                               "body{font-family:bf,sans-serif}"),
    "/app.js": ("application/javascript",
                f"fetch('{u('forbid6', '/api/data.json')}').catch(()=>{{}});"
                f"fetch('{u('api-v4', '/api/v.json')}').catch(()=>{{}});"),
}
CTYPES = {".css": "text/css", ".js": "application/javascript", ".json": "application/json",
          ".png": "image/png", ".woff2": "font/woff2"}


# --------------------------------------------------------------------------- #
# Certificates (made with the openssl command-line tool)
# --------------------------------------------------------------------------- #
def make_certs(d: str) -> None:
    os.makedirs(d, exist_ok=True)
    if os.path.exists(os.path.join(d, "wrong.crt")):
        return

    def run(*args):
        subprocess.run(["openssl", *args], check=True, capture_output=True)

    run("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "825", "-subj", "/CN=IPv6 Bench Test CA",
        "-keyout", f"{d}/ca.key", "-out", f"{d}/ca.crt",
        "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign")
    for name, san in (("bench", f"DNS:*.{ZONE},DNS:{ZONE}"), ("wrong", "DNS:wrong.example")):
        with open(f"{d}/{name}.ext", "w") as fh:
            fh.write(f"subjectAltName={san}\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\n"
                     "extendedKeyUsage=serverAuth\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n")
        cn = f"*.{ZONE}" if name == "bench" else "wrong.example"
        run("req", "-newkey", "rsa:2048", "-nodes", "-subj", f"/CN={cn}",
            "-keyout", f"{d}/{name}.key", "-out", f"{d}/{name}.csr")
        run("x509", "-req", "-in", f"{d}/{name}.csr", "-CA", f"{d}/ca.crt", "-CAkey", f"{d}/ca.key",
            "-CAcreateserial", "-days", "825", "-extfile", f"{d}/{name}.ext", "-out", f"{d}/{name}.crt")


# --------------------------------------------------------------------------- #
# Authoritative DNS server for bench.test
# --------------------------------------------------------------------------- #
def _rr(name: str, rtype: int, rdata: bytes, ttl: int = 60) -> bytes:
    return dnswire.encode_name(name) + struct.pack("!HHIH", rtype, 1, ttl, len(rdata)) + rdata


def dns_answer(query: bytes, v6_addr_for_zone: str) -> bytes:
    qid, flags = struct.unpack("!HH", query[:4])
    qname, off = dnswire.decode_name(query, 12)
    qtype = struct.unpack("!H", query[off:off + 2])[0]
    question = query[12:off + 4]
    rcode, answers = 0, []
    label = qname[:-len(ZONE) - 1] if qname.endswith("." + ZONE) else None
    if label in CASES or label in EXTRA_A_ONLY:
        case = CASES.get(label, {"aaaa": None})
        aaaa = case["aaaa"]
        if aaaa and aaaa.startswith("cname:"):
            target = aaaa.split(":", 1)[1]
            answers.append(_rr(qname, dnswire.TYPE_CNAME, dnswire.encode_name(target)))
            if qtype == dnswire.TYPE_A:
                answers.append(_rr(target, dnswire.TYPE_A, socket.inet_aton("127.0.0.1")))
        elif qtype == dnswire.TYPE_A:
            answers.append(_rr(qname, dnswire.TYPE_A, socket.inet_aton("127.0.0.1")))
        elif qtype == dnswire.TYPE_AAAA and aaaa:
            addr = NAT64_ADDR if aaaa == "nat64" else v6_addr_for_zone
            answers.append(_rr(qname, dnswire.TYPE_AAAA, socket.inet_pton(socket.AF_INET6, addr)))
        # any other case: NOERROR with no answers  (= NODATA, the "no AAAA" signal)
    else:
        rcode = 5          # REFUSED: we only serve bench.test
    hdr = struct.pack("!HHHHHH", qid, 0x8400 | (flags & 0x0100) | rcode, 1, len(answers), 0, 0)
    return hdr + question + b"".join(answers)


class _DNSHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        try:
            sock.sendto(dns_answer(data, "::1"), self.client_address)
        except Exception as exc:  # noqa: BLE001
            print("dns error:", exc)


# --------------------------------------------------------------------------- #
# HTTPS servers
# --------------------------------------------------------------------------- #
class _Handler(BaseHTTPRequestHandler):
    server_version = "IPv6Bench/1.0"
    # HTTP/1.1 keep-alive: closing a TLS connection immediately after the reply
    # can make the kernel send a TCP RST that the browser sees as ERR_CONNECTION_RESET.
    protocol_version = "HTTP/1.1"
    timeout = 10

    def log_message(self, fmt, *args):
        fam = "IPv6" if self.server.is_v6 else "IPv4"
        sys.stderr.write(f"  [{fam} {self.server.host_label:<11}] {self.command} {self.path} -> "
                         f"{getattr(self, '_status', '?')}\n")

    def _send(self, status, ctype="text/plain", body=b"", extra=None):
        self._status = status
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_GET(self):
        behaviour = self.server.behaviour
        path = self.path.split("?")[0]
        if behaviour == "500":
            return self._send(500, body=b"internal error (on purpose)")
        if behaviour == "403":
            return self._send(403, body=b"forbidden over IPv6 (on purpose)")
        if behaviour == "redirect":
            return self._send(302, extra={"Location": u("v4only", "/moved.png")})
        if path == "/" and self.server.host_label == "www":
            return self._send(200, "text/html", INDEX_HTML.encode())
        if path in FILES:
            ctype, body = FILES[path]
            return self._send(200, ctype, body.encode())
        ext = os.path.splitext(path)[1]
        return self._send(200, CTYPES.get(ext, "application/octet-stream"), b"x" * 16)

    do_HEAD = do_GET


class _TLSServer(ThreadingHTTPServer):
    """TLS handshake happens in each connection's own thread, so one bad
    handshake (e.g. a browser rejecting our test certificate) can't stall the server."""
    daemon_threads = True
    ssl_ctx: ssl.SSLContext

    def finish_request(self, request, client_address):
        try:
            request = self.ssl_ctx.wrap_socket(request, server_side=True)
        except (ssl.SSLError, OSError) as exc:
            fam = "IPv6" if self.is_v6 else "IPv4"
            sys.stderr.write(f"  [{fam} {self.host_label:<11}] TLS handshake failed: {exc}\n")
            return
        super().finish_request(request, client_address)


class _V6Server(_TLSServer):
    address_family = socket.AF_INET6


class _V4Server(_TLSServer):
    pass


def _start_https(label, bind_addr, port, behaviour, certfile, keyfile, is_v6, native_v6):
    cls = _V6Server if (is_v6 and native_v6) else _V4Server
    srv = cls((bind_addr, port), _Handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile, keyfile)
    srv.ssl_ctx = ctx
    srv.behaviour, srv.host_label, srv.is_v6 = behaviour, label, is_v6
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def native_ipv6_loopback() -> bool:
    try:
        s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        s.bind(("::1", 0))
        s.close()
        return True
    except OSError:
        return False


def serve() -> None:
    certs = os.path.join(BENCH_DIR, "certs")
    make_certs(certs)
    native = native_ipv6_loopback()
    v6_bind = "::1" if native else SHIM_V6_ADDR
    print(f"IPv6 listeners on {v6_bind}" + ("" if native else
          "   (no IPv6 stack here: using a LAB SHIM address that stands in for ::1)"))

    dns = socketserver.ThreadingUDPServer(("127.0.0.1", DNS_PORT), _DNSHandler)
    threading.Thread(target=dns.serve_forever, daemon=True).start()
    print(f"DNS server for *.{ZONE} on 127.0.0.1:{DNS_PORT}")

    good = (f"{certs}/bench.crt", f"{certs}/bench.key")
    wrong = (f"{certs}/wrong.crt", f"{certs}/wrong.key")
    for label, c in CASES.items():
        v4_behaviour = "500" if c["v6"] == "500" else "ok"
        _start_https(label, "127.0.0.1", c["port"], v4_behaviour, *good, is_v6=False, native_v6=native)
        if c["v6"] != "none":
            cert = wrong if c["v6"] == "badcert" else good
            _start_https(label, v6_bind, c["port"], c["v6"], *cert, is_v6=True, native_v6=native)
        print(f"  {label + '.' + ZONE:<24} :{c['port']}  IPv6 behaviour = {c['v6']:<9} ({c['why']})")

    state = {"zone": ZONE, "dns": f"127.0.0.1:{DNS_PORT}", "ca_file": f"{certs}/ca.crt",
             "root_url": u("www", "/"), "native_ipv6": native,
             "v6_shim": {} if native else {"::1": SHIM_V6_ADDR, NAT64_ADDR: "127.0.0.1"},
             "expected": {f"https://{h}.{ZONE}:{c['port']}": {"verdict": c["expect"][0], "stage": c["expect"][1],
                                                               "code": c["expect"][2], "why": c["why"]}
                          for h, c in CASES.items()}}
    with open(os.path.join(BENCH_DIR, "state.json"), "w", encoding="utf-8") as fh:
        json.dump(state, fh, indent=2)
    print(f"\nBenchmark page: {state['root_url']}")
    print("Ground truth written to bench/state.json.  Leave this running; press Ctrl+C to stop.\n")
    print("Request log:")
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        print("\nstopped")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "serve":
        serve()
    else:
        print(__doc__)
