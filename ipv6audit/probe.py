"""Layered connectivity probe: DNS -> TCP -> TLS -> HTTP, per address family.

For one endpoint (scheme, host, port, path) we run the full stack separately
over IPv6 and IPv4 and record the *first* layer that fails.  Comparing the two
families lets us tell an IPv6-specific breakage apart from a resource that is
simply down for everyone.

AAAA presence is only the first of four gates; an endpoint is READY only when
an IPv6 TCP connection, TLS handshake and HTTP exchange all succeed.
"""
from __future__ import annotations

import ipaddress
import socket
import ssl
import time
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit

from . import dnswire

STAGES = ("dns", "tcp", "tls", "http")

# Verdicts (per endpoint)
READY = "READY"                          # all four layers pass over native IPv6
IPV4_ONLY = "IPV4_ONLY"                  # DNS layer: no AAAA
IPV4_ONLY_NAT64 = "IPV4_ONLY_NAT64"      # only reachable via synthesized AAAA
IPV6_TCP_FAIL = "IPV6_TCP_FAIL"
IPV6_TLS_FAIL = "IPV6_TLS_FAIL"
IPV6_HTTP_FAIL = "IPV6_HTTP_FAIL"
IPV6_DNS_ERROR = "IPV6_DNS_ERROR"        # SERVFAIL/timeout on AAAA but A fine
BROKEN_BOTH = "BROKEN_BOTH"              # fails on IPv4 too -> not an IPv6 issue
INCONCLUSIVE_NO_IPV6 = "INCONCLUSIVE_NO_IPV6"  # *our* machine has no IPv6 route: can't judge the site
VERDICT_STAGE = {IPV4_ONLY: "dns", IPV6_DNS_ERROR: "dns", IPV4_ONLY_NAT64: "dns",
                 IPV6_TCP_FAIL: "tcp", IPV6_TLS_FAIL: "tls", IPV6_HTTP_FAIL: "http"}


@dataclass
class ProbeConfig:
    resolvers: list | None = None
    timeout: float = 5.0
    ca_file: str | None = None
    nat64_prefixes: list = field(default_factory=list)
    # Lab only: map an IPv6 address to an IPv4 loopback "stand-in" when the
    # machine has no IPv6 stack. Never used against real sites.
    v6_shim: dict = field(default_factory=dict)
    # Look like normal desktop Chrome: many sites' bot filters reject unknown clients,
    # which would hide the IPv6 result behind a 403 on BOTH families.
    user_agent: str = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                       "(KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36")
    max_addresses: int = 3
    retry_delay: float = 2.0      # seconds to wait before re-trying a timed-out probe


def _ssl_context(cfg: ProbeConfig) -> ssl.SSLContext:
    ctx = ssl.create_default_context(cafile=cfg.ca_file) if cfg.ca_file else ssl.create_default_context()
    if cfg.ca_file:                 # also keep system roots
        ctx.load_default_certs()
    ctx.set_alpn_protocols(["http/1.1"])
    return ctx


def _classify_tls_error(exc: Exception) -> str:
    if isinstance(exc, ssl.SSLCertVerificationError):
        code = getattr(exc, "verify_code", None)
        msg = str(exc).lower()
        if code == 62 or "hostname mismatch" in msg or "doesn't match" in msg:
            return "TLS_CERT_NAME_MISMATCH"
        if code == 10 or "expired" in msg:
            return "TLS_CERT_EXPIRED"
        if code in (18, 19, 20, 21) or "self-signed" in msg or "unable to get local issuer" in msg:
            return "TLS_CERT_UNTRUSTED"
        return "TLS_CERT_INVALID"
    if isinstance(exc, (socket.timeout, TimeoutError)):
        return "TLS_TIMEOUT"
    msg = str(exc).lower()
    if "handshake failure" in msg or "no shared cipher" in msg or "unsupported protocol" in msg \
            or "wrong version" in msg or "tlsv1 alert" in msg:
        return "TLS_HANDSHAKE_FAILURE"
    if isinstance(exc, (ConnectionResetError, ssl.SSLEOFError)) or "eof" in msg:
        return "TLS_RESET"
    return "TLS_ERROR"


def _classify_tcp_error(exc: Exception) -> str:
    if isinstance(exc, (socket.timeout, TimeoutError)):
        return "TCP_TIMEOUT"
    if isinstance(exc, ConnectionRefusedError):
        return "TCP_REFUSED"
    if isinstance(exc, ConnectionResetError):
        return "TCP_RESET"
    # Linux: ENETUNREACH 101, EHOSTUNREACH 113, EADDRNOTAVAIL 99
    # Windows: WSAENETUNREACH 10051, WSAEHOSTUNREACH 10065, WSAEADDRNOTAVAIL 10049
    codes = {getattr(exc, "errno", None), getattr(exc, "winerror", None)}
    if codes & {101, 113, 99, 10051, 10065, 10049}:
        return "TCP_UNREACHABLE"
    if codes & {97, 10047}:                                        # EAFNOSUPPORT: no IPv6 stack
        return "TCP_NO_IPV6_STACK"
    return "TCP_ERROR"


def _connect(addr: str, port: int, family: int, cfg: ProbeConfig) -> socket.socket:
    if family == 6 and addr in cfg.v6_shim:
        return socket.create_connection((cfg.v6_shim[addr], port), timeout=cfg.timeout)
    af = socket.AF_INET6 if family == 6 else socket.AF_INET
    s = socket.socket(af, socket.SOCK_STREAM)
    s.settimeout(cfg.timeout)
    try:
        s.connect((addr, port, 0, 0) if family == 6 else (addr, port))
    except Exception:
        s.close()
        raise
    return s


def _http_exchange(sock, host: str, port: int, scheme: str, path: str, cfg: ProbeConfig) -> dict:
    default = 443 if scheme == "https" else 80
    host_hdr = host if port == default else f"{host}:{port}"
    req = (f"GET {path or '/'} HTTP/1.1\r\nHost: {host_hdr}\r\nUser-Agent: {cfg.user_agent}\r\n"
           f"Accept: */*\r\nConnection: close\r\n\r\n").encode()
    sock.sendall(req)
    buf = b""
    while b"\r\n\r\n" not in buf and len(buf) < 65536:
        chunk = sock.recv(8192)
        if not chunk:
            break
        buf += chunk
    head = buf.split(b"\r\n\r\n", 1)[0].decode("iso-8859-1", "replace")
    lines = head.split("\r\n")
    parts = lines[0].split(" ", 2) if lines and lines[0] else []
    if len(parts) < 2 or not parts[0].startswith("HTTP/") or not parts[1].isdigit():
        raise ValueError(f"malformed status line: {lines[0][:80]!r}" if lines else "empty response")
    headers = {}
    for ln in lines[1:]:
        k, _, v = ln.partition(":")
        headers[k.strip().lower()] = v.strip()
    return {"status": int(parts[1]), "reason": parts[2] if len(parts) > 2 else "",
            "location": headers.get("location"), "server": headers.get("server")}


def probe_family(scheme: str, host: str, port: int, path: str, family: int, cfg: ProbeConfig) -> dict:
    """Run DNS->TCP->TLS->HTTP for one address family. Stops at the first failure."""
    r = {"family": family, "failed_stage": None, "failure_code": None,
         "dns": {}, "tcp": {}, "tls": {}, "http": {}}

    def fail(stage, code, detail=None):
        r["failed_stage"], r["failure_code"] = stage, code
        r[stage]["ok"] = False
        if detail:
            r[stage]["error"] = detail
        return r

    # ---- DNS --------------------------------------------------------------
    literal = None
    try:
        ip = ipaddress.ip_address(host.strip("[]"))
        literal = str(ip)
        if ip.version != family:
            r["dns"] = {"ok": False, "literal": literal}
            return fail("dns", "DNS_LITERAL_OTHER_FAMILY")
        addrs, dres = [literal], {"ok": True, "literal": literal, "addresses": [literal]}
    except ValueError:
        ans = dnswire.resolve(host, dnswire.TYPE_AAAA if family == 6 else dnswire.TYPE_A,
                              cfg.resolvers, timeout=min(cfg.timeout, 3.0))
        addrs = ans.addresses
        dres = {"ok": bool(addrs), "rcode": ans.rcode, "addresses": addrs,
                "cname_chain": ans.cname_chain, "ttl": ans.ttl, "ms": round(ans.elapsed_ms, 1)}
    r["dns"] = dres
    if family == 6 and addrs:
        synth = [a for a in addrs if dnswire.is_synthesized(a, cfg.nat64_prefixes)]
        dres["synthesized"] = len(synth) == len(addrs)
    if not addrs:
        code = {"NOERROR": f"DNS_NO_{'AAAA' if family == 6 else 'A'}", "NXDOMAIN": "DNS_NXDOMAIN",
                "SERVFAIL": "DNS_SERVFAIL", "TIMEOUT": "DNS_TIMEOUT",
                "REFUSED": "DNS_REFUSED"}.get(dres.get("rcode"), "DNS_ERROR")
        return fail("dns", code)

    # ---- TCP (try up to N addresses, like a real client would) ------------
    sock, attempts = None, []
    for addr in addrs[:cfg.max_addresses]:
        t0 = time.perf_counter()
        try:
            sock = _connect(addr, port, family, cfg)
            attempts.append({"addr": addr, "ok": True, "ms": round((time.perf_counter() - t0) * 1000, 1)})
            break
        except Exception as exc:  # noqa: BLE001
            attempts.append({"addr": addr, "ok": False, "code": _classify_tcp_error(exc),
                             "error": f"{type(exc).__name__}: {exc}",
                             "ms": round((time.perf_counter() - t0) * 1000, 1)})
    r["tcp"] = {"ok": sock is not None, "attempts": attempts,
                "shim": family == 6 and any(a["addr"] in cfg.v6_shim for a in attempts)}
    if sock is None:
        return fail("tcp", attempts[-1]["code"], attempts[-1]["error"])
    r["tcp"]["addr"] = attempts[-1]["addr"]

    try:
        # ---- TLS ----------------------------------------------------------
        if scheme == "https":
            t0 = time.perf_counter()
            try:
                ctx = _ssl_context(cfg)
                sock = ctx.wrap_socket(sock, server_hostname=None if literal else host)
                cert = sock.getpeercert() or {}
                subj = dict(x[0] for x in cert.get("subject", ()))
                r["tls"] = {"ok": True, "version": sock.version(),
                            "cipher": (sock.cipher() or [None])[0],
                            "cert_cn": subj.get("commonName"),
                            "cert_not_after": cert.get("notAfter"),
                            "ms": round((time.perf_counter() - t0) * 1000, 1)}
            except Exception as exc:  # noqa: BLE001
                r["tls"] = {"ms": round((time.perf_counter() - t0) * 1000, 1)}
                return fail("tls", _classify_tls_error(exc), f"{type(exc).__name__}: {exc}")
        else:
            r["tls"] = {"ok": True, "skipped": "plain http"}

        # ---- HTTP ---------------------------------------------------------
        t0 = time.perf_counter()
        try:
            h = _http_exchange(sock, host, port, scheme, path, cfg)
        except Exception as exc:  # noqa: BLE001
            r["http"] = {"ms": round((time.perf_counter() - t0) * 1000, 1)}
            code = "HTTP_TIMEOUT" if isinstance(exc, (socket.timeout, TimeoutError)) else "HTTP_ERROR"
            if isinstance(exc, ValueError):
                code = "HTTP_MALFORMED"
            return fail("http", code, f"{type(exc).__name__}: {exc}")
        h["ms"] = round((time.perf_counter() - t0) * 1000, 1)
        h["ok"] = h["status"] < 400
        r["http"] = h
        if h["status"] >= 400:
            return fail("http", f"HTTP_{h['status']}")
        if 300 <= h["status"] < 400 and h.get("location") and family == 6:
            target = urlsplit(urljoin(f"{scheme}://{host}:{port}{path}", h["location"]))
            if target.hostname and target.hostname.lower() != host.lower():
                a6 = dnswire.resolve(target.hostname, dnswire.TYPE_AAAA, cfg.resolvers, timeout=3.0)
                native = [a for a in a6.addresses if not dnswire.is_synthesized(a, cfg.nat64_prefixes)]
                h["redirect_host"] = target.hostname
                h["redirect_host_has_aaaa"] = bool(native)
                if not native:
                    return fail("http", "HTTP_REDIRECT_TO_IPV4_ONLY",
                                f"redirects to {target.hostname} which has no AAAA")
    finally:
        try:
            sock.close()
        except Exception:  # noqa: BLE001
            pass
    return r


_ROUTE_CACHE: dict = {}


def local_ipv6_route() -> bool:
    """Does THIS machine have a route to the IPv6 Internet?
    connect() on a UDP socket sends no packet; it only asks the kernel for a route."""
    if "v6" not in _ROUTE_CACHE:
        try:
            s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            s.connect(("2001:4860:4860::8888", 53))
            s.close()
            _ROUTE_CACHE["v6"] = True
        except OSError:
            _ROUTE_CACHE["v6"] = False
    return _ROUTE_CACHE["v6"]


def verdict(v6: dict, v4: dict) -> tuple[str, str | None, str | None]:
    """Combine the two family results -> (verdict, failed_stage, failure_code)."""
    v6_ok = v6["failed_stage"] is None
    v4_ok = v4["failed_stage"] is None
    synth = v6.get("dns", {}).get("synthesized")
    if v6_ok:
        if synth:
            return IPV4_ONLY_NAT64, "dns", "DNS_ONLY_SYNTHESIZED_AAAA"
        return READY, None, None
    stage, code = v6["failed_stage"], v6["failure_code"]
    # Is it IPv6-specific?  If IPv4 also fails at the same or an earlier layer,
    # the resource is simply broken (or blocks scanners) for everyone.
    if not v4_ok:
        same_http = (stage == "http" and v4["failed_stage"] == "http"
                     and v4["failure_code"] == code)
        if STAGES.index(v4["failed_stage"]) <= STAGES.index(stage) or same_http:
            return BROKEN_BOTH, stage, code
    if stage == "dns":
        if code in ("DNS_NO_AAAA", "DNS_NXDOMAIN", "DNS_LITERAL_OTHER_FAMILY"):
            return IPV4_ONLY, stage, code
        return IPV6_DNS_ERROR, stage, code
    if synth:          # only DNS64-synthesized AAAA: the host itself is IPv4-only
        return IPV4_ONLY_NAT64, "dns", "DNS_ONLY_SYNTHESIZED_AAAA"
    if code in ("TCP_NO_IPV6_STACK",) or (code == "TCP_UNREACHABLE" and not local_ipv6_route()):
        # The site has AAAA, but the failure is on OUR side (no IPv6 internet here).
        return INCONCLUSIVE_NO_IPV6, stage, code
    return {"tcp": IPV6_TCP_FAIL, "tls": IPV6_TLS_FAIL, "http": IPV6_HTTP_FAIL}[stage], stage, code


def probe_endpoint(url: str, cfg: ProbeConfig) -> dict:
    sp = urlsplit(url)
    scheme = sp.scheme.lower()
    port = sp.port or (443 if scheme == "https" else 80)
    path = sp.path or "/"
    if sp.query:
        path += "?" + sp.query
    host = sp.hostname or ""
    v6 = probe_family(scheme, host, port, path, 6, cfg)
    v4 = probe_family(scheme, host, port, path, 4, cfg)
    # A single timeout is often a momentary network stall, not a property of the host.
    # Retry each timed-out family once; it only counts as a failure if it fails again.
    retried = {}
    for fam_no in (6, 4):
        res = v6 if fam_no == 6 else v4
        if res["failure_code"] and "TIMEOUT" in res["failure_code"]:
            time.sleep(cfg.retry_delay)
            again = probe_family(scheme, host, port, path, fam_no, cfg)
            retried[f"ipv{fam_no}"] = {"first_failure": res["failure_code"],
                                      "second_failure": again["failure_code"]}
            if fam_no == 6:
                v6 = again
            else:
                v4 = again
    v, stage, code = verdict(v6, v4)
    return {"origin": f"{scheme}://{host}:{port}", "host": host, "port": port, "scheme": scheme,
            "probe_url": url, "verdict": v, "failed_stage": stage, "failure_code": code,
            "ipv6": v6, "ipv4": v4, "retried": retried}
