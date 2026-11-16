"""Minimal DNS wire-format client (RFC 1035) using only the standard library.

Why not just socket.getaddrinfo()?  getaddrinfo hides *why* a lookup failed
(NXDOMAIN vs. NODATA vs. SERVFAIL vs. timeout) and silently mixes A/AAAA
results.  For a readiness audit we need the exact DNS outcome for the AAAA
query, plus the CNAME chain, so we speak DNS directly to a resolver.
"""
from __future__ import annotations

import ipaddress
import os
import random
import socket
import struct
import time
from dataclasses import dataclass, field

TYPE_A, TYPE_NS, TYPE_CNAME, TYPE_SOA, TYPE_AAAA = 1, 2, 5, 6, 28
CLASS_IN = 1
RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}


@dataclass
class DnsAnswer:
    qname: str
    qtype: int
    rcode: str = "NOERROR"          # NOERROR / NXDOMAIN / SERVFAIL / TIMEOUT / ERROR
    addresses: list[str] = field(default_factory=list)
    cname_chain: list[str] = field(default_factory=list)
    ttl: int | None = None
    elapsed_ms: float = 0.0
    error: str | None = None

    @property
    def nodata(self) -> bool:
        """Name exists but has no record of this type (the classic 'no AAAA')."""
        return self.rcode == "NOERROR" and not self.addresses


# --------------------------------------------------------------------------- #
# Encoding / decoding
# --------------------------------------------------------------------------- #
def encode_name(name: str) -> bytes:
    out = b""
    for label in name.rstrip(".").split("."):
        if label:
            raw = label.encode("idna") if not label.isascii() else label.encode()
            out += bytes([len(raw)]) + raw
    return out + b"\x00"


def build_query(name: str, qtype: int, qid: int | None = None) -> tuple[int, bytes]:
    qid = random.randint(0, 0xFFFF) if qid is None else qid
    header = struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0)  # RD=1
    return qid, header + encode_name(name) + struct.pack("!HH", qtype, CLASS_IN)


def decode_name(msg: bytes, off: int) -> tuple[str, int]:
    labels, jumped, end, hops = [], False, off, 0
    while True:
        if off >= len(msg):
            raise ValueError("truncated name")
        ln = msg[off]
        if ln & 0xC0 == 0xC0:                     # compression pointer
            ptr = struct.unpack("!H", msg[off:off + 2])[0] & 0x3FFF
            if not jumped:
                end = off + 2
            off, jumped = ptr, True
            hops += 1
            if hops > 30:
                raise ValueError("compression loop")
            continue
        if ln == 0:
            if not jumped:
                end = off + 1
            break
        labels.append(msg[off + 1:off + 1 + ln].decode(errors="replace"))
        off += 1 + ln
    return ".".join(labels).lower(), end


def parse_response(msg: bytes) -> dict:
    qid, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", msg[:12])
    off = 12
    for _ in range(qd):
        _, off = decode_name(msg, off)
        off += 4
    records = []
    for _ in range(an + ns):
        name, off = decode_name(msg, off)
        rtype, rclass, ttl, rdlen = struct.unpack("!HHIH", msg[off:off + 10])
        off += 10
        rdata = msg[off:off + rdlen]
        if rtype == TYPE_A and rdlen == 4:
            value = socket.inet_ntop(socket.AF_INET, rdata)
        elif rtype == TYPE_AAAA and rdlen == 16:
            value = str(ipaddress.IPv6Address(rdata))
        elif rtype in (TYPE_CNAME, TYPE_NS):
            value, _ = decode_name(msg, off)
        else:
            value = rdata.hex()
        records.append({"name": name, "type": rtype, "ttl": ttl, "value": value})
        off += rdlen
    return {"id": qid, "tc": bool(flags & 0x0200), "rcode": flags & 0x000F, "records": records}


# --------------------------------------------------------------------------- #
# Transport
# --------------------------------------------------------------------------- #
def system_resolvers() -> list[tuple[str, int]]:
    """DNS servers this machine uses: /etc/resolv.conf on Linux/Mac,
    PowerShell's Get-DnsClientServerAddress on Windows. Falls back to 8.8.8.8."""
    servers = []
    try:
        with open("/etc/resolv.conf") as fh:
            for line in fh:
                parts = line.split()
                if len(parts) >= 2 and parts[0] == "nameserver":
                    servers.append((parts[1].split("%")[0], 53))
    except OSError:
        pass
    if not servers and os.name == "nt":
        servers = _windows_resolvers()
    return servers or [("8.8.8.8", 53)]


def _windows_resolvers() -> list[tuple[str, int]]:
    import subprocess
    try:
        out = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             "Get-DnsClientServerAddress | Where-Object {$_.ServerAddresses} | "
             "ForEach-Object {$_.ServerAddresses}"],
            capture_output=True, text=True, timeout=15).stdout
    except (OSError, subprocess.SubprocessError):
        return []
    found = []
    for line in out.split():
        addr = line.strip()
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            continue
        # link-local (fe80::) and site-local fec0:: placeholders need a zone id; skip them
        if ip.is_link_local or addr.lower().startswith("fec0:"):
            continue
        if (addr, 53) not in found:
            found.append((addr, 53))
    # prefer IPv4 resolvers first: they work on every network
    return sorted(found, key=lambda s: ":" in s[0])


def parse_resolver(spec: str | None) -> list[tuple[str, int]]:
    """'1.1.1.1', '127.0.0.1:5353', '[2606:4700:4700::1111]:53' or None=system."""
    if not spec:
        env = os.environ.get("IPV6AUDIT_RESOLVER")
        if not env:
            return system_resolvers()
        spec = env
    out = []
    for item in spec.split(","):
        item = item.strip()
        if item.startswith("["):
            host, _, port = item[1:].partition("]")
            out.append((host, int(port.lstrip(":") or 53)))
        elif item.count(":") == 1:
            host, port = item.split(":")
            out.append((host, int(port)))
        else:
            out.append((item, 53))
    return out


def _exchange(server: tuple[str, int], payload: bytes, timeout: float) -> bytes:
    fam = socket.AF_INET6 if ":" in server[0] else socket.AF_INET
    with socket.socket(fam, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        s.sendto(payload, server)
        data, _ = s.recvfrom(4096)
    resp = parse_response(data)
    if resp["tc"]:                                  # truncated -> retry over TCP
        with socket.create_connection(server, timeout=timeout) as t:
            t.sendall(struct.pack("!H", len(payload)) + payload)
            ln = struct.unpack("!H", _recv_exact(t, 2))[0]
            data = _recv_exact(t, ln)
    return data


def _recv_exact(s: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("short read")
        buf += chunk
    return buf


def resolve(name: str, qtype: int, resolvers: list[tuple[str, int]] | None = None,
            timeout: float = 3.0, retries: int = 2, _depth: int = 0) -> DnsAnswer:
    """Resolve name/qtype, following CNAMEs. Never raises."""
    resolvers = resolvers or system_resolvers()
    ans = DnsAnswer(qname=name.lower().rstrip("."), qtype=qtype)
    t0 = time.perf_counter()
    last_err = None
    for attempt in range(retries + 1):
        server = resolvers[attempt % len(resolvers)]
        qid, payload = build_query(name, qtype)
        try:
            raw = _exchange(server, payload, timeout)
            resp = parse_response(raw)
            if resp["id"] != qid:
                last_err = "id mismatch"
                continue
            break
        except socket.timeout:
            last_err = "TIMEOUT"
        except (OSError, ValueError, struct.error) as exc:
            last_err = f"{type(exc).__name__}: {exc}"
    else:
        ans.rcode = "TIMEOUT" if last_err == "TIMEOUT" else "ERROR"
        ans.error = last_err
        ans.elapsed_ms = (time.perf_counter() - t0) * 1000
        return ans

    ans.rcode = RCODES.get(resp["rcode"], f"RCODE{resp['rcode']}")
    # Walk the CNAME chain inside the answer section.
    target = ans.qname
    by_name: dict[str, list[dict]] = {}
    for rr in resp["records"]:
        by_name.setdefault(rr["name"], []).append(rr)
    for _ in range(16):
        rrs = by_name.get(target, [])
        cn = [r for r in rrs if r["type"] == TYPE_CNAME]
        if cn:
            target = cn[0]["value"]
            ans.cname_chain.append(target)
            continue
        hits = [r for r in rrs if r["type"] == qtype]
        ans.addresses = [r["value"] for r in hits]
        if hits:
            ans.ttl = min(r["ttl"] for r in hits)
        break
    # Resolver gave us only a CNAME: chase it ourselves.
    if not ans.addresses and ans.cname_chain and ans.rcode == "NOERROR" and _depth < 8:
        sub = resolve(target, qtype, resolvers, timeout, retries, _depth + 1)
        ans.addresses, ans.rcode = sub.addresses, sub.rcode
        ans.cname_chain += sub.cname_chain
        ans.ttl = sub.ttl
    ans.elapsed_ms = (time.perf_counter() - t0) * 1000
    return ans


# --------------------------------------------------------------------------- #
# NAT64 / DNS64 detection (RFC 7050)
# --------------------------------------------------------------------------- #
WELL_KNOWN_V4 = {"192.0.0.170", "192.0.0.171"}


def detect_nat64_prefixes(resolvers=None, timeout: float = 2.0) -> list[ipaddress.IPv6Network]:
    """Query ipv4only.arpa AAAA. A DNS64 resolver synthesises an answer whose
    embedded IPv4 address is 192.0.0.170/171; the surrounding bits are the NAT64
    prefix.  We support the common /96 case (e.g. 64:ff9b::/96)."""
    ans = resolve("ipv4only.arpa", TYPE_AAAA, resolvers, timeout=timeout, retries=1)
    prefixes = set()
    for a in ans.addresses:
        ip = ipaddress.IPv6Address(a)
        tail = ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
        if str(tail) in WELL_KNOWN_V4:
            prefixes.add(ipaddress.IPv6Network((int(ip) & ~0xFFFFFFFF, 96)))
    return sorted(prefixes)


def is_synthesized(addr: str, prefixes) -> bool:
    try:
        ip = ipaddress.IPv6Address(addr)
    except ValueError:
        return False
    if ip in ipaddress.IPv6Network("64:ff9b::/96"):
        return True
    return any(ip in p for p in prefixes)
