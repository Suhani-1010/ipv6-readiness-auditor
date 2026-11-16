"""Audit orchestration: capture -> dependency tree -> per-origin layered probes."""
from __future__ import annotations

import datetime as _dt
from concurrent.futures import ThreadPoolExecutor

from . import crawler, dnswire, probe

# Resource types whose failure breaks the page (vs. merely degrading it).
CRITICAL_TYPES = {"Document", "Script", "Stylesheet", "Fetch", "XHR", "document", "script",
                  "stylesheet", "fetch", "xhr"}


def make_config(resolver=None, timeout=5.0, ca_file=None, v6_shim=None) -> probe.ProbeConfig:
    resolvers = dnswire.parse_resolver(resolver)
    cfg = probe.ProbeConfig(resolvers=resolvers, timeout=timeout, ca_file=ca_file,
                            v6_shim=v6_shim or {})
    cfg.nat64_prefixes = dnswire.detect_nat64_prefixes(resolvers)
    return cfg


def detect_pathway(cfg: probe.ProbeConfig) -> dict:
    """Describe the vantage point: can this host do native IPv6? NAT64?"""
    import socket
    info = {"nat64_prefixes": [str(p) for p in cfg.nat64_prefixes], "ipv6_stack": True,
            "ipv6_default_route": False, "ipv4_default_route": False, "lab_v6_shim": bool(cfg.v6_shim)}
    try:
        socket.socket(socket.AF_INET6, socket.SOCK_DGRAM).close()
    except OSError:
        info["ipv6_stack"] = False
    for fam, target, key in ((socket.AF_INET6, "2001:4860:4860::8888", "ipv6_default_route"),
                             (socket.AF_INET, "8.8.8.8", "ipv4_default_route")):
        try:
            s = socket.socket(fam, socket.SOCK_DGRAM)
            s.connect((target, 53))          # no packet sent; just a route lookup
            info[key] = True
            s.close()
        except OSError:
            pass
    v6, v4 = info["ipv6_default_route"], info["ipv4_default_route"]
    if info["nat64_prefixes"] and v6 and not v4:
        info["pathway"] = "ipv6-only + NAT64/DNS64 (synthesized)"
    elif v6 and v4 and info["nat64_prefixes"]:
        info["pathway"] = "dual-stack + DNS64/NAT64"
    elif v6 and v4:
        info["pathway"] = "dual-stack"
    elif v6:
        info["pathway"] = "ipv6-only (native)"
    elif v4:
        info["pathway"] = "ipv4-only"
    else:
        info["pathway"] = "no default route (lab)"
    return info


def audit(url: str, cfg: probe.ProbeConfig, *, browser_args=None, ignore_https_errors=False,
          timeout_s=30.0, settle_s=3.0, workers=16, headless=True) -> dict:
    started = _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")
    cap = crawler.capture(url, timeout_s=timeout_s, settle_s=settle_s, browser_args=browser_args,
                          ignore_https_errors=ignore_https_errors, headless=headless)
    tree = crawler.build_tree(cap)
    nodes = tree["nodes"]

    # One probe per origin, using the first URL seen for that origin.
    rep: dict[str, str] = {}
    for u, n in nodes.items():
        rep.setdefault(n["origin"], u)
    with ThreadPoolExecutor(max_workers=workers) as ex:
        results = dict(zip(rep.keys(), ex.map(lambda u: probe.probe_endpoint(u, cfg), rep.values())))

    for u, n in nodes.items():
        r = results[n["origin"]]
        n["verdict"], n["failed_stage"], n["failure_code"] = r["verdict"], r["failed_stage"], r["failure_code"]
        n["critical"] = n["resource_type"] in CRITICAL_TYPES

    # Propagate: on an IPv6-only network a child cannot load if any ancestor failed.
    bad = {probe.IPV4_ONLY, probe.IPV4_ONLY_NAT64, probe.IPV6_TCP_FAIL, probe.IPV6_TLS_FAIL,
           probe.IPV6_HTTP_FAIL, probe.IPV6_DNS_ERROR}
    for u, n in nodes.items():
        cur, blocker = n, None
        while cur.get("parent"):
            cur = nodes[cur["parent"]]
            if cur["verdict"] in bad:
                blocker = cur["url"]
        n["blocked_by"] = blocker

    summary = summarize(nodes, results, tree["root"])
    return {"schema": "ipv6-readiness-audit/1", "page": url, "final_url": cap.get("final_url"),
            "started_utc": started, "load_seconds": cap.get("load_seconds"),
            "vantage": detect_pathway(cfg), "capture_errors": cap["errors"], "summary": summary,
            "tree": {"root": tree["root"], "edges": tree["edges"]}, "resources": nodes,
            "origins": results}


def _native_aaaa(origin_result: dict) -> bool:
    dns = origin_result.get("ipv6", {}).get("dns", {})
    return bool(dns.get("addresses")) and not dns.get("synthesized")


def summarize(nodes: dict, origins: dict, root: str) -> dict:
    from collections import Counter
    rv = Counter(n["verdict"] for n in nodes.values())
    ov = Counter(o["verdict"] for o in origins.values())
    stages = Counter(o["failed_stage"] for o in origins.values()
                     if o["verdict"] not in (probe.READY, probe.BROKEN_BOTH, probe.INCONCLUSIVE_NO_IPV6))
    neutral = (probe.READY, probe.BROKEN_BOTH, probe.INCONCLUSIVE_NO_IPV6)
    ipv6_bad = [n for n in nodes.values() if n["verdict"] not in neutral]
    inconclusive = [n for n in nodes.values() if n["verdict"] == probe.INCONCLUSIVE_NO_IPV6]
    root_v = nodes[root]["verdict"] if root in nodes else None
    crit_bad = [n for n in ipv6_bad if n["critical"]]
    # Root probe got the SAME TLS or HTTP error over IPv4 and IPv6 (a bot filter, or e.g. an
    # incomplete certificate chain that browsers repair but strict clients reject), yet the
    # browser loaded the page: IPv6 behaves exactly like IPv4 here -> judge the rest of the page.
    root_o = origins.get(nodes.get(root, {}).get("origin"), {})
    bstatus = nodes.get(root, {}).get("status")
    root_http_parity = (root_v == probe.BROKEN_BOTH and root_o.get("failed_stage") in ("http", "tls")
                        and root_o["ipv6"]["failure_code"] == root_o["ipv4"]["failure_code"]
                        and isinstance(bstatus, int) and bstatus < 400)
    if root_http_parity:
        root_v = probe.READY
    if root_v == probe.BROKEN_BOTH:
        page = "UNREACHABLE"            # main page fails on IPv4 too: down/blocked, not an IPv6 result
    elif root_v == probe.INCONCLUSIVE_NO_IPV6 or (inconclusive and root_v == probe.READY and not ipv6_bad):
        page = "INCONCLUSIVE_NO_IPV6"   # can't finish the verdict from this vantage point
    elif root_v != probe.READY:
        page = "NOT_READY"           # the page itself is unreachable over IPv6
    elif crit_bad:
        page = "BROKEN_ON_IPV6"      # loads, but a script/style/API it needs fails
    elif ipv6_bad:
        page = "DEGRADED_ON_IPV6"    # only images/fonts/media fail
    else:
        page = "FULLY_READY"
    root_host = nodes.get(root, {}).get("host")
    return {
        "page_verdict": page, "root_verdict": root_v,
        # a *native* AAAA only: DNS64-synthesized 64:ff9b:: addresses don't count
        "root_has_aaaa": _native_aaaa(origins.get(nodes.get(root, {}).get("origin"), {})),
        "resources_total": len(nodes), "origins_total": len(origins),
        "resources_by_verdict": dict(rv), "origins_by_verdict": dict(ov),
        "ipv6_failures_by_stage": dict(stages),
        "ipv6_failing_resources": len(ipv6_bad),
        "inconclusive_resources": len(inconclusive),
        "ipv6_failing_critical": len(crit_bad),
        "ipv6_failing_third_party": sum(1 for n in ipv6_bad if n["third_party"]),
        "resource_ipv6_ready_pct": round(100 * rv.get(probe.READY, 0) / max(1, len(nodes)), 1),
        "ipv4_only_hosts": sorted({n["host"] for n in ipv6_bad
                                   if n["verdict"] in (probe.IPV4_ONLY, probe.IPV4_ONLY_NAT64)}),
        "aaaa_but_broken_hosts": sorted({n["host"] for n in ipv6_bad
                                         if n["verdict"] in (probe.IPV6_TCP_FAIL, probe.IPV6_TLS_FAIL,
                                                             probe.IPV6_HTTP_FAIL)}),
        "root_host": root_host,
        "root_http_parity": root_http_parity,
        "root_parity_code": root_o.get("failure_code") if root_http_parity else None,
        "retried_origins": sorted(o["host"] for o in origins.values() if o.get("retried")),
        "retry_recovered": sorted(o["host"] for o in origins.values()
                                  if o.get("retried", {}).get("ipv6", {}).get("second_failure", "x") is None),
    }
