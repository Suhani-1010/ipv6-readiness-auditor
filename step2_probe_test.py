"""Step 2: test DNS -> TCP -> TLS -> HTTP over IPv6 and IPv4 for a few sites.

Run from the project folder:   python3 step2_probe_test.py
Optional: give your own URLs:  python3 step2_probe_test.py https://example.com
"""
import sys

from ipv6audit import dnswire, probe

urls = sys.argv[1:] or [
    "https://www.google.com/",
    "https://github.com/",
    "https://www.wikipedia.org/",
    "https://www.cloudflare.com/",
]

cfg = probe.ProbeConfig(resolvers=dnswire.system_resolvers(), timeout=5.0)

print("Does this machine have an IPv6 route to the Internet?",
      "YES" if probe.local_ipv6_route() else "NO  (IPv6 results will be INCONCLUSIVE, not the site's fault)")


def ladder(fam: dict) -> str:
    """Show each layer as ok / FAIL / -- (not reached)."""
    parts = []
    for stage in probe.STAGES:
        if fam["failed_stage"] == stage:
            parts.append(f"{stage.upper()}:FAIL")
        elif (fam.get(stage) or {}).get("ok"):
            parts.append(f"{stage.upper()}:ok")
        else:
            parts.append(f"{stage.upper()}:--")
    return "  ".join(parts)


for url in urls:
    r = probe.probe_endpoint(url, cfg)
    v6, v4 = r["ipv6"], r["ipv4"]
    print(f"\n{url}")
    print(f"  IPv6  {ladder(v6)}   {v6['failure_code'] or ''}")
    print(f"  IPv4  {ladder(v4)}   {v4['failure_code'] or ''}")
    if v6["http"].get("status"):
        print(f"  IPv6 HTTP status: {v6['http']['status']}")
    if v4["http"].get("status"):
        print(f"  IPv4 HTTP status: {v4['http']['status']}")
    if v6["failed_stage"] == "tcp":
        print(f"  IPv6 TCP error: {v6['tcp'].get('error')}")
    print(f"  ==> VERDICT: {r['verdict']}"
          + (f"  (failed at {r['failed_stage'].upper()} layer: {r['failure_code']})" if r["failed_stage"] else ""))
