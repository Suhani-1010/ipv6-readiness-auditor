"""Step 6c: show the details behind the interesting results of a batch run.

Run:  python step6_inspect.py hostel

Prints:
  1. every host that HAS a real AAAA record but fails over IPv6 (TCP / TLS / HTTP),
     with the exact error and what IPv4 did for comparison
  2. timeouts that succeeded on the automatic retry (treated as momentary glitches)
  3. every site whose page verdict is UNREACHABLE, with the main host's layer results
and, for every site where the main host failed identically on IPv4 and IPv6 (but the
browser loaded the page), a note at the end.
"""
import glob
import json
import os
import sys

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(errors="replace")

AAAA_BROKEN = {"IPV6_TCP_FAIL", "IPV6_TLS_FAIL", "IPV6_HTTP_FAIL", "IPV6_DNS_ERROR"}


def ladder(fam):
    out = []
    for st in ("dns", "tcp", "tls", "http"):
        if fam.get("failed_stage") == st:
            out.append(f"{st.upper()}:FAIL")
        elif (fam.get(st) or {}).get("ok"):
            out.append(f"{st.upper()}:ok")
        else:
            out.append(f"{st.upper()}:--")
    return " ".join(out)


def detail(fam):
    st = fam.get("failed_stage")
    if not st:
        h = fam.get("http") or {}
        return f"HTTP {h.get('status', '')}"
    d = fam.get(st) or {}
    msg = d.get("error") or (f"HTTP {d.get('status')} {d.get('reason', '')}" if d.get("status") else "")
    return f"{fam.get('failure_code')}  {str(msg)[:110]}"


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return
    label = sys.argv[1]
    files = sorted(glob.glob(os.path.join("results", label, "sites", "*.json")))
    if not files:
        print(f"No results found in results/{label}/sites/")
        return

    print(f"=== 1. Hosts WITH a real AAAA record that still fail over IPv6 ({label}) ===\n")
    n = 0
    for p in files:
        a = json.load(open(p, encoding="utf-8"))
        site = a.get("site", {}).get("name", a["page"])
        for origin, o in sorted(a["origins"].items()):
            if o["verdict"] not in AAAA_BROKEN:
                continue
            n += 1
            v6, v4 = o["ipv6"], o["ipv4"]
            third = any(r["origin"] == origin and r["third_party"] for r in a["resources"].values())
            types = sorted({r["resource_type"] for r in a["resources"].values() if r["origin"] == origin})
            print(f"[{site}] {origin}   ({'3rd-party' if third else '1st-party'}; {', '.join(types)})")
            print(f"   verdict : {o['verdict']}  (failed at {o['failed_stage'].upper()})")
            print(f"   IPv6    : {ladder(v6)}   -> {detail(v6)}")
            print(f"             addresses {', '.join(v6['dns'].get('addresses', [])[:2])}")
            print(f"   IPv4    : {ladder(v4)}   -> {detail(v4)}")
            if o.get("retried"):
                print(f"   retried : {o['retried']}  (timed out twice: counted as a real failure)")
            print()
    if n == 0:
        print("(none)\n")

    print(f"=== 2. Timeouts that recovered on retry (NOT counted as failures) ({label}) ===\n")
    k = 0
    for p in files:
        a = json.load(open(p, encoding="utf-8"))
        for origin, o in sorted(a["origins"].items()):
            for fam, r in (o.get("retried") or {}).items():
                if r.get("second_failure") is None:
                    k += 1
                    print(f"[{a.get('site', {}).get('name', a['page'])}] {origin}  {fam}: "
                          f"{r['first_failure']} -> ok on retry")
    print("(none)\n" if k == 0 else "")

    print(f"=== 3. Sites with page verdict UNREACHABLE ({label}) ===\n")
    m = 0
    for p in files:
        a = json.load(open(p, encoding="utf-8"))
        if a["summary"]["page_verdict"] != "UNREACHABLE":
            continue
        m += 1
        root = a["tree"]["root"]
        node = a["resources"].get(root, {})
        o = a["origins"].get(node.get("origin"), {})
        print(f"[{a.get('site', {}).get('name', a['page'])}] {a['page']}")
        print(f"   browser : status {node.get('status')}  error {node.get('browser_error')}  "
              f"final URL {a.get('final_url')}")
        print(f"   capture : {'; '.join(a.get('capture_errors', [])) or '-'}")
        if o:
            print(f"   IPv6    : {ladder(o['ipv6'])}   -> {detail(o['ipv6'])}")
            print(f"   IPv4    : {ladder(o['ipv4'])}   -> {detail(o['ipv4'])}")
        print()
    if m == 0:
        print("(none)\n")

    print(f"=== 4. Main host failed IDENTICALLY on IPv4 and IPv6 (IPv6 = IPv4 here) ({label}) ===\n")
    q = 0
    for p in files:
        a = json.load(open(p, encoding="utf-8"))
        if a["summary"].get("root_http_parity"):
            q += 1
            # older result files don't store the code: read it from the main host's probe
            code = a["summary"].get("root_parity_code")
            if not code:
                root_origin = a["resources"].get(a["tree"]["root"], {}).get("origin")
                code = a["origins"].get(root_origin, {}).get("failure_code")
            print(f"[{a.get('site', {}).get('name', a['page'])}] same error on both: "
                  f"{code}  -> page judged by its dependencies "
                  f"({a['summary']['page_verdict']})")
    print("(none)\n" if q == 0 else "")


if __name__ == "__main__":
    main()
