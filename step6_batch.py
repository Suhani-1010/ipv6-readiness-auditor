"""Step 6a: audit every site in sites.csv and save the results.

Run (inside the venv):
    python3 step6_batch.py --label lab          # in the college lab (IPv4-only vantage)
    python3 step6_batch.py --label hostel       # on Windows + phone hotspot (dual-stack)

Results go to results/<label>/ :
    sites/<site>.json/.csv/.html   full report for every site (same as step 4)
    summary.csv                    one row per site
    run_info.json                  where/when the run happened (vantage point)

If the run is interrupted, run the same command again: finished sites are skipped.
Use --redo to audit everything again.
"""
import argparse
import csv
import datetime as dt
import json
import os
import sys
import time
import traceback

from ipv6audit import auditor, report

if hasattr(sys.stdout, "reconfigure"):          # Windows consoles: never crash on odd characters
    sys.stdout.reconfigure(errors="replace")

SUMMARY_FIELDS = ["category", "name", "url", "status", "error", "root_status", "page_verdict", "root_verdict",
                  "root_has_aaaa", "resources_total", "origins_total", "origins_ready",
                  "origins_ipv4_only", "origins_aaaa_but_broken", "origins_nat64", "origins_inconclusive",
                  "origins_broken_both", "fail_dns", "fail_tcp", "fail_tls", "fail_http",
                  "ipv6_failing_resources", "ipv6_failing_critical", "ipv6_failing_third_party",
                  "resource_ipv6_ready_pct", "ipv4_only_hosts", "aaaa_but_broken_hosts", "seconds"]


def summary_row(site: dict, a: dict, seconds: float) -> dict:
    s = a["summary"]
    ov = s["origins_by_verdict"]
    st = s["ipv6_failures_by_stage"]
    root = a["resources"].get(a["tree"]["root"], {})
    return {**site, "status": "ok", "error": "; ".join(a.get("capture_errors", []))[:200],
            "root_status": root.get("status") or root.get("browser_error") or "no response",
            "page_verdict": s["page_verdict"], "root_verdict": s["root_verdict"],
            "root_has_aaaa": s["root_has_aaaa"], "resources_total": s["resources_total"],
            "origins_total": s["origins_total"], "origins_ready": ov.get("READY", 0),
            "origins_ipv4_only": ov.get("IPV4_ONLY", 0),
            "origins_aaaa_but_broken": sum(ov.get(k, 0) for k in ("IPV6_TCP_FAIL", "IPV6_TLS_FAIL",
                                                                  "IPV6_HTTP_FAIL", "IPV6_DNS_ERROR")),
            "origins_nat64": ov.get("IPV4_ONLY_NAT64", 0),
            "origins_inconclusive": ov.get("INCONCLUSIVE_NO_IPV6", 0),
            "origins_broken_both": ov.get("BROKEN_BOTH", 0),
            "fail_dns": st.get("dns", 0), "fail_tcp": st.get("tcp", 0),
            "fail_tls": st.get("tls", 0), "fail_http": st.get("http", 0),
            "ipv6_failing_resources": s["ipv6_failing_resources"],
            "ipv6_failing_critical": s["ipv6_failing_critical"],
            "ipv6_failing_third_party": s["ipv6_failing_third_party"],
            "resource_ipv6_ready_pct": s["resource_ipv6_ready_pct"],
            "ipv4_only_hosts": " ".join(s["ipv4_only_hosts"]),
            "aaaa_but_broken_hosts": " ".join(s["aaaa_but_broken_hosts"]),
            "seconds": round(seconds, 1)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--label", required=True, help="name for this run, e.g. lab or hostel")
    ap.add_argument("--sites", default="sites.csv")
    ap.add_argument("--resolver", default=None, help="DNS server, e.g. 1.1.1.1 (default: system)")
    ap.add_argument("--timeout", type=float, default=5.0, help="seconds per connection attempt")
    ap.add_argument("--redo", action="store_true", help="audit sites again even if already done")
    ap.add_argument("--only", default=None,
                    help='redo just these sites, comma-separated names, e.g. "NDTV,Swiggy,IRCTC"')
    ap.add_argument("--headed", action="store_true",
                    help="run Chrome with a visible window (gets past some bot blockers). "
                         "On Linux without a screen, start with: xvfb-run python3 step6_batch.py ...")
    args = ap.parse_args()

    outdir = os.path.join("results", args.label)
    sitedir = os.path.join(outdir, "sites")
    os.makedirs(sitedir, exist_ok=True)
    with open(args.sites, newline="", encoding="utf-8") as fh:
        sites = list(csv.DictReader(fh))

    summary_path = os.path.join(outdir, "summary.csv")
    done = {}
    if os.path.exists(summary_path) and not args.redo:
        with open(summary_path, newline="", encoding="utf-8") as fh:
            done = {r["url"]: r for r in csv.DictReader(fh) if r["status"] == "ok"}
    if args.only:
        wanted = [w.strip().lower() for w in args.only.split(",") if w.strip()]
        redo = [s for s in sites if any(w in s["name"].lower() for w in wanted)]
        print("Re-auditing only:", ", ".join(s["name"] for s in redo) or "(no name matched!)")
        for s in redo:
            done.pop(s["url"], None)

    cfg = auditor.make_config(resolver=args.resolver, timeout=args.timeout)
    vantage = auditor.detect_pathway(cfg)
    print(f"Run '{args.label}': vantage = {vantage['pathway']}, resolvers = {cfg.resolvers}")
    print(f"{len(sites)} sites, {len(done)} already done\n")
    info = {"label": args.label, "vantage": vantage, "resolvers": cfg.resolvers,
            "started_utc": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
            "platform": sys.platform, "python": sys.version.split()[0]}

    rows = []
    for i, site in enumerate(sites, 1):
        site = {k: site[k] for k in ("category", "name", "url")}
        if site["url"] in done:
            rows.append(done[site["url"]])
            print(f"[{i:2}/{len(sites)}] {site['name']:<18} (already done)")
            continue
        t0 = time.time()
        try:
            a = auditor.audit(site["url"], cfg, timeout_s=45, settle_s=3, headless=not args.headed)
            a["site"] = site
            paths = report.write_all(a, sitedir)
            row = summary_row(site, a, time.time() - t0)
            print(f"[{i:2}/{len(sites)}] {site['name']:<18} {row['page_verdict']:<22} "
                  f"{row['origins_total']:>3} origins, {row['origins_ipv4_only'] + row['origins_nat64']:>3} IPv4-only, "
                  f"{row['origins_aaaa_but_broken']:>2} AAAA-but-broken  ({row['seconds']}s)")
            rs = str(row["root_status"])
            if not rs.isdigit() or int(rs) >= 400 or int(row["resources_total"]) <= 2:
                print(f"         WARNING: page answered {rs} with {row['resources_total']} file(s): "
                      "probably blocked or empty, dependency counts are incomplete")
        except Exception as exc:  # noqa: BLE001  one bad site must not stop the batch
            row = {**site, "status": "error", "error": f"{type(exc).__name__}: {exc}"[:200],
                   "seconds": round(time.time() - t0, 1)}
            print(f"[{i:2}/{len(sites)}] {site['name']:<18} ERROR {row['error'][:80]}")
            traceback.print_exc(limit=1)
        rows.append(row)
        # rewrite summary after every site so an interruption loses nothing
        with open(summary_path, "w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=SUMMARY_FIELDS, extrasaction="ignore")
            w.writeheader()
            w.writerows(rows + [done[s["url"]] for s in sites[i:] if s["url"] in done])

    info["finished_utc"] = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    with open(os.path.join(outdir, "run_info.json"), "w", encoding="utf-8") as fh:
        json.dump(info, fh, indent=2)
    ok = sum(1 for r in rows if r.get("status") == "ok")
    print(f"\nDone: {ok}/{len(sites)} sites audited. Summary: {summary_path}")
    print(f"Next: python3 step6_analyze.py {args.label}")


if __name__ == "__main__":
    main()
