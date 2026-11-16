"""Step 4: full audit of ONE page = crawl (step 3) + probe every host (step 2) + reports.

Run (inside the venv):  python3 step4_audit.py https://www.iitg.ac.in/
Reports are written to the  reports/  folder.
"""
import sys

from ipv6audit import auditor, report

url = sys.argv[1] if len(sys.argv) > 1 else "https://www.wikipedia.org/"

cfg = auditor.make_config(timeout=5.0)          # system DNS resolver, 5 s per connection
print(f"Vantage point: {auditor.detect_pathway(cfg)['pathway']}")
print(f"Auditing {url} ...")

result = auditor.audit(url, cfg)
s = result["summary"]

print(f"\nPAGE VERDICT: {s['page_verdict']}")
print(f"  root host {s['root_host']} has AAAA: {s['root_has_aaaa']}")
print(f"  resources: {s['resources_total']}   unique origins probed: {s['origins_total']}")
print(f"  origins by verdict: {s['origins_by_verdict']}")
print(f"  IPv6 failures by layer: {s['ipv6_failures_by_stage'] or '-'}")
print(f"  IPv4-only hosts: {', '.join(s['ipv4_only_hosts']) or '-'}")
print(f"  hosts with AAAA but broken: {', '.join(s['aaaa_but_broken_hosts']) or '-'}")

print("\nPer-origin results:")
for origin, o in sorted(result["origins"].items(), key=lambda kv: kv[1]["verdict"]):
    where = f"{o['failed_stage'].upper()}:{o['failure_code']}" if o["failed_stage"] else ""
    print(f"  {o['verdict']:<22} {origin:<55} {where}")

paths = report.write_all(result, "reports")
print("\nReports written:")
for kind, p in paths.items():
    print(f"  {kind:<14} {p}")
