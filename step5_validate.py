"""Step 5: audit the benchmark site and check the auditor against the ground truth.

Terminal 1:  python3 -m ipv6audit.bench serve      (leave it running)
Terminal 2:  python3 step5_validate.py
"""
import json

from ipv6audit import auditor, report

state = json.load(open("bench/state.json", encoding="utf-8"))
cfg = auditor.make_config(resolver=state["dns"], timeout=3.0, ca_file=state["ca_file"],
                          v6_shim=state["v6_shim"])
if state["v6_shim"]:
    print("NOTE: lab shim active (this machine has no IPv6 stack)\n")

# The browser must find *.bench.test too: map those names to 127.0.0.1 (IPv4 discovery).
browser_args = [f"--host-resolver-rules=MAP *.{state['zone']} 127.0.0.1", "--no-proxy-server", "--ignore-certificate-errors"]
result = auditor.audit(state["root_url"], cfg, browser_args=browser_args,
                       ignore_https_errors=True, settle_s=2)
paths = report.write_all(result, "reports")

got = result["origins"]
expected = state["expected"]
rows, seeded, detected, false_alarms = [], 0, 0, 0
for origin, exp in expected.items():
    g = got.get(origin)
    if g is None:
        status = "MISSED (never discovered by crawler)"
        ok = False
    else:
        ok = (g["verdict"], g["failed_stage"], g["failure_code"]) == (exp["verdict"], exp["stage"], exp["code"])
        status = "PASS" if ok else f"FAIL (got {g['verdict']} / {g['failed_stage']} / {g['failure_code']})"
    if exp["verdict"] != "READY":
        seeded += 1
        detected += ok
    elif not ok:
        false_alarms += 1
    rows.append((origin, exp, status))

print(f"{'origin':<36} {'expected verdict':<17} {'layer':<5} {'code':<27} result")
print("-" * 112)
for origin, exp, status in rows:
    print(f"{origin:<36} {exp['verdict']:<17} {str(exp['stage'] or '-'):<5} {str(exp['code'] or '-'):<27} {status}")

extra = set(got) - set(expected)
print(f"\nSeeded issues detected at the correct layer: {detected}/{seeded}  "
      f"({100 * detected / seeded:.0f}%)")
print(f"Healthy hosts wrongly flagged (false alarms): {false_alarms}")
if extra:
    print(f"Unexpected extra origins: {sorted(extra)}")
print(f"Page verdict: {result['summary']['page_verdict']}")
print(f"HTML report: {paths['html']}")
