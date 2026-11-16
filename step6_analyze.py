"""Step 6b: turn batch results into statistics, tables and charts.

Run:  python3 step6_analyze.py lab               # one run
      python3 step6_analyze.py lab hostel        # several runs + a comparison table

Writes into results/<label>/ :
    stats.md              the numbers for your report (Markdown tables)
    site_table.csv        one row per site (open in Excel / LibreOffice)
    offenders.csv         IPv4-only / broken hosts and how many sites depend on them
    chart_*.png           charts (needs matplotlib: pip install matplotlib)
and, with more than one label, results/comparison.md
"""
import csv
import glob
import json
import os
import sys
from collections import Counter, defaultdict

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(errors="replace")

BAD = {"IPV4_ONLY", "IPV4_ONLY_NAT64", "IPV6_TCP_FAIL", "IPV6_TLS_FAIL", "IPV6_HTTP_FAIL", "IPV6_DNS_ERROR"}
AAAA_BROKEN = {"IPV6_TCP_FAIL", "IPV6_TLS_FAIL", "IPV6_HTTP_FAIL", "IPV6_DNS_ERROR"}
PAGE_ORDER = ["FULLY_READY", "DEGRADED_ON_IPV6", "BROKEN_ON_IPV6", "NOT_READY", "INCONCLUSIVE_NO_IPV6",
              "UNREACHABLE", "ERROR"]
PAGE_MEANING = {"FULLY_READY": "every resource works over IPv6",
                "DEGRADED_ON_IPV6": "only images/fonts/media fail",
                "BROKEN_ON_IPV6": "a script, stylesheet or API fails",
                "NOT_READY": "the page itself fails over IPv6",
                "INCONCLUSIVE_NO_IPV6": "cannot judge: no IPv6 route at this vantage",
                "UNREACHABLE": "main page fails on IPv4 too (down or blocked)",
                "ERROR": "audit crashed"}

# Status palette (reference instance of the dataviz skill)
C_GOOD, C_WARN, C_SERIOUS, C_CRIT = "#0ca30c", "#fab219", "#ec835a", "#d03b3b"
C_NEUTRAL, C_FAINT = "#a3a29b", "#d6d5ce"
TEXT, TEXT2, SURFACE = "#0b0b0b", "#52514e", "#fcfcfb"


def pct(a, b):
    return f"{100 * a / b:.0f}%" if b else "-"


def load(label):
    d = os.path.join("results", label)
    with open(os.path.join(d, "summary.csv"), newline="", encoding="utf-8") as fh:
        summary = list(csv.DictReader(fh))
    info = {}
    if os.path.exists(os.path.join(d, "run_info.json")):
        info = json.load(open(os.path.join(d, "run_info.json"), encoding="utf-8"))
    audits = {}
    for p in glob.glob(os.path.join(d, "sites", "*.json")):
        a = json.load(open(p, encoding="utf-8"))
        audits[a["page"]] = a
    return d, summary, info, audits


def analyze(label):
    d, summary, info, audits = load(label)
    ok = [r for r in summary if r["status"] == "ok"]
    n = len(ok)
    verdicts = Counter(r["page_verdict"] for r in ok)
    verdicts["ERROR"] = len(summary) - n

    root_aaaa = [r for r in ok if r["root_has_aaaa"] == "True"]
    aaaa_not_ready = [r for r in root_aaaa if r["page_verdict"] not in ("FULLY_READY", "UNREACHABLE")]
    aaaa_not_ready_definite = [r for r in aaaa_not_ready if r["page_verdict"] not in ("INCONCLUSIVE_NO_IPV6",)]

    # ---- dependency-level statistics (from the full per-site JSON) -----------------
    origin_verdicts = Counter()
    layer = Counter()
    third_bad = first_bad = 0
    host_sites = defaultdict(set)          # failing host -> sites that depend on it
    host_verdict = {}
    crit_bad_sites = 0
    for r in ok:
        a = audits.get(r["url"])
        if not a:
            continue
        nodes = a["resources"]
        origin_party = {}
        for n_ in nodes.values():
            origin_party.setdefault(n_["origin"], n_["third_party"])
        for origin, o in a["origins"].items():
            origin_verdicts[o["verdict"]] += 1
            if o["verdict"] in BAD:
                layer[o["failed_stage"]] += 1
                if origin_party.get(origin):
                    third_bad += 1
                else:
                    first_bad += 1
                host_sites[o["host"]].add(r["name"])
                host_verdict[o["host"]] = f"{o['verdict']} ({o['failure_code']})"
        if any(n_["critical"] and n_["verdict"] in BAD for n_ in nodes.values()):
            crit_bad_sites += 1

    retried = recovered = 0
    for r in ok:
        a = audits.get(r["url"])
        for o in (a or {}).get("origins", {}).values():
            for res in (o.get("retried") or {}).values():
                retried += 1
                recovered += res.get("second_failure") is None
    total_origins = sum(origin_verdicts.values())
    bad_origins = sum(v for k, v in origin_verdicts.items() if k in BAD)
    v4only = lambda r: int(r["origins_ipv4_only"] or 0) + int(r.get("origins_nat64") or 0)  # noqa: E731
    sites_with_v4_dep = sum(1 for r in ok if v4only(r) > 0)

    # ---- per-category -------------------------------------------------------------
    cats = defaultdict(list)
    for r in ok:
        cats[r["category"]].append(r)

    # ---- write site_table.csv and offenders.csv ----------------------------------
    cols = ["category", "name", "page_verdict", "root_has_aaaa", "resources_total", "origins_total",
            "origins_ready", "origins_ipv4_only", "origins_aaaa_but_broken", "origins_inconclusive",
            "fail_dns", "fail_tcp", "fail_tls", "fail_http", "resource_ipv6_ready_pct", "ipv4_only_hosts"]
    with open(os.path.join(d, "site_table.csv"), "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        w.writerows(summary)
    offenders = sorted(host_sites.items(), key=lambda kv: (-len(kv[1]), kv[0]))
    with open(os.path.join(d, "offenders.csv"), "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["host", "verdict", "sites_affected", "site_names"])
        for h, s in offenders:
            w.writerow([h, host_verdict[h], len(s), "; ".join(sorted(s))])

    # ---- stats.md ---------------------------------------------------------------------
    v = info.get("vantage", {})
    L = [f"# IPv6 readiness: run `{label}`", "",
         f"- Vantage point: **{v.get('pathway', '?')}** (IPv6 route: {v.get('ipv6_default_route')}, "
         f"NAT64 prefixes: {v.get('nat64_prefixes') or 'none'})",
         f"- Run time (UTC): {info.get('started_utc', '?')} to {info.get('finished_utc', '?')}",
         f"- Sites audited: **{n} of {len(summary)}**", ""]
    if v and not v.get("ipv6_default_route"):
        L += ["> This vantage point has **no IPv6 route**. DNS-layer results (missing AAAA) are definite;",
              "> TCP/TLS/HTTP results for hosts that do have AAAA are INCONCLUSIVE and must be re-measured",
              "> from an IPv6-capable network.", ""]
    L += ["## 1. Page-level verdicts", "", "| Verdict | Sites | Share | Meaning |", "|---|---|---|---|"]
    for k in PAGE_ORDER:
        if verdicts.get(k):
            L.append(f"| {k} | {verdicts[k]} | {pct(verdicts[k], len(summary))} | {PAGE_MEANING[k]} |")
    L += ["", "## 2. AAAA record vs real readiness", "",
          f"- Sites whose main host has an AAAA record: **{len(root_aaaa)} / {n}** ({pct(len(root_aaaa), n)})",
          f"- ...of those, NOT fully IPv6-ready: **{len(aaaa_not_ready)}** "
          f"({len(aaaa_not_ready_definite)} definite, {len(aaaa_not_ready) - len(aaaa_not_ready_definite)} inconclusive)",
          "- An AAAA check alone would have called all of these sites ready.", ""]
    if aaaa_not_ready_definite:
        L.append("Sites with AAAA that still fail on IPv6: " +
                 ", ".join(f"{r['name']} ({r['page_verdict']})" for r in aaaa_not_ready_definite))
        L.append("")
    L += ["## 3. IPv4 dependency leakage", "",
          f"- Unique (site, origin) pairs probed: **{total_origins}**",
          f"- Failing over IPv6: **{bad_origins}** ({pct(bad_origins, total_origins)}), "
          f"of which third-party: **{third_bad}** ({pct(third_bad, bad_origins)}), first-party: {first_bad}",
          f"- Sites depending on at least one IPv4-only host: **{sites_with_v4_dep} / {n}**",
          f"- Sites where a *critical* resource (script/stylesheet/API) fails on IPv6: **{crit_bad_sites} / {n}**",
          f"- Inconclusive origins (no IPv6 route here): {origin_verdicts.get('INCONCLUSIVE_NO_IPV6', 0)}",
          f"- Timed-out probes retried once: {retried} ({recovered} succeeded on retry and are not counted as failures)",
          "", "### Failing origins by layer", "", "| Layer | Origins | Share of failures |", "|---|---|---|"]
    for st in ("dns", "tcp", "tls", "http"):
        L.append(f"| {st.upper()} | {layer.get(st, 0)} | {pct(layer.get(st, 0), bad_origins)} |")
    L += ["", "### Origin verdicts (all sites together)", "", "| Verdict | Origins |", "|---|---|"]
    for k, c in origin_verdicts.most_common():
        L.append(f"| {k} | {c} |")
    L += ["", "## 4. By category", "",
          "| Category | Sites | Root has AAAA | Fully ready | Avg origins/site | IPv4-only origins |",
          "|---|---|---|---|---|---|"]
    for c, rs in cats.items():
        L.append(f"| {c} | {len(rs)} | {sum(r['root_has_aaaa'] == 'True' for r in rs)} | "
                 f"{sum(r['page_verdict'] == 'FULLY_READY' for r in rs)} | "
                 f"{sum(int(r['origins_total']) for r in rs) / len(rs):.1f} | "
                 f"{sum(v4only(r) for r in rs)} |")
    L += ["", "## 5. Most common failing hosts (shared dependencies)", "",
          "| Host | Verdict | Sites affected |", "|---|---|---|"]
    for h, s in offenders[:15]:
        L.append(f"| {h} | {host_verdict[h]} | {len(s)} |")
    L += ["", "## 6. Per-site results", "",
          "| Site | Category | Page verdict | Root AAAA | Origins | IPv4-only | AAAA-but-broken | Inconclusive |",
          "|---|---|---|---|---|---|---|---|"]
    for r in summary:
        if r["status"] != "ok":
            L.append(f"| {r['name']} | {r['category']} | ERROR | - | - | - | - | - |")
            continue
        L.append(f"| {r['name']} | {r['category']} | {r['page_verdict']} | {r['root_has_aaaa']} | "
                 f"{r['origins_total']} | {v4only(r)} | {r['origins_aaaa_but_broken']} | "
                 f"{r['origins_inconclusive']} |")
    blocked = [r for r in ok if not str(r.get("root_status", "200")).isdigit()
               or int(r.get("root_status") or 200) >= 400 or int(r["resources_total"]) <= 2]
    if blocked:
        L += ["", "### Sites that returned a blocked or empty page to the crawler", "",
              "Their DNS-layer verdict for the main host is still valid, but their dependency counts are incomplete.", ""]
        L += [f"- {r['name']}: answered {r.get('root_status')} with {r['resources_total']} file(s)" for r in blocked]
    errors = [r for r in summary if r["status"] != "ok"]
    if errors:
        L += ["", "### Errors", ""] + [f"- {r['name']}: {r['error']}" for r in errors]
    open(os.path.join(d, "stats.md"), "w", encoding="utf-8").write("\n".join(L) + "\n")

    charts(d, label, summary, verdicts, layer)
    print("\n".join(L[:40]))
    print(f"\n... full statistics in {os.path.join(d, 'stats.md')}")
    return {r["name"]: r.get("page_verdict", "ERROR") if r["status"] == "ok" else "ERROR" for r in summary}


def charts(d, label, summary, verdicts, layer):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        from matplotlib.ticker import MaxNLocator
    except ImportError:
        print("(matplotlib not installed: skipping charts.  pip install matplotlib)")
        return
    plt.rcParams.update({"font.size": 10, "axes.edgecolor": C_FAINT, "axes.labelcolor": TEXT2,
                         "xtick.color": TEXT2, "ytick.color": TEXT, "figure.facecolor": SURFACE,
                         "axes.facecolor": SURFACE, "axes.spines.top": False, "axes.spines.right": False})
    pcol = {"FULLY_READY": C_GOOD, "DEGRADED_ON_IPV6": C_WARN, "BROKEN_ON_IPV6": C_SERIOUS,
            "NOT_READY": C_CRIT, "INCONCLUSIVE_NO_IPV6": C_NEUTRAL, "UNREACHABLE": C_FAINT,
            "ERROR": C_FAINT}

    # 1. page verdicts
    ks = [k for k in PAGE_ORDER if verdicts.get(k)]
    fig, ax = plt.subplots(figsize=(7, 0.55 * len(ks) + 1.2))
    ax.barh(ks[::-1], [verdicts[k] for k in ks[::-1]], color=[pcol[k] for k in ks[::-1]], height=0.6)
    for i, k in enumerate(ks[::-1]):
        ax.text(verdicts[k] + 0.2, i, str(verdicts[k]), va="center", color=TEXT)
    ax.set_xlabel("number of sites")
    ax.xaxis.set_major_locator(MaxNLocator(integer=True))
    ax.set_title(f"Page-level IPv6 verdict ({label})", loc="left", color=TEXT)
    ax.grid(axis="x", color=C_FAINT, linewidth=0.6)
    ax.set_axisbelow(True)
    fig.tight_layout()
    fig.savefig(os.path.join(d, "chart_page_verdicts.png"), dpi=160)
    plt.close(fig)

    # 2. per-site origins by verdict (stacked)
    ok = [r for r in summary if r["status"] == "ok"]
    ok.sort(key=lambda r: int(r["origins_total"]))
    segs = [("origins_ready", "READY", C_GOOD), ("origins_ipv4_only", "IPv4-only (no AAAA)", C_CRIT),
            ("origins_aaaa_but_broken", "AAAA but TCP/TLS/HTTP fails", C_SERIOUS),
            ("origins_nat64", "IPv4-only (only a NAT64 AAAA)", C_WARN),
            ("origins_inconclusive", "inconclusive (no IPv6 route)", C_NEUTRAL),
            ("origins_broken_both", "broken on IPv4 too", C_FAINT)]
    fig, ax = plt.subplots(figsize=(9, 0.32 * len(ok) + 1.6))
    left = [0] * len(ok)
    names = [r["name"] for r in ok]
    for key, lab, col in segs:
        vals = [int(r[key] or 0) for r in ok]
        if sum(vals):
            ax.barh(names, vals, left=left, color=col, label=lab, height=0.7, edgecolor=SURFACE, linewidth=1.5)
            left = [a + b for a, b in zip(left, vals)]
    for i, tot in enumerate(left):
        ax.text(tot + 0.4, i, str(tot), va="center", fontsize=8, color=TEXT2)
    ax.set_xlabel("unique origins (hosts) loaded by the page")
    ax.set_title(f"Dependencies per site and their IPv6 state ({label})", loc="left", color=TEXT, pad=34)
    ax.legend(loc="lower left", bbox_to_anchor=(0, 1.02), ncol=3, frameon=False, fontsize=8)
    ax.xaxis.set_major_locator(MaxNLocator(integer=True))
    ax.grid(axis="x", color=C_FAINT, linewidth=0.6)
    ax.set_axisbelow(True)
    fig.tight_layout()
    fig.savefig(os.path.join(d, "chart_origins_per_site.png"), dpi=160)
    plt.close(fig)

    # 3. failures by layer
    st = ["dns", "tcp", "tls", "http"]
    vals = [layer.get(s, 0) for s in st]
    fig, ax = plt.subplots(figsize=(6, 3.2))
    ax.bar([s.upper() for s in st], vals, color="#2a78d6", width=0.55)
    for i, val in enumerate(vals):
        ax.text(i, val, str(val), ha="center", va="bottom", color=TEXT)
    ax.set_ylabel("failing origins")
    ax.yaxis.set_major_locator(MaxNLocator(integer=True))
    ax.set_title(f"Layer where IPv6 first fails ({label})", loc="left", color=TEXT)
    ax.grid(axis="y", color=C_FAINT, linewidth=0.6)
    ax.set_axisbelow(True)
    fig.tight_layout()
    fig.savefig(os.path.join(d, "chart_failure_layers.png"), dpi=160)
    plt.close(fig)
    print(f"Charts saved: {d}/chart_*.png")


def main():
    labels = sys.argv[1:]
    if not labels:
        print(__doc__)
        return
    per_run = {lab: analyze(lab) for lab in labels}
    if len(labels) > 1:
        sites = list(dict.fromkeys(s for run in per_run.values() for s in run))
        L = ["# Comparison of vantage points", "",
             "| Site | " + " | ".join(labels) + " |", "|---|" + "---|" * len(labels)]
        for s in sites:
            L.append(f"| {s} | " + " | ".join(per_run[lab].get(s, "-") for lab in labels) + " |")
        open(os.path.join("results", "comparison.md"), "w", encoding="utf-8").write("\n".join(L) + "\n")
        print("\nComparison written to results/comparison.md")


if __name__ == "__main__":
    main()
