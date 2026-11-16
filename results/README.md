# Results

| Folder | Run | Network | Date |
|---|---|---|---|
| `hostel/` | main result | Windows laptop on a Jio hotspot: dual-stack IPv6 + DNS64/NAT64 | 24 Oct 2026 |
| `lab-headed/` | comparison | Ubuntu VM on IIT Guwahati campus Wi-Fi: IPv4-only | 19 Oct 2026 |
| `benchmark/` | validation | Ubuntu VM, IPv6 loopback `::1` | 24 Oct 2026 |

Each run folder holds `stats.md` (all statistics), `summary.csv`, `site_table.csv`, `offenders.csv`, three charts and one JSON / CSV / HTML report per site in `sites/` (open the `.html` files in a browser). `comparison.md` compares the two runs site by site.

Regenerate the statistics with `python step6_analyze.py lab-headed hostel`.
