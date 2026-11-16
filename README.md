# IPv6 Website and Dependency Readiness Auditor

A tool that checks whether a website **really works for an IPv6-only user**: not just whether its name has an IPv6 address (an AAAA record), but whether **every server the page loads files from** works over IPv6, at every layer of the connection: **DNS → TCP → TLS → HTTP**.

Course project for *Internet Engineering* (IIT Guwahati), Problem Statement 8.

> Only **7 of 30** popular websites worked completely over IPv6 when tested from a real IPv6 network, even though **20** of them have an AAAA record.

---

## Contents

- [Why this tool](#why-this-tool)
- [Key results](#key-results)
- [How it works](#how-it-works)
- [Repository layout](#repository-layout)
- [Installation](#installation)
- [Usage](#usage)
- [Validation (benchmark)](#validation-benchmark)
- [Output files](#output-files)
- [Verdicts and failure codes](#verdicts-and-failure-codes)
- [Limitations](#limitations)
- [Report and presentation](#report-and-presentation)

---

## Why this tool

The usual test for "IPv6 support" is one DNS question: *does the name have an AAAA record?* That misses two things:

1. **The address might not work.** A server can have an AAAA record but refuse IPv6 connections, present a wrong certificate, or redirect IPv6 users to an IPv4-only server.
2. **A page is not one server.** A homepage loads scripts, stylesheets, fonts, images and API calls from 1 to 300 different servers, mostly run by other companies. One IPv4-only script can break the page on an IPv6-only network.

This auditor tests **every server in the page's dependency graph** and reports **the exact layer where IPv6 fails**.

## Key results

Measured on 24 October 2026 from a Jio phone hotspot (dual-stack IPv6 with NAT64), 30 websites in 6 categories:

| Result | Value |
|---|---|
| Fully IPv6-ready | **7 / 30** (Google, YouTube, Wikipedia, Facebook, MIT, Income Tax, IIT Delhi) |
| Main page loads, but a script / stylesheet / API fails | 12 / 30 |
| Main page itself fails over IPv6 | 10 / 30 |
| Sites with an AAAA record that are still **not** fully ready | **13 of 20 (65%)** |
| Servers that fail over IPv6 | 444 of 922 (48%) |
| …of which third-party | **96%** |
| Servers with IPv6 that redirect to an IPv4-only server | 8 (e.g. `login.microsoftonline.com` → `login.live.com`) |
| Benchmark: seeded faults found at the correct layer | **9 / 9, 0 false alarms** |

A second run from the IIT Guwahati lab (IPv4-only network) confirmed the same 10 DNS-level failures; the other 20 sites could only be judged with real IPv6.

## How it works

```
 1. Load the page        2. Build the tree          3. Probe each server              4. Verdict + report
 headless Chrome   -->   who loaded what      -->   DNS -> TCP -> TLS -> HTTP   -->  compare IPv6 with IPv4,
 (Playwright, CDP)       (parent -> child)          once over IPv6, once over IPv4    write JSON / CSV / HTML
```

- **Step 1 – Load the page.** Chromium (via Playwright) opens the homepage once. The Chrome DevTools Protocol reports every request and its *initiator* (the HTML/CSS file or script that asked for it). Discovery runs on the normal network on purpose: over IPv6 only, IPv4-only files would never load and would never be seen.
- **Step 2 – Build the tree.** Requests are linked parent → child and marked first- or third-party.
- **Step 3 – Probe each server.** For every unique origin the probe runs the four layers in order, separately over IPv6 and IPv4, and stops at the first failure:
  1. **DNS** – our own DNS client asks for AAAA / A records (tells NODATA from NXDOMAIN, follows CNAMEs, detects NAT64 `64:ff9b::/96` addresses via RFC 7050).
  2. **TCP** – connect to up to 3 addresses.
  3. **TLS** – handshake with SNI and full certificate checks.
  4. **HTTP** – `GET` the first file seen from that server; a status ≥ 400, or a redirect to a host with no real AAAA record, is a failure.
- **Step 4 – Verdict.** Comparing IPv6 with IPv4 separates IPv6 problems from general ones (`BROKEN_BOTH`). Files inherit their server's verdict; children of a failing parent are marked *blocked*.

Fairness rules: a probe that times out is retried once; if the main server fails *identically* over IPv4 and IPv6 (e.g. a bot filter) but the browser loaded the page, the page is judged by its dependencies; if the measuring machine itself has no IPv6 route, results are `INCONCLUSIVE_NO_IPV6` instead of blaming the site.

More detail: [`docs/design.md`](docs/design.md).

## Repository layout

```
ipv6audit/            the auditor (Python package)
  dnswire.py          DNS client written from scratch (wire format, CNAME, NAT64 detection)
  probe.py            four-layer probe and verdict logic
  crawler.py          headless-browser capture and dependency tree
  auditor.py          orchestration, page verdict, summary
  report.py           JSON, CSV and interactive HTML reports
  bench.py            controlled benchmark site with seeded IPv6 faults
step1_dns_test.py     step-by-step scripts used to build and test the tool
step2_probe_test.py
step3_crawl_test.py
step4_audit.py
step5_validate.py     benchmark validation against ground truth
step6_batch.py        audit all sites in sites.csv
step6_analyze.py      statistics, tables, charts, run comparison
step6_inspect.py      details behind each IPv6-specific failure
sites.csv             the 30 websites audited
docs/                 design and benchmark documentation
results/              measurement results (lab, hostel, benchmark)
report/               project report (PDF) and presentation
```

## Installation

Python 3.10+ and about 400 MB for Chromium.

**Linux / macOS**
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt          # playwright, matplotlib
playwright install --with-deps chromium
```

**Windows (PowerShell)**
```powershell
py -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
playwright install chromium
```

Check the network first: `ping -6 google.com` must get replies for IPv6 results to be conclusive.

## Usage

| Task | Command |
|---|---|
| DNS layer only (A / AAAA, NAT64 check) | `python step1_dns_test.py` |
| Four-layer probe of some URLs | `python step2_probe_test.py https://www.google.com/ https://github.com/` |
| Dependency tree of one page | `python step3_crawl_test.py https://www.iitg.ac.in/` |
| Full audit of one page (all reports) | `python step4_audit.py https://www.iitg.ac.in/` |
| Audit all sites in `sites.csv` | `python step6_batch.py --label hostel --headed` |
| Redo some sites only | `python step6_batch.py --label hostel --headed --only "NDTV,IRCTC"` |
| Statistics and charts | `python step6_analyze.py hostel` |
| Compare two runs | `python step6_analyze.py lab-headed hostel` |
| Details of IPv6-specific failures | `python step6_inspect.py hostel` |

`--headed` opens a visible Chrome window, which many sites require (they block headless browsers). On a Linux machine without a screen use `xvfb-run -a python3 step6_batch.py … --headed`. A batch run is resumable: run the same command again and finished sites are skipped.

## Validation (benchmark)

`ipv6audit/bench.py` runs a fake domain `bench.test` on one machine: its own DNS server, its own certificates, and 12 HTTPS hosts that each have a working IPv4 listener (127.0.0.1) and an IPv6 listener (`::1`) that breaks in one specific way.

```bash
python3 -m ipv6audit.bench serve      # terminal 1, leave running
python3 step5_validate.py             # terminal 2
```

Result with the final code (Ubuntu, real IPv6 loopback):

```
Seeded issues detected at the correct layer: 9/9  (100%)
Healthy hosts wrongly flagged (false alarms): 0
```

Test cases: missing AAAA, CNAME to an IPv4-only name, API reached only through JavaScript, NAT64-only address, TCP refused, wrong certificate, HTTP 403 only over IPv6, redirect to an IPv4-only host, plus healthy controls and a host broken on both IPv4 and IPv6. Details: [`docs/benchmark.md`](docs/benchmark.md).

## Output files

Per site (`results/<label>/sites/`): `<site>.json` (everything), `<site>.resources.csv` (one row per file), `<site>.origins.csv` (one row per server, each layer over IPv6 and IPv4), `<site>.html` (interactive dependency graph; open in a browser).

Per run (`results/<label>/`): `summary.csv`, `site_table.csv`, `offenders.csv`, `stats.md`, `chart_page_verdicts.png`, `chart_origins_per_site.png`, `chart_failure_layers.png`, `run_info.json`. Comparison of runs: `results/comparison.md`.

## Verdicts and failure codes

| Server verdict | Meaning |
|---|---|
| `READY` | DNS, TCP, TLS and HTTP all pass over IPv6 |
| `IPV4_ONLY` | no AAAA record |
| `IPV4_ONLY_NAT64` | only a synthesized `64:ff9b::` address: really IPv4-only |
| `IPV6_TCP_FAIL` / `IPV6_TLS_FAIL` / `IPV6_HTTP_FAIL` | has AAAA, but fails at that layer over IPv6 |
| `BROKEN_BOTH` | fails over IPv4 too: not an IPv6 problem |
| `INCONCLUSIVE_NO_IPV6` | the measuring machine has no IPv6 route |

| Page verdict | Meaning |
|---|---|
| `FULLY_READY` | every file works over IPv6 |
| `DEGRADED_ON_IPV6` | only images, fonts or media fail |
| `BROKEN_ON_IPV6` | a script, stylesheet or API fails |
| `NOT_READY` | the main page itself fails over IPv6 |
| `UNREACHABLE` | the main page fails over IPv4 too |

Failure codes include `DNS_NO_AAAA`, `DNS_NXDOMAIN`, `DNS_ONLY_SYNTHESIZED_AAAA`, `TCP_REFUSED`, `TCP_TIMEOUT`, `TCP_UNREACHABLE`, `TLS_CERT_NAME_MISMATCH`, `TLS_CERT_UNTRUSTED`, `HTTP_403`, `HTTP_REDIRECT_TO_IPV4_ONLY` and more (see `ipv6audit/probe.py`).

## Limitations

- One vantage point per network; results depend on location (CDNs and split-horizon DNS).
- The IPv6 network used had NAT64; no browser test with IPv4 fully disabled was done.
- Third-party content changes on every visit; each site was loaded once per run.
- Homepage only (no login, scrolling or clicks), as required by the problem statement.
- First/third-party is decided by the registrable domain (e.g. `media-amazon.com` counts as third-party for `amazon.in`).
- Chrome reports some script-created images under the page rather than the script.

## Report and presentation

- Full project report: [`report/`](report/)
- Presentation slides: [`report/`](report/)

Author: [Your name], [Roll number], Department of CSE, IIT Guwahati.
