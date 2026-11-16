# Design

This document explains how the auditor is built: the data flow, each module, and the decisions behind it.

## Data flow

```
sites.csv ─► step6_batch.py ─► auditor.audit(url)
                                   │
                                   ├─ crawler.capture()      Chromium + CDP: every request + initiator
                                   ├─ crawler.build_tree()   unique URLs, parent → child, 1st/3rd party
                                   ├─ probe.probe_endpoint() one per origin, 16 in parallel
                                   │     ├─ probe_family(…, 6)   DNS → TCP → TLS → HTTP over IPv6
                                   │     ├─ probe_family(…, 4)   the same over IPv4
                                   │     └─ verdict(v6, v4)
                                   ├─ copy verdicts onto files, mark blocked children
                                   └─ summarize()            page verdict + counts
                               ─► report.write_all()         JSON, 2 CSVs, HTML graph
                               ─► summary.csv ─► step6_analyze.py ─► stats.md, charts, comparison.md
```

## Modules

### `dnswire.py` – DNS client
- Builds DNS queries byte by byte (RFC 1035), sends them over UDP, falls back to TCP when the answer is truncated, and decodes answers including name compression.
- Follows CNAME chains inside the answer and, if needed, with a new query.
- Returns the exact outcome: `NOERROR` with addresses, `NOERROR` with none (**NODATA**, the "no AAAA" signal), `NXDOMAIN`, `SERVFAIL`, `TIMEOUT`.
- Finds the system's resolvers from `/etc/resolv.conf` (Linux) or PowerShell `Get-DnsClientServerAddress` (Windows).
- **NAT64 detection** (RFC 7050): queries `ipv4only.arpa` AAAA; a DNS64 resolver answers with the well-known addresses 192.0.0.170/171 embedded in its prefix, which reveals the NAT64 prefix. Addresses inside that prefix or the well-known `64:ff9b::/96` are *synthesized*.

Why not `socket.getaddrinfo()`? It hides why a lookup failed and mixes A and AAAA results; the audit needs the exact AAAA outcome.

### `probe.py` – four-layer probe
`probe_family(scheme, host, port, path, family, cfg)` runs, for one IP version:

| Layer | Action | Failure codes |
|---|---|---|
| DNS | AAAA (IPv6) or A (IPv4) via `dnswire` | `DNS_NO_AAAA`, `DNS_NXDOMAIN`, `DNS_SERVFAIL`, `DNS_TIMEOUT` |
| TCP | connect to up to 3 addresses | `TCP_REFUSED`, `TCP_TIMEOUT`, `TCP_UNREACHABLE`, `TCP_NO_IPV6_STACK` |
| TLS | wrap the same socket, SNI + full verification | `TLS_CERT_NAME_MISMATCH`, `TLS_CERT_UNTRUSTED`, `TLS_CERT_EXPIRED`, `TLS_HANDSHAKE_FAILURE`, `TLS_TIMEOUT` |
| HTTP | `GET <path> HTTP/1.1`, read the status line | `HTTP_<status>`, `HTTP_REDIRECT_TO_IPV4_ONLY`, `HTTP_TIMEOUT`, `HTTP_MALFORMED` |

`verdict(v6, v4)` combines both families:
- IPv6 passes everything → `READY` (or `IPV4_ONLY_NAT64` if all its addresses are synthesized).
- IPv4 fails at the same or an earlier layer → `BROKEN_BOTH` (not an IPv6 problem).
- DNS failure → `IPV4_ONLY`; TCP / TLS / HTTP failure → `IPV6_TCP_FAIL` / `IPV6_TLS_FAIL` / `IPV6_HTTP_FAIL`.
- `TCP_UNREACHABLE` while the measuring machine has no IPv6 default route → `INCONCLUSIVE_NO_IPV6`.

`probe_endpoint(url)` probes both families and retries a timed-out family once; only a repeated timeout counts. The probe identifies itself as desktop Chrome, because some bot filters reject unknown clients on both IPv4 and IPv6.

### `crawler.py` – dependency capture
- Launches Chromium through Playwright with a normal Chrome user-agent, Indian locale, 1366×768 window and the automation flag disabled (many sites block headless browsers); `--headed` gives a visible window.
- Listens to CDP `Network.requestWillBeSent`, `responseReceived` and `loadingFailed`. The initiator gives the parent: a parser initiator's URL (HTML or CSS) or the first URL in a script initiator's stack. Redirect hops become parent → child.
- Requests from out-of-process iframes are caught through Playwright's `request` event and attached to their frame.
- Waits for `load`, then network idle (bounded), then a settle time. Only the initial page load is captured.

### `auditor.py` – orchestration
- Probes each unique origin once (16 in parallel), using the first URL seen from it.
- A file is *critical* if it is a document, script, stylesheet, fetch or XHR.
- Page verdict: `NOT_READY` if the root fails over IPv6; `BROKEN_ON_IPV6` if a critical file fails; `DEGRADED_ON_IPV6` if only non-critical files fail; `FULLY_READY` otherwise; `UNREACHABLE` if the root fails over IPv4 too.
- If the root fails identically over IPv4 and IPv6 at TLS or HTTP while the browser loaded the page, IPv6 behaves like IPv4, so the page is judged by its dependencies.
- `detect_pathway()` labels the vantage point: IPv4-only, dual-stack, dual-stack + DNS64/NAT64, IPv6-only.

### `report.py` – outputs
JSON (everything), `resources.csv`, `origins.csv` and a self-contained HTML page with a collapsible dependency tree, an "IPv6 problems only" filter and a per-origin layer ladder for IPv6 and IPv4.

### Analysis scripts
- `step6_batch.py` audits `sites.csv`, writes `summary.csv` after every site (resumable), warns about blocked or empty pages.
- `step6_analyze.py` computes page-verdict counts, AAAA-vs-readiness, dependency leakage, third-party share, failures by layer, per-category tables, the most common failing hosts, charts and run comparisons.
- `step6_inspect.py` prints every IPv6-specific failure with both families' layer results, retried timeouts, and identical-on-both cases.

## Key design decisions

| Decision | Reason |
|---|---|
| Own DNS client | Exact NODATA / NXDOMAIN / SERVFAIL outcome and NAT64 detection |
| Discover over the normal network, test over IPv6 separately | IPv4-only dependencies would be invisible to an IPv6-only crawl |
| Always probe IPv4 too | Separate IPv6 problems from servers broken for everyone |
| Stop at the first failing layer | The failing layer tells the owner what to fix |
| Probe per origin, not per URL | Hundreds of files per page; servers are what support IPv6 or not |
| Retry timeouts once | A momentary mobile-network stall is not a property of the server |
| Inconclusive verdict | A network without IPv6 must not blame the website |
