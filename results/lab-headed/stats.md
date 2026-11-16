# IPv6 readiness: run `lab-headed`

- Vantage point: **ipv4-only** (IPv6 route: False, NAT64 prefixes: none)
- Run time (UTC): 2026-10-19T05:33:23+00:00 to 2026-10-19T05:46:15+00:00
- Sites audited: **30 of 30**

> This vantage point has **no IPv6 route**. DNS-layer results (missing AAAA) are definite;
> TCP/TLS/HTTP results for hosts that do have AAAA are INCONCLUSIVE and must be re-measured
> from an IPv6-capable network.

## 1. Page-level verdicts

| Verdict | Sites | Share | Meaning |
|---|---|---|---|
| NOT_READY | 10 | 33% | the page itself fails over IPv6 |
| INCONCLUSIVE_NO_IPV6 | 20 | 67% | cannot judge: no IPv6 route at this vantage |

## 2. AAAA record vs real readiness

- Sites whose main host has an AAAA record: **20 / 30** (67%)
- ...of those, NOT fully IPv6-ready: **20** (0 definite, 20 inconclusive)
- An AAAA check alone would have called all of these sites ready.

## 3. IPv4 dependency leakage

- Unique (site, origin) pairs probed: **1071**
- Failing over IPv6: **617** (58%), of which third-party: **588** (95%), first-party: 29
- Sites depending on at least one IPv4-only host: **24 / 30**
- Sites where a *critical* resource (script/stylesheet/API) fails on IPv6: **23 / 30**
- Inconclusive origins (no IPv6 route here): 447
- Timed-out probes retried once: 0 (0 succeeded on retry and are not counted as failures)

### Failing origins by layer

| Layer | Origins | Share of failures |
|---|---|---|
| DNS | 617 | 100% |
| TCP | 0 | 0% |
| TLS | 0 | 0% |
| HTTP | 0 | 0% |

### Origin verdicts (all sites together)

| Verdict | Origins |
|---|---|
| IPV4_ONLY | 617 |
| INCONCLUSIVE_NO_IPV6 | 447 |
| BROKEN_BOTH | 6 |
| READY | 1 |

## 4. By category

| Category | Sites | Root has AAAA | Fully ready | Avg origins/site | IPv4-only origins |
|---|---|---|---|---|---|
| Global tech | 7 | 6 | 0 | 10.7 | 25 |
| Education | 6 | 2 | 0 | 7.3 | 5 |
| Government | 5 | 4 | 0 | 8.8 | 10 |
| Banking & payments | 4 | 3 | 0 | 17.5 | 28 |
| E-commerce | 4 | 2 | 0 | 23.0 | 57 |
| News & media | 4 | 3 | 0 | 186.5 | 492 |

## 5. Most common failing hosts (shared dependencies)

| Host | Verdict | Sites affected |
|---|---|---|
| ad.doubleclick.net | IPV4_ONLY (DNS_NO_AAAA) | 7 |
| dpm.demdex.net | IPV4_ONLY (DNS_NO_AAAA) | 7 |
| cm.g.doubleclick.net | IPV4_ONLY (DNS_NO_AAAA) | 5 |
| csync.loopme.me | IPV4_ONLY (DNS_NO_AAAA) | 4 |
| eb2.3lift.com | IPV4_ONLY (DNS_NO_AAAA) | 4 |
| ib.adnxs.com | IPV4_ONLY (DNS_NO_AAAA) | 4 |
| id5-sync.com | IPV4_ONLY (DNS_NO_AAAA) | 4 |
| image2.pubmatic.com | IPV4_ONLY (DNS_NO_AAAA) | 4 |
| image4.pubmatic.com | IPV4_ONLY (DNS_NO_AAAA) | 4 |
| pixel.rubiconproject.com | IPV4_ONLY (DNS_NO_AAAA) | 4 |
| pixel.tapad.com | IPV4_ONLY (DNS_NO_AAAA) | 4 |
| ps.eyeota.net | IPV4_ONLY (DNS_NO_AAAA) | 4 |
| us-u.openx.net | IPV4_ONLY (DNS_NO_AAAA) | 4 |
| x.bidswitch.net | IPV4_ONLY (DNS_NO_AAAA) | 4 |
| aa.agkn.com | IPV4_ONLY (DNS_NO_AAAA) | 3 |

## 6. Per-site results

| Site | Category | Page verdict | Root AAAA | Origins | IPv4-only | AAAA-but-broken | Inconclusive |
|---|---|---|---|---|---|---|---|
| Google | Global tech | INCONCLUSIVE_NO_IPV6 | True | 6 | 0 | 0 | 6 |
| YouTube | Global tech | INCONCLUSIVE_NO_IPV6 | True | 12 | 1 | 0 | 11 |
| Wikipedia | Global tech | INCONCLUSIVE_NO_IPV6 | True | 1 | 0 | 0 | 1 |
| Facebook | Global tech | INCONCLUSIVE_NO_IPV6 | True | 3 | 0 | 0 | 3 |
| Microsoft | Global tech | INCONCLUSIVE_NO_IPV6 | True | 33 | 14 | 0 | 19 |
| GitHub | Global tech | NOT_READY | False | 3 | 2 | 0 | 1 |
| LinkedIn | Global tech | INCONCLUSIVE_NO_IPV6 | True | 17 | 8 | 0 | 9 |
| IIT Guwahati | Education | NOT_READY | False | 9 | 1 | 0 | 8 |
| IIT Bombay | Education | NOT_READY | False | 5 | 1 | 0 | 4 |
| IIT Madras | Education | NOT_READY | False | 11 | 1 | 0 | 10 |
| IIT Delhi | Education | INCONCLUSIVE_NO_IPV6 | True | 3 | 0 | 0 | 3 |
| NPTEL | Education | NOT_READY | False | 12 | 2 | 0 | 10 |
| MIT | Education | INCONCLUSIVE_NO_IPV6 | True | 4 | 0 | 0 | 4 |
| India.gov.in | Government | INCONCLUSIVE_NO_IPV6 | True | 13 | 3 | 0 | 10 |
| UIDAI (Aadhaar) | Government | NOT_READY | False | 5 | 3 | 0 | 2 |
| Income Tax | Government | INCONCLUSIVE_NO_IPV6 | True | 5 | 0 | 0 | 5 |
| DigiLocker | Government | INCONCLUSIVE_NO_IPV6 | True | 8 | 3 | 0 | 5 |
| IRCTC | Government | INCONCLUSIVE_NO_IPV6 | True | 13 | 1 | 0 | 12 |
| SBI | Banking & payments | INCONCLUSIVE_NO_IPV6 | True | 3 | 1 | 0 | 2 |
| HDFC Bank | Banking & payments | INCONCLUSIVE_NO_IPV6 | True | 33 | 17 | 0 | 16 |
| Paytm | Banking & payments | NOT_READY | False | 19 | 5 | 0 | 14 |
| PhonePe | Banking & payments | INCONCLUSIVE_NO_IPV6 | True | 15 | 5 | 0 | 10 |
| Amazon India | E-commerce | INCONCLUSIVE_NO_IPV6 | True | 47 | 37 | 0 | 9 |
| Flipkart | E-commerce | NOT_READY | False | 8 | 6 | 0 | 1 |
| Myntra | E-commerce | INCONCLUSIVE_NO_IPV6 | True | 22 | 6 | 0 | 16 |
| Swiggy | E-commerce | NOT_READY | False | 15 | 8 | 0 | 7 |
| Times of India | News & media | INCONCLUSIVE_NO_IPV6 | True | 261 | 172 | 0 | 87 |
| NDTV | News & media | INCONCLUSIVE_NO_IPV6 | True | 323 | 223 | 0 | 97 |
| BBC | News & media | NOT_READY | False | 132 | 90 | 0 | 42 |
| JioHotstar | News & media | INCONCLUSIVE_NO_IPV6 | True | 30 | 7 | 0 | 23 |
