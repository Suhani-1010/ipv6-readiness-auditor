# IPv6 readiness: run `hostel`

- Vantage point: **dual-stack + DNS64/NAT64** (IPv6 route: True, NAT64 prefixes: ['64:ff9b::/96'])
- Run time (UTC): 2026-10-24T10:13:21+00:00 to 2026-10-24T10:17:06+00:00
- Sites audited: **30 of 30**

## 1. Page-level verdicts

| Verdict | Sites | Share | Meaning |
|---|---|---|---|
| FULLY_READY | 7 | 23% | every resource works over IPv6 |
| DEGRADED_ON_IPV6 | 1 | 3% | only images/fonts/media fail |
| BROKEN_ON_IPV6 | 12 | 40% | a script, stylesheet or API fails |
| NOT_READY | 10 | 33% | the page itself fails over IPv6 |

## 2. AAAA record vs real readiness

- Sites whose main host has an AAAA record: **20 / 30** (67%)
- ...of those, NOT fully IPv6-ready: **13** (13 definite, 0 inconclusive)
- An AAAA check alone would have called all of these sites ready.

Sites with AAAA that still fail on IPv6: Microsoft (BROKEN_ON_IPV6), LinkedIn (BROKEN_ON_IPV6), India.gov.in (BROKEN_ON_IPV6), DigiLocker (BROKEN_ON_IPV6), IRCTC (BROKEN_ON_IPV6), SBI (DEGRADED_ON_IPV6), HDFC Bank (BROKEN_ON_IPV6), PhonePe (BROKEN_ON_IPV6), Amazon India (BROKEN_ON_IPV6), Myntra (BROKEN_ON_IPV6), Times of India (BROKEN_ON_IPV6), NDTV (BROKEN_ON_IPV6), JioHotstar (BROKEN_ON_IPV6)

## 3. IPv4 dependency leakage

- Unique (site, origin) pairs probed: **922**
- Failing over IPv6: **444** (48%), of which third-party: **425** (96%), first-party: 19
- Sites depending on at least one IPv4-only host: **23 / 30**
- Sites where a *critical* resource (script/stylesheet/API) fails on IPv6: **22 / 30**
- Inconclusive origins (no IPv6 route here): 0
- Timed-out probes retried once: 13 (0 succeeded on retry and are not counted as failures)

### Failing origins by layer

| Layer | Origins | Share of failures |
|---|---|---|
| DNS | 436 | 98% |
| TCP | 0 | 0% |
| TLS | 0 | 0% |
| HTTP | 8 | 2% |

### Origin verdicts (all sites together)

| Verdict | Origins |
|---|---|
| IPV4_ONLY_NAT64 | 436 |
| READY | 377 |
| BROKEN_BOTH | 101 |
| IPV6_HTTP_FAIL | 8 |

## 4. By category

| Category | Sites | Root has AAAA | Fully ready | Avg origins/site | IPv4-only origins |
|---|---|---|---|---|---|
| Global tech | 7 | 6 | 4 | 11.1 | 19 |
| Education | 6 | 2 | 2 | 6.2 | 5 |
| Government | 5 | 4 | 1 | 9.0 | 10 |
| Banking & payments | 4 | 3 | 0 | 15.8 | 20 |
| E-commerce | 4 | 2 | 0 | 23.8 | 47 |
| News & media | 4 | 3 | 0 | 151.0 | 335 |

## 5. Most common failing hosts (shared dependencies)

| Host | Verdict | Sites affected |
|---|---|---|
| dpm.demdex.net | IPV4_ONLY_NAT64 (DNS_ONLY_SYNTHESIZED_AAAA) | 6 |
| cm.g.doubleclick.net | IPV4_ONLY_NAT64 (DNS_ONLY_SYNTHESIZED_AAAA) | 5 |
| ib.adnxs.com | IPV4_ONLY_NAT64 (DNS_ONLY_SYNTHESIZED_AAAA) | 4 |
| pixel.tapad.com | IPV4_ONLY_NAT64 (DNS_ONLY_SYNTHESIZED_AAAA) | 4 |
| ps.eyeota.net | IPV4_ONLY_NAT64 (DNS_ONLY_SYNTHESIZED_AAAA) | 4 |
| aa.agkn.com | IPV4_ONLY_NAT64 (DNS_ONLY_SYNTHESIZED_AAAA) | 3 |
| bam.nr-data.net | IPV4_ONLY_NAT64 (DNS_ONLY_SYNTHESIZED_AAAA) | 3 |
| c.amazon-adsystem.com | IPV4_ONLY_NAT64 (DNS_ONLY_SYNTHESIZED_AAAA) | 3 |
| config.aps.amazon-adsystem.com | IPV4_ONLY_NAT64 (DNS_ONLY_SYNTHESIZED_AAAA) | 3 |
| crb.kargo.com | IPV4_ONLY_NAT64 (DNS_ONLY_SYNTHESIZED_AAAA) | 3 |
| image2.pubmatic.com | IPV4_ONLY_NAT64 (DNS_ONLY_SYNTHESIZED_AAAA) | 3 |
| image4.pubmatic.com | IPV4_ONLY_NAT64 (DNS_ONLY_SYNTHESIZED_AAAA) | 3 |
| jadserve.postrelease.com | IPV4_ONLY_NAT64 (DNS_ONLY_SYNTHESIZED_AAAA) | 3 |
| lb.eu-1-id5-sync.com | IPV4_ONLY_NAT64 (DNS_ONLY_SYNTHESIZED_AAAA) | 3 |
| match.adsrvr.org | IPV4_ONLY_NAT64 (DNS_ONLY_SYNTHESIZED_AAAA) | 3 |

## 6. Per-site results

| Site | Category | Page verdict | Root AAAA | Origins | IPv4-only | AAAA-but-broken | Inconclusive |
|---|---|---|---|---|---|---|---|
| Google | Global tech | FULLY_READY | True | 6 | 0 | 0 | 0 |
| YouTube | Global tech | FULLY_READY | True | 12 | 0 | 0 | 0 |
| Wikipedia | Global tech | FULLY_READY | True | 1 | 0 | 0 | 0 |
| Facebook | Global tech | FULLY_READY | True | 3 | 0 | 0 | 0 |
| Microsoft | Global tech | BROKEN_ON_IPV6 | True | 34 | 11 | 1 | 0 |
| GitHub | Global tech | NOT_READY | False | 4 | 1 | 0 | 0 |
| LinkedIn | Global tech | BROKEN_ON_IPV6 | True | 18 | 7 | 1 | 0 |
| IIT Guwahati | Education | NOT_READY | False | 9 | 1 | 0 | 0 |
| IIT Bombay | Education | NOT_READY | False | 5 | 1 | 0 | 0 |
| IIT Madras | Education | NOT_READY | False | 4 | 1 | 0 | 0 |
| IIT Delhi | Education | FULLY_READY | True | 3 | 0 | 0 | 0 |
| NPTEL | Education | NOT_READY | False | 12 | 2 | 0 | 0 |
| MIT | Education | FULLY_READY | True | 4 | 0 | 0 | 0 |
| India.gov.in | Government | BROKEN_ON_IPV6 | True | 13 | 2 | 0 | 0 |
| UIDAI (Aadhaar) | Government | NOT_READY | False | 6 | 4 | 0 | 0 |
| Income Tax | Government | FULLY_READY | True | 5 | 0 | 0 | 0 |
| DigiLocker | Government | BROKEN_ON_IPV6 | True | 8 | 3 | 0 | 0 |
| IRCTC | Government | BROKEN_ON_IPV6 | True | 13 | 1 | 0 | 0 |
| SBI | Banking & payments | DEGRADED_ON_IPV6 | True | 3 | 1 | 0 | 0 |
| HDFC Bank | Banking & payments | BROKEN_ON_IPV6 | True | 26 | 13 | 0 | 0 |
| Paytm | Banking & payments | NOT_READY | False | 19 | 2 | 0 | 0 |
| PhonePe | Banking & payments | BROKEN_ON_IPV6 | True | 15 | 4 | 0 | 0 |
| Amazon India | E-commerce | BROKEN_ON_IPV6 | True | 50 | 33 | 0 | 0 |
| Flipkart | E-commerce | NOT_READY | False | 8 | 4 | 0 | 0 |
| Myntra | E-commerce | BROKEN_ON_IPV6 | True | 22 | 5 | 0 | 0 |
| Swiggy | E-commerce | NOT_READY | False | 15 | 5 | 0 | 0 |
| Times of India | News & media | BROKEN_ON_IPV6 | True | 234 | 136 | 4 | 0 |
| NDTV | News & media | BROKEN_ON_IPV6 | True | 281 | 168 | 2 | 0 |
| BBC | News & media | NOT_READY | False | 60 | 23 | 0 | 0 |
| JioHotstar | News & media | BROKEN_ON_IPV6 | True | 29 | 8 | 0 | 0 |
