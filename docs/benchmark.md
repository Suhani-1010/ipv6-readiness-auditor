# Benchmark: a test website with known faults

The benchmark proves the auditor is correct: it is a website where the right answer for every server is known in advance.

## How it is built (`ipv6audit/bench.py`)

- **Fake zone `bench.test`.** A small authoritative DNS server on `127.0.0.1:5354` answers only for `*.bench.test`. It decides which names get an AAAA record, returns a CNAME for one, and a NAT64-looking address (`64:ff9b::7f00:1`) for another.
- **Two listeners per host.** Every test host has its own port. The IPv4 listener on `127.0.0.1` always works, so the browser can discover every file. The IPv6 listener on `::1` misbehaves in the way the test case requires (or does not exist).
- **Own certificates.** Made with `openssl` on first run: a test CA, a certificate for `*.bench.test`, and one for `wrong.example` used by the TLS case. The probe trusts the test CA; Chrome is told to accept the certificates during discovery.
- **Ground truth.** `bench/state.json` records the expected verdict, layer and failure code for every host.
- **Page.** `www.bench.test` loads stylesheets and scripts from the other hosts; `style.css` loads a font, and `app.js` calls two APIs, so nested (CSS- and JavaScript-initiated) dependencies are tested too.
- If the machine has no IPv6 stack, the IPv6 listeners run on a stand-in loopback address (`127.0.6.1`, a "lab shim"); on a normal Linux or Windows machine the real `::1` is used.

## Test cases

| Host | Port | IPv6 behaviour | Expected verdict | Layer | Code |
|---|---|---|---|---|---|
| www | 8440 | healthy (root page) | READY | – | – |
| static | 8441 | healthy | READY | – | – |
| fonts | 8442 | healthy (loaded from CSS) | READY | – | – |
| v4only | 8443 | no AAAA record | IPV4_ONLY | DNS | DNS_NO_AAAA |
| cdn | 8444 | CNAME to an IPv4-only name | IPV4_ONLY | DNS | DNS_NO_AAAA |
| tcpdrop | 8445 | AAAA, nothing listens on IPv6 | IPV6_TCP_FAIL | TCP | TCP_REFUSED |
| tlsbad | 8446 | certificate for the wrong name | IPV6_TLS_FAIL | TLS | TLS_CERT_NAME_MISMATCH |
| forbid6 | 8447 | 403 only over IPv6 (called by JS) | IPV6_HTTP_FAIL | HTTP | HTTP_403 |
| redir6 | 8448 | 302 to an IPv4-only host over IPv6 | IPV6_HTTP_FAIL | HTTP | HTTP_REDIRECT_TO_IPV4_ONLY |
| api-v4 | 8449 | no AAAA (called by JS) | IPV4_ONLY | DNS | DNS_NO_AAAA |
| broken-both | 8450 | 500 on IPv4 and IPv6 (control) | BROKEN_BOTH | HTTP | HTTP_500 |
| synth | 8451 | only a NAT64-synthesized AAAA | IPV4_ONLY_NAT64 | DNS | DNS_ONLY_SYNTHESIZED_AAAA |

## Running it

```bash
python3 -m ipv6audit.bench serve      # terminal 1
python3 step5_validate.py             # terminal 2
```

## Result (final code, Ubuntu 24.04, real `::1`)

```
origin                               expected verdict  layer code                        result
https://www.bench.test:8440          READY             -     -                           PASS
https://static.bench.test:8441       READY             -     -                           PASS
https://fonts.bench.test:8442        READY             -     -                           PASS
https://v4only.bench.test:8443       IPV4_ONLY         dns   DNS_NO_AAAA                 PASS
https://cdn.bench.test:8444          IPV4_ONLY         dns   DNS_NO_AAAA                 PASS
https://tcpdrop.bench.test:8445      IPV6_TCP_FAIL     tcp   TCP_REFUSED                 PASS
https://tlsbad.bench.test:8446       IPV6_TLS_FAIL     tls   TLS_CERT_NAME_MISMATCH      PASS
https://forbid6.bench.test:8447      IPV6_HTTP_FAIL    http  HTTP_403                    PASS
https://redir6.bench.test:8448       IPV6_HTTP_FAIL    http  HTTP_REDIRECT_TO_IPV4_ONLY  PASS
https://api-v4.bench.test:8449       IPV4_ONLY         dns   DNS_NO_AAAA                 PASS
https://broken-both.bench.test:8450  BROKEN_BOTH       http  HTTP_500                    PASS
https://synth.bench.test:8451        IPV4_ONLY_NAT64   dns   DNS_ONLY_SYNTHESIZED_AAAA   PASS

Seeded issues detected at the correct layer: 9/9  (100%)
Healthy hosts wrongly flagged (false alarms): 0
Page verdict: BROKEN_ON_IPV6
```

The server's own request log agrees: `forbid6` answered 200 over IPv4 and 403 over IPv6; `redir6` answered 302 only over IPv6; `tlsbad` logged the auditor rejecting its certificate; `v4only`, `cdn`, `api-v4`, `synth` and `tcpdrop` received no IPv6 HTTP request at all, because the auditor stopped at DNS or TCP.
