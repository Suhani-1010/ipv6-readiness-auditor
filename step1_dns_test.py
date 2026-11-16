"""Step 1: try the DNS layer by hand."""
from ipv6audit import dnswire

resolvers = dnswire.system_resolvers()
print("Using resolver(s):", resolvers)

hosts = ["google.com", "github.com", "wikipedia.org", "iitg.ac.in",
         "cloudflare.com", "facebook.com", "amazon.in",
         "stackoverflow.com", "irctc.co.in", "thisdoesnotexist12345.com"]

for host in hosts:
    aaaa = dnswire.resolve(host, dnswire.TYPE_AAAA, resolvers)
    a = dnswire.resolve(host, dnswire.TYPE_A, resolvers)
    print(f"\n{host}")
    print(f"  A    -> rcode={a.rcode:8} {a.addresses}  ({a.elapsed_ms:.0f} ms)")
    print(f"  AAAA -> rcode={aaaa.rcode:8} {aaaa.addresses}  ({aaaa.elapsed_ms:.0f} ms)")
    if aaaa.cname_chain:
        print(f"  CNAME chain: {' -> '.join(aaaa.cname_chain)}")
    if aaaa.rcode == "NXDOMAIN":
        print("  ==> NXDOMAIN: this name does not exist at all")
    elif aaaa.nodata and a.addresses:
        print("  ==> no AAAA record: this host is IPv4-only at the DNS layer")
    elif not aaaa.addresses and not a.addresses:
        print("  ==> no A and no AAAA: host has no address at all (not an IPv6 problem)")
    else:
        print("  ==> has AAAA (but this alone does NOT prove IPv6 works)")

print("\nNAT64 prefixes on this network:", dnswire.detect_nat64_prefixes(resolvers) or "none")
