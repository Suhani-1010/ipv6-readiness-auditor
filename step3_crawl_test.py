"""Step 3: open a page in headless Chrome and print its dependency tree.

Run (inside the venv):  python3 step3_crawl_test.py https://www.wikipedia.org/
"""
import sys
from collections import Counter

from ipv6audit import crawler

url = sys.argv[1] if len(sys.argv) > 1 else "https://www.wikipedia.org/"
print(f"Loading {url} in headless Chrome ...")

cap = crawler.capture(url, timeout_s=30, settle_s=3)
tree = crawler.build_tree(cap)
nodes = tree["nodes"]

print(f"Page loaded in {cap['load_seconds']} s, {len(cap['requests'])} network requests, "
      f"{len(nodes)} unique URLs")
if cap["errors"]:
    print("Errors:", cap["errors"])

# children lookup: parent url -> list of child urls
kids = {}
for parent, child in tree["edges"]:
    kids.setdefault(parent, []).append(child)


def show(u, indent=0):
    n = nodes[u]
    tag = "3rd-party" if n["third_party"] else "1st-party"
    short = u if len(u) < 90 else u[:87] + "..."
    print(f"{'    ' * indent}[{n['resource_type']:<10}] {tag:<9} {short}")
    for k in sorted(kids.get(u, [])):
        show(k, indent + 1)


print("\nDependency tree (parent -> what it loaded):\n")
show(tree["root"])

hosts = Counter(n["host"] for n in nodes.values())
print(f"\n{len(hosts)} unique hosts (each one will be probed over IPv6 in the next step):")
for h, c in hosts.most_common():
    print(f"  {c:3}  {h}")
