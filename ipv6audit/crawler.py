"""Headless-browser dependency capture (initial page load only, no crawling).

We drive Chromium with Playwright and subscribe to Chrome DevTools Protocol
Network.requestWillBeSent events. Each event carries an `initiator`:
  * parser  -> the HTML/CSS document that referenced the resource (url)
  * script  -> a JS call stack; the top frame's script URL issued fetch/XHR/
               dynamic <script>/<img> insertion
  * preload / preflight / other
From these we build a directed tree: document -> subresource -> sub-subresource.

Discovery runs on whatever network the machine has (normally dual-stack), so
IPv4-only children are still *seen*; reachability is then tested separately
per address family by probe.py.
"""
from __future__ import annotations

import os
import time
from urllib.parse import urlsplit, urldefrag

from playwright.sync_api import sync_playwright


def _initiator_url(init: dict | None) -> str | None:
    if not init:
        return None
    if init.get("url"):
        return init["url"]
    stack = init.get("stack")
    while stack:
        for fr in stack.get("callFrames", []):
            if fr.get("url"):
                return fr["url"]
        stack = stack.get("parent")
    return None


def capture(url: str, timeout_s: float = 30.0, settle_s: float = 3.0,
            browser_args: list[str] | None = None, ignore_https_errors: bool = False,
            headless: bool = True) -> dict:
    """Load `url` once and return {'page': url, 'requests': [...], 'errors': [...]}."""
    reqs: dict[str, dict] = {}          # requestId -> record
    order: list[str] = []
    by_url_first: dict[str, str] = {}
    errors: list[str] = []

    launch_kw = {}
    if browser_args and "--no-proxy-server" in browser_args:
        # Chrome also reads proxy settings from environment variables; drop them too.
        launch_kw["env"] = {k: v for k, v in os.environ.items() if "proxy" not in k.lower()}
    with sync_playwright() as p:
        # Many sites block "HeadlessChrome". Present a normal desktop Chrome instead:
        # regular user-agent, common window size, Indian locale, no automation flag.
        args = list(browser_args or []) + ["--disable-blink-features=AutomationControlled"]
        browser = p.chromium.launch(headless=headless, args=args, **launch_kw)
        platform = "Windows NT 10.0; Win64; x64" if os.name == "nt" else "X11; Linux x86_64"
        major = browser.version.split(".")[0]
        ua = (f"Mozilla/5.0 ({platform}) AppleWebKit/537.36 (KHTML, like Gecko) "
              f"Chrome/{major}.0.0.0 Safari/537.36")
        ctx = browser.new_context(ignore_https_errors=ignore_https_errors, user_agent=ua,
                                  locale="en-IN", viewport={"width": 1366, "height": 768},
                                  service_workers="block")
        page = ctx.new_page()
        cdp = ctx.new_cdp_session(page)
        cdp.send("Network.enable")

        def on_will_send(ev):
            rid = ev["requestId"]
            req = ev["request"]
            u = urldefrag(req["url"])[0]
            if not u.startswith(("http://", "https://")):
                return
            if ev.get("redirectResponse") and rid in reqs:
                # Same requestId re-used for a redirect hop: parent is the previous hop.
                prev = reqs[rid]
                prev["redirected_to"] = u
                prev["status"] = ev["redirectResponse"].get("status")
                hop_id = f"{rid}#{len(order)}"
                reqs[hop_id] = prev
                order[order.index(rid)] = hop_id
                parent = prev["url"]
                kind = "redirect"
            else:
                parent = _initiator_url(ev.get("initiator"))
                kind = (ev.get("initiator") or {}).get("type", "other")
            reqs[rid] = {"id": rid, "url": u, "method": req.get("method"),
                         "resource_type": ev.get("type", "Other"), "initiator_type": kind,
                         "parent_url": parent, "frame_id": ev.get("frameId"),
                         "ts": ev.get("timestamp"), "status": None, "remote_ip": None,
                         "failed": None}
            order.append(rid)
            by_url_first.setdefault(u, rid)

        def on_response(ev):
            r = reqs.get(ev["requestId"])
            if r:
                resp = ev["response"]
                r["status"] = resp.get("status")
                r["remote_ip"] = resp.get("remoteIPAddress")
                r["protocol"] = resp.get("protocol")
                r["mime"] = resp.get("mimeType")

        def on_failed(ev):
            r = reqs.get(ev["requestId"])
            if r:
                r["failed"] = ev.get("errorText") or "failed"

        cdp.on("Network.requestWillBeSent", on_will_send)
        cdp.on("Network.responseReceived", on_response)
        cdp.on("Network.loadingFailed", on_failed)
        # Requests from out-of-process iframes are invisible to this CDP
        # session; catch them through Playwright and attach to their frame.
        seen_pw: list[tuple[str, str | None, str]] = []
        page.on("request", lambda r: seen_pw.append(
            (urldefrag(r.url)[0], r.frame.url if r.frame else None, r.resource_type)))

        t0 = time.time()
        try:
            page.goto(url, wait_until="load", timeout=timeout_s * 1000)
            try:
                page.wait_for_load_state("networkidle", timeout=max(1000, (timeout_s - (time.time() - t0)) * 1000))
            except Exception:  # noqa: BLE001  long-polling pages never go idle
                pass
            page.wait_for_timeout(settle_s * 1000)
        except Exception as exc:  # noqa: BLE001
            errors.append(f"navigation: {type(exc).__name__}: {exc}".splitlines()[0])
        final_url = page.url
        cdp_urls = {r["url"] for r in reqs.values()}
        extra = []
        for u, frame_url, rtype in seen_pw:
            if u.startswith(("http://", "https://")) and u not in cdp_urls:
                cdp_urls.add(u)
                extra.append({"id": f"pw-{len(extra)}", "url": u, "method": "GET",
                              "resource_type": rtype, "initiator_type": "frame",
                              "parent_url": frame_url, "status": None, "failed": None})
        browser.close()

    records = [reqs[i] for i in order] + extra
    return {"page": url, "final_url": final_url, "requests": records,
            "errors": errors, "load_seconds": round(time.time() - t0, 2)}


def build_tree(cap: dict) -> dict:
    """Collapse requests to unique URLs and wire parent->child edges.

    Returns {'root': url, 'nodes': {url: {...}}, 'edges': [[parent, child], ...]}
    Unknown parents fall back to the root document.
    """
    reqs = cap["requests"]
    if not reqs:
        return {"root": cap["page"], "nodes": {cap["page"]: {"url": cap["page"], "resource_type": "Document",
                                                            "depth": 0}}, "edges": []}
    root = reqs[0]["url"]
    nodes: dict[str, dict] = {}
    for r in reqs:
        n = nodes.setdefault(r["url"], {"url": r["url"], "resource_type": r["resource_type"],
                                         "initiator_type": r["initiator_type"], "parent": None,
                                         "status": r.get("status"), "browser_error": r.get("failed"),
                                         "remote_ip": r.get("remote_ip"), "count": 0})
        n["count"] += 1
        if n["status"] is None and r.get("status") is not None:
            n["status"] = r["status"]
        if r.get("failed") and not n["browser_error"]:
            n["browser_error"] = r["failed"]
        if n["parent"] is None and r["url"] != root:
            p = r.get("parent_url")
            n["parent"] = p if p in nodes and p != r["url"] else root
    # break any cycles defensively and compute depth
    for url, n in nodes.items():
        seen, cur, depth = {url}, n, 0
        while cur["parent"]:
            if cur["parent"] in seen:
                cur["parent"] = root
                break
            seen.add(cur["parent"])
            cur = nodes[cur["parent"]]
            depth += 1
        n["depth"] = depth
    edges = [[n["parent"], u] for u, n in nodes.items() if n["parent"]]
    for u, n in nodes.items():
        sp = urlsplit(u)
        n["host"] = sp.hostname
        n["origin"] = f"{sp.scheme}://{sp.hostname}:{sp.port or (443 if sp.scheme == 'https' else 80)}"
        n["third_party"] = _site(sp.hostname) != _site(urlsplit(root).hostname)
    return {"root": root, "nodes": nodes, "edges": edges}


def _site(host: str | None) -> str:
    """Rough eTLD+1 (good enough for first/third-party labelling)."""
    if not host:
        return ""
    parts = host.split(".")
    two_level = {"co.uk", "ac.in", "co.in", "gov.in", "org.in", "net.in", "nic.in", "com.au", "co.jp", "com.br"}
    if len(parts) >= 3 and ".".join(parts[-2:]) in two_level:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])
