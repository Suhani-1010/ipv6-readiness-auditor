"""Machine-readable (JSON/CSV) and visual (HTML) reports."""
from __future__ import annotations

import csv
import html
import json
import os
import re

RESOURCE_FIELDS = ["page", "url", "host", "origin", "resource_type", "initiator_type", "depth",
                   "parent", "third_party", "critical", "verdict", "failed_stage", "failure_code",
                   "blocked_by", "browser_status", "browser_error"]
ORIGIN_FIELDS = ["page", "origin", "host", "verdict", "failed_stage", "failure_code",
                 "v6_dns_rcode", "v6_addresses", "v6_synthesized", "v6_tcp", "v6_tls", "v6_http_status",
                 "v6_failure_code", "v4_addresses", "v4_failure_code", "v4_http_status", "probe_url"]


def slug(url: str) -> str:
    return re.sub(r"[^A-Za-z0-9]+", "_", re.sub(r"^https?://", "", url)).strip("_")[:80]


def resource_rows(a: dict):
    for u, n in a["resources"].items():
        yield {"page": a["page"], "url": u, "host": n["host"], "origin": n["origin"],
               "resource_type": n["resource_type"], "initiator_type": n.get("initiator_type"),
               "depth": n["depth"], "parent": n.get("parent") or "", "third_party": n["third_party"],
               "critical": n["critical"], "verdict": n["verdict"], "failed_stage": n["failed_stage"] or "",
               "failure_code": n["failure_code"] or "", "blocked_by": n.get("blocked_by") or "",
               "browser_status": n.get("status") or "", "browser_error": n.get("browser_error") or ""}


def _stage_mark(fam: dict, stage: str) -> str:
    s = fam.get(stage) or {}
    if fam.get("failed_stage") == stage:
        return "FAIL"
    if s.get("ok"):
        return "ok"
    return "-"


def origin_rows(a: dict):
    for o in a["origins"].values():
        v6, v4 = o["ipv6"], o["ipv4"]
        yield {"page": a["page"], "origin": o["origin"], "host": o["host"], "verdict": o["verdict"],
               "failed_stage": o["failed_stage"] or "", "failure_code": o["failure_code"] or "",
               "v6_dns_rcode": v6["dns"].get("rcode", "literal"),
               "v6_addresses": " ".join(v6["dns"].get("addresses", [])),
               "v6_synthesized": v6["dns"].get("synthesized", ""),
               "v6_tcp": _stage_mark(v6, "tcp"), "v6_tls": _stage_mark(v6, "tls"),
               "v6_http_status": v6["http"].get("status", ""), "v6_failure_code": v6["failure_code"] or "",
               "v4_addresses": " ".join(v4["dns"].get("addresses", [])),
               "v4_failure_code": v4["failure_code"] or "", "v4_http_status": v4["http"].get("status", ""),
               "probe_url": o["probe_url"]}


def write_csv(path: str, fields: list[str], rows) -> None:
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fields)
        w.writeheader()
        for r in rows:
            w.writerow(r)


def write_all(a: dict, outdir: str) -> dict:
    os.makedirs(outdir, exist_ok=True)
    base = os.path.join(outdir, slug(a["page"]))
    paths = {"json": base + ".json", "resources_csv": base + ".resources.csv",
             "origins_csv": base + ".origins.csv", "html": base + ".html"}
    with open(paths["json"], "w", encoding="utf-8") as fh:
        json.dump(a, fh, indent=2, default=str)
    write_csv(paths["resources_csv"], RESOURCE_FIELDS, resource_rows(a))
    write_csv(paths["origins_csv"], ORIGIN_FIELDS, origin_rows(a))
    with open(paths["html"], "w", encoding="utf-8") as fh:
        fh.write(render_html(a))
    return paths


# --------------------------------------------------------------------------- #
# HTML dependency graph (self-contained, no network needed to open it)
# --------------------------------------------------------------------------- #
def render_html(a: dict) -> str:
    data = json.dumps({"page": a["page"], "summary": a["summary"], "vantage": a["vantage"],
                       "root": a["tree"]["root"], "resources": a["resources"],
                       "origins": {k: {"verdict": v["verdict"], "failed_stage": v["failed_stage"],
                                       "failure_code": v["failure_code"], "host": v["host"],
                                       "v6": _fam_view(v["ipv6"]), "v4": _fam_view(v["ipv4"])}
                                   for k, v in a["origins"].items()}}, default=str)
    data = data.replace("</", "<\\/")
    return HTML_TEMPLATE.replace("__TITLE__", html.escape(a["page"])).replace("__DATA__", data)


def _fam_view(f: dict) -> dict:
    out = {"failed_stage": f["failed_stage"], "failure_code": f["failure_code"], "stages": {}}
    for st in ("dns", "tcp", "tls", "http"):
        d = f.get(st) or {}
        state = "fail" if f["failed_stage"] == st else ("ok" if d.get("ok") else "skip")
        detail = ""
        if st == "dns":
            detail = ", ".join(d.get("addresses", [])) or d.get("rcode", "")
            if d.get("synthesized"):
                detail += " (NAT64-synthesized)"
        elif st == "tcp":
            detail = d.get("addr", "") or d.get("error", "")
            if d.get("shim"):
                detail += " [lab shim]"
        elif st == "tls":
            detail = d.get("skipped") or (f"{d.get('version','')} CN={d.get('cert_cn','')}"
                                          if d.get("ok") else d.get("error", ""))
        elif st == "http":
            detail = (f"{d.get('status')} {d.get('reason','')}" if d.get("status") else d.get("error", ""))
        out["stages"][st] = {"state": state, "detail": str(detail)[:160]}
    return out


HTML_TEMPLATE = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>IPv6 audit · __TITLE__</title>
<style>
:root{--bg:#f7f7f5;--panel:#fff;--ink:#1d1d1b;--mute:#6b6b66;--line:#e3e2dc;
--ok:#1f8a4c;--ok-bg:#e3f4ea;--bad:#c4372b;--bad-bg:#fbe6e3;--warn:#b26b00;--warn-bg:#fdf0d9;
--gray:#6b6b66;--gray-bg:#ecebe6;--accent:#2f5bd3}
@media (prefers-color-scheme:dark){:root{--bg:#151514;--panel:#1e1e1c;--ink:#ecebe6;--mute:#9a9992;--line:#2f2f2c;
--ok:#5cc98a;--ok-bg:#16301f;--bad:#ff7a6c;--bad-bg:#3a1a16;--warn:#f0b04f;--warn-bg:#352611;--gray:#a3a29b;--gray-bg:#2a2a27;--accent:#8aa8ff}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.45 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
header{padding:20px 24px 8px}h1{font-size:20px;margin:0 0 4px}h2{font-size:15px;margin:28px 0 10px}
.mute{color:var(--mute)}main{padding:0 24px 40px;max-width:1400px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:10px;margin-top:14px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:12px 14px}
.card b{display:block;font-size:22px;font-variant-numeric:tabular-nums}.card span{color:var(--mute);font-size:12px}
.pill{display:inline-block;padding:1px 8px;border-radius:99px;font-size:11.5px;font-weight:600;white-space:nowrap}
.v-READY,.s-ok{background:var(--ok-bg);color:var(--ok)}
.v-IPV4_ONLY,.v-IPV6_TCP_FAIL,.v-IPV6_TLS_FAIL,.v-IPV6_HTTP_FAIL,.v-IPV6_DNS_ERROR,.s-fail{background:var(--bad-bg);color:var(--bad)}
.v-IPV4_ONLY_NAT64,.v-INCONCLUSIVE_NO_IPV6,.pv-INCONCLUSIVE_NO_IPV6{background:var(--warn-bg);color:var(--warn)}.v-BROKEN_BOTH,.s-skip,.pv-UNREACHABLE{background:var(--gray-bg);color:var(--gray)}
.pv-FULLY_READY{background:var(--ok-bg);color:var(--ok)}.pv-DEGRADED_ON_IPV6{background:var(--warn-bg);color:var(--warn)}
.pv-BROKEN_ON_IPV6,.pv-NOT_READY{background:var(--bad-bg);color:var(--bad)}
.toolbar{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-bottom:8px}
.toolbar button{background:var(--panel);color:var(--ink);border:1px solid var(--line);border-radius:7px;padding:4px 10px;cursor:pointer;font:inherit;font-size:12.5px}
.toolbar button.on{border-color:var(--accent);color:var(--accent)}
.tree{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:10px 6px;overflow-x:auto}
.node{display:flex;align-items:center;gap:8px;padding:3px 8px;border-radius:6px;white-space:nowrap;cursor:pointer}
.node:hover{background:var(--gray-bg)}.node .tw{width:14px;color:var(--mute);text-align:center;flex:none}
.node .u{overflow:hidden;text-overflow:ellipsis;max-width:62vw}.node .t{color:var(--mute);font-size:11.5px;width:74px;flex:none}
.node .blk{color:var(--bad);font-size:11.5px}.kids{margin-left:18px;border-left:1px dashed var(--line);padding-left:4px}
.hidden{display:none}
table{border-collapse:collapse;width:100%;background:var(--panel);border:1px solid var(--line);border-radius:10px;overflow:hidden;font-size:12.5px}
th,td{text-align:left;padding:7px 9px;border-bottom:1px solid var(--line);vertical-align:top}th{color:var(--mute);font-weight:600;background:var(--bg)}
.lad{display:flex;gap:3px}.lad .pill{min-width:44px;text-align:center}
.det{color:var(--mute);font-size:11.5px;max-width:420px;word-break:break-all}
.legend{display:flex;gap:6px;flex-wrap:wrap;margin-top:8px}
@media (max-width:700px){header,main{padding-left:16px;padding-right:16px}.node .u{max-width:48vw}.wrap{overflow-x:auto}}
</style></head><body>
<header><h1>IPv6 readiness audit</h1><div class="mute" id="sub"></div><div class="legend" id="legend"></div></header>
<main>
<div class="cards" id="cards"></div>
<h2>Dependency graph <span class="mute" style="font-weight:400">(initial page load; parent → sub-resource)</span></h2>
<div class="toolbar"><button id="f-all" class="on">All</button><button id="f-bad">IPv6 problems only</button>
<button id="f-exp">Expand all</button><button id="f-col">Collapse to depth 1</button></div>
<div class="tree" id="tree"></div>
<h2>Per-origin layered diagnosis</h2>
<div class="wrap"><table id="origins"><thead><tr><th>Origin</th><th>Verdict</th><th>IPv6: DNS · TCP · TLS · HTTP</th><th>IPv4: DNS · TCP · TLS · HTTP</th><th>Where IPv6 failed</th></tr></thead><tbody></tbody></table></div>
<p class="mute" style="margin-top:18px">AAAA presence alone is never counted as ready: READY requires DNS, TCP, TLS and HTTP to succeed over IPv6.
BROKEN_BOTH = fails over IPv4 as well (not IPv6-specific). IPV4_ONLY_NAT64 = works only through a synthesized (DNS64) address.</p>
</main>
<script>
const D=__DATA__;const R=D.resources,O=D.origins,S=D.summary;
const BAD=new Set(["IPV4_ONLY","IPV4_ONLY_NAT64","IPV6_TCP_FAIL","IPV6_TLS_FAIL","IPV6_HTTP_FAIL","IPV6_DNS_ERROR"]);
const esc=s=>String(s??"").replace(/[&<>"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));
const pill=(v,p="v")=>`<span class="pill ${p}-${v}">${esc(v)}</span>`;
document.getElementById("sub").innerHTML=`${esc(D.page)} · vantage: ${esc(D.vantage.pathway)}${D.vantage.lab_v6_shim?" · <b>lab IPv6 shim active</b>":""}`;
document.getElementById("legend").innerHTML=["READY","IPV4_ONLY","IPV6_TCP_FAIL","IPV6_TLS_FAIL","IPV6_HTTP_FAIL","IPV4_ONLY_NAT64","INCONCLUSIVE_NO_IPV6","BROKEN_BOTH"].map(v=>pill(v)).join("");
const card=(b,s)=>`<div class="card"><b>${b}</b><span>${s}</span></div>`;
document.getElementById("cards").innerHTML=
 `<div class="card"><b>${pill(S.page_verdict,"pv")}</b><span>page verdict (root AAAA: ${S.root_has_aaaa?"yes":"no"})</span></div>`+
 card(S.resources_total,"resources loaded")+card(S.origins_total,"unique origins probed")+
 card(S.resource_ipv6_ready_pct+"%","resources IPv6-ready")+card(S.ipv6_failing_resources,"resources failing on IPv6")+
 card(S.ipv6_failing_critical,"critical (script/css/api) failing")+
 card(Object.entries(S.ipv6_failures_by_stage).map(([k,v])=>`${k.toUpperCase()}:${v}`).join(" ")||"–","origin failures by layer");
const kids={};for(const[u,n]of Object.entries(R)){if(n.parent)(kids[n.parent]=kids[n.parent]||[]).push(u)}
const subtreeBad={};function sb(u){if(u in subtreeBad)return subtreeBad[u];let b=BAD.has(R[u].verdict);for(const k of kids[u]||[])b=sb(k)||b;return subtreeBad[u]=b}
let onlyBad=false;
function render(u,depth){const n=R[u];const ks=(kids[u]||[]).slice().sort((a,b)=>(BAD.has(R[b].verdict)-BAD.has(R[a].verdict))||a.localeCompare(b));
 if(onlyBad&&!sb(u))return"";
 const label=`<div class="node" data-u="${esc(u)}"><span class="tw">${ks.length?(depth<2?"▾":"▸"):"·"}</span>${pill(n.verdict)}<span class="t">${esc(n.resource_type)}</span><span class="u" title="${esc(u)}">${esc(u)}</span>${n.failure_code?`<span class="mute">${esc(n.failure_code)}</span>`:""}${n.blocked_by&&!BAD.has(n.verdict)?`<span class="blk">blocked on IPv6 via ancestor</span>`:""}</div>`;
 const inner=ks.map(k=>render(k,depth+1)).join("");
 return label+(ks.length?`<div class="kids ${depth<2?"":"hidden"}">${inner}</div>`:"")}
function draw(){document.getElementById("tree").innerHTML=render(D.root,0)}
draw();
document.getElementById("tree").addEventListener("click",e=>{const n=e.target.closest(".node");if(!n)return;const k=n.nextElementSibling;
 if(k&&k.classList.contains("kids")){k.classList.toggle("hidden");n.querySelector(".tw").textContent=k.classList.contains("hidden")?"▸":"▾"}});
const setOn=id=>{for(const b of ["f-all","f-bad"])document.getElementById(b).classList.toggle("on",b===id)};
document.getElementById("f-all").onclick=()=>{onlyBad=false;setOn("f-all");draw()};
document.getElementById("f-bad").onclick=()=>{onlyBad=true;setOn("f-bad");draw();document.querySelectorAll(".kids").forEach(k=>k.classList.remove("hidden"))};
document.getElementById("f-exp").onclick=()=>document.querySelectorAll(".kids").forEach(k=>k.classList.remove("hidden"));
document.getElementById("f-col").onclick=()=>document.querySelectorAll(".tree>.kids .kids").forEach(k=>k.classList.add("hidden"));
const lad=f=>`<div class="lad">${["dns","tcp","tls","http"].map(s=>`<span class="pill s-${f.stages[s].state}" title="${esc(f.stages[s].detail)}">${s.toUpperCase()}</span>`).join("")}</div>`;
const rows=Object.entries(O).sort((a,b)=>(BAD.has(b[1].verdict)-BAD.has(a[1].verdict))||a[0].localeCompare(b[0]));
document.querySelector("#origins tbody").innerHTML=rows.map(([k,o])=>{const fs=o.v6.failed_stage;
 return `<tr><td>${esc(k)}</td><td>${pill(o.verdict)}</td><td>${lad(o.v6)}</td><td>${lad(o.v4)}</td><td class="det">${fs?`<b>${esc(fs.toUpperCase())}</b> · ${esc(o.v6.failure_code)}<br>${esc(o.v6.stages[fs].detail)}`:(o.verdict==="IPV4_ONLY_NAT64"?"only via NAT64":"")}</td></tr>`}).join("");
</script></body></html>
"""
