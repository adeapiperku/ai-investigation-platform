"""Step 6 entry point: export the knowledge graph as an interactive HTML page.

Usage:
    python 06_export_graph_html.py [--graph FILE] [--out FILE] [--top-files N]

The full knowledge graph has tens of thousands of file/hash nodes, which no
browser can render at once. This exporter builds a *readable investigation view*
- every core entity (client, host, session, users, applications, URLs, CVEs,
IPs, MACs, artifacts) plus the top-N files by evidence - and writes a single
self-contained HTML file (embedded data + a dependency-free, force-directed
graph explorer). Open it in any browser; nothing is fetched from the network.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List

DEFAULT_GRAPH = Path("data/processed/knowledge_graph.json")
DEFAULT_OUT = Path("data/processed/knowledge_graph.html")

# Entity types always kept (few in number, they form the investigation backbone).
CORE_TYPES = {
    "client", "host", "session", "request", "ip", "mac", "artifact",
    "user", "application", "url", "cve",
}


def _select_nodes(
    nodes: List[Dict[str, Any]], edges: List[Dict[str, Any]], top_files: int
) -> Dict[str, Dict[str, Any]]:
    """Keep the core entities + the top-N file nodes + their hashes."""
    by_id = {n["id"]: n for n in nodes}
    kept: Dict[str, Dict[str, Any]] = {
        n["id"]: n for n in nodes if n.get("type") in CORE_TYPES
    }

    files = sorted(
        (n for n in nodes if n.get("type") == "file"),
        key=lambda n: n.get("evidence_count", 0),
        reverse=True,
    )[:top_files]
    for node in files:
        kept[node["id"]] = node

    # Add hashes attached to the kept files (so files link to something).
    kept_files = {n["id"] for n in files}
    for edge in edges:
        if edge.get("type") == "HAS_HASH" and edge["source"] in kept_files:
            target = by_id.get(edge["target"])
            if target:
                kept[target["id"]] = target
    return kept


def _annotate_counts(nodes: Dict[str, Dict[str, Any]], edges: List[Dict[str, Any]]) -> None:
    """Attach aggregate file counts to user / application nodes (labels lose them)."""
    owns: Counter = Counter()
    assoc: Counter = Counter()
    for edge in edges:
        if edge.get("type") == "OWNS":
            owns[edge["source"]] += 1
        elif edge.get("type") == "ASSOCIATED_WITH":
            assoc[edge["target"]] += 1
    for node_id, node in nodes.items():
        if node.get("type") == "user":
            node.setdefault("properties", {})["files_owned"] = owns.get(node_id, 0)
        elif node.get("type") == "application":
            node.setdefault("properties", {})["files_associated"] = assoc.get(node_id, 0)


def build_view(graph: Dict[str, Any], top_files: int) -> Dict[str, Any]:
    """Produce the pruned {nodes, links} view embedded into the HTML."""
    nodes = graph.get("nodes", [])
    edges = graph.get("edges", [])
    kept = _select_nodes(nodes, edges, top_files)
    _annotate_counts(kept, edges)

    index = {nid: i for i, nid in enumerate(kept)}
    view_nodes = [
        {
            "id": n["id"],
            "type": n.get("type"),
            "label": n.get("label") or n["id"],
            "ec": n.get("evidence_count", 0),
            "props": n.get("properties", {}),
        }
        for n in kept.values()
    ]
    view_links = [
        {"s": index[e["source"]], "t": index[e["target"]],
         "type": e.get("type"), "w": e.get("weight", 1)}
        for e in edges
        if e["source"] in index and e["target"] in index
    ]
    return {"nodes": view_nodes, "links": view_links}


def render_html(view: Dict[str, Any], meta: Dict[str, Any]) -> str:
    """Inject the view data into the self-contained HTML/JS template."""
    payload = json.dumps({"view": view, "meta": meta}, ensure_ascii=False)
    return _TEMPLATE.replace("/*__DATA__*/", payload)


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Export the knowledge graph as HTML")
    parser.add_argument("--graph", type=Path, default=DEFAULT_GRAPH)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--top-files", type=int, default=120,
                        help="how many top file nodes to include (default 120)")
    args = parser.parse_args(argv)

    if not args.graph.exists():
        print(f"error: knowledge graph not found: {args.graph}\n"
              "run Step 3 first:  python 03_build_knowledge_graph.py", file=sys.stderr)
        return 1

    graph = json.loads(args.graph.read_text(encoding="utf-8"))
    view = build_view(graph, args.top_files)
    meta = {
        "total_nodes": graph.get("stats", {}).get("total_nodes"),
        "total_edges": graph.get("stats", {}).get("total_edges"),
        "shown_nodes": len(view["nodes"]),
        "shown_links": len(view["links"]),
        "context": graph.get("graph_metadata", {}).get("collection_context", {}),
    }
    args.out.write_text(render_html(view, meta), encoding="utf-8")
    print("Done.")
    print(f"  full graph : {meta['total_nodes']} nodes / {meta['total_edges']} edges")
    print(f"  shown      : {meta['shown_nodes']} nodes / {meta['shown_links']} edges")
    print(f"  output     : {args.out}")
    print(f"  open it    : start {args.out}" if sys.platform == "win32"
          else f"  open it    : open {args.out}")
    return 0


# --------------------------------------------------------------------------- #
# Self-contained HTML template (no external resources). Data is injected at
# /*__DATA__*/ as {"view": {nodes, links}, "meta": {...}}.
# --------------------------------------------------------------------------- #
_TEMPLATE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Investigation Knowledge Graph</title>
<style>
  :root { color-scheme: dark; }
  * { box-sizing: border-box; }
  html, body { margin: 0; height: 100%; overflow: hidden;
    background: #070a0f; color: #e6edf3;
    font: 13px/1.45 -apple-system, system-ui, "Segoe UI", Roboto, sans-serif; }
  #app { display: flex; height: 100%; }
  #stage { flex: 1; position: relative; }
  canvas { display: block; width: 100%; height: 100%; cursor: grab; }
  canvas.grab { cursor: grabbing; }

  /* floating panel */
  #panel { position: absolute; top: 16px; right: 16px; width: 250px;
    background: rgba(18,24,33,0.82); backdrop-filter: blur(10px);
    border: 1px solid rgba(255,255,255,0.08); border-radius: 14px;
    padding: 16px 16px 14px; box-shadow: 0 12px 40px rgba(0,0,0,0.55); }
  #panel h1 { font-size: 15px; font-weight: 650; margin: 0 0 2px;
    letter-spacing: .2px; }
  .meta { color: #7d8896; font-size: 11px; margin-bottom: 12px; }
  #search { width: 100%; padding: 8px 11px; font-size: 12px; color: #e6edf3;
    background: rgba(0,0,0,0.35); border: 1px solid rgba(255,255,255,0.10);
    border-radius: 9px; outline: none; margin-bottom: 12px; }
  #search:focus { border-color: #2f81f7; }
  .legend { display: flex; flex-direction: column; gap: 1px; }
  .legend div { display: flex; align-items: center; gap: 9px; padding: 4px 6px;
    border-radius: 7px; cursor: pointer; user-select: none; transition: background .12s; }
  .legend div:hover { background: rgba(255,255,255,0.05); }
  .legend .sw { width: 11px; height: 11px; border-radius: 50%; flex: none;
    box-shadow: 0 0 8px currentColor; }
  .legend .cnt { margin-left: auto; color: #7d8896; font-variant-numeric: tabular-nums; }
  .legend .off { opacity: .32; }
  .legend .off .sw { box-shadow: none; }
  .hint { color: #5a6472; font-size: 10.5px; margin-top: 13px; line-height: 1.7; }

  /* tooltip */
  #tip { position: absolute; pointer-events: none; display: none; z-index: 6;
    max-width: 340px; padding: 10px 12px; font-size: 12px;
    background: rgba(13,18,26,0.95); border: 1px solid rgba(255,255,255,0.12);
    border-radius: 10px; box-shadow: 0 10px 34px rgba(0,0,0,0.6); }
  #tip .ty { font-size: 9.5px; letter-spacing: 1.2px; text-transform: uppercase;
    color: #7d8896; margin-bottom: 3px; }
  #tip .lb { font-weight: 640; color: #fff; word-break: break-all; margin-bottom: 5px; }
  #tip .row { color: #aeb8c4; }
  #tip .row b { color: #e6edf3; font-weight: 550; }
</style>
</head>
<body>
<div id="app">
  <div id="stage">
    <canvas id="cv"></canvas>
    <div id="tip"></div>
    <div id="panel">
      <h1>Knowledge Graph</h1>
      <div class="meta" id="meta"></div>
      <input id="search" placeholder="Search nodes…" autocomplete="off" spellcheck="false">
      <div class="legend" id="legend"></div>
      <div class="hint">Hover a node to trace its links · click to pin ·
        drag to move · scroll to zoom · double-click to reset view.</div>
    </div>
  </div>
</div>
<script>
const DATA = /*__DATA__*/;
const V = DATA.view, META = DATA.meta;

const COLORS = { client:"#f778ba", host:"#58a6ff", session:"#56d4dd", request:"#a5d6ff",
  user:"#3fb950", application:"#e3b341", file:"#7d8896", hash:"#59636e",
  ip:"#ff7b72", mac:"#ffa657", artifact:"#bc8cff", url:"#39c5cf", cve:"#f85149" };
const color = t => COLORS[t] || "#8b949e";

const cv = document.getElementById("cv"), ctx = cv.getContext("2d");
const tip = document.getElementById("tip");
let W, H, DPR = Math.min(window.devicePixelRatio || 1, 2);
function resize(){ W = cv.clientWidth; H = cv.clientHeight;
  cv.width = W*DPR; cv.height = H*DPR; ctx.setTransform(DPR,0,0,DPR,0,0); }
addEventListener("resize", () => { resize(); });

// --- build nodes / links + adjacency ---
const nodes = V.nodes.map((n,i) => ({...n, i,
  x: Math.cos(i*2.4)*260 + (Math.random()-0.5)*60,
  y: Math.sin(i*2.4)*260 + (Math.random()-0.5)*60, vx:0, vy:0,
  r: Math.max(4.5, Math.min(26, 4.5 + Math.log2((n.ec||1)+1)*2.3)),
  adj: new Set(), inc: [] }));
const links = V.links.map(l => ({...l, s: nodes[l.s], t: nodes[l.t]}));
for (const l of links){ l.s.adj.add(l.t); l.t.adj.add(l.s); l.s.inc.push(l); l.t.inc.push(l); }
const hidden = new Set();

// --- view transform ---
let scale = 1, ox = 0, oy = 0;
const toScreen = (x,y) => [x*scale+ox, y*scale+oy];
const toWorld = (px,py) => [(px-ox)/scale, (py-oy)/scale];

// --- Fruchterman-Reingold initial layout ---
const K = Math.sqrt((1500*950)/Math.max(nodes.length,1)) * 0.9;
function layout(iters){
  let temp = K*6;
  for (let it=0; it<iters; it++){
    for (const n of nodes){ n.dx=0; n.dy=0; }
    for (let a=0; a<nodes.length; a++){ const na=nodes[a];
      for (let b=a+1; b<nodes.length; b++){ const nb=nodes[b];
        let dx=na.x-nb.x, dy=na.y-nb.y, d=Math.hypot(dx,dy)||0.01, f=(K*K)/(d*d);
        na.dx+=dx*f; na.dy+=dy*f; nb.dx-=dx*f; nb.dy-=dy*f; } }
    for (const l of links){ let dx=l.s.x-l.t.x, dy=l.s.y-l.t.y,
      d=Math.hypot(dx,dy)||0.01, f=(d)/K;
      l.s.dx-=dx*f; l.s.dy-=dy*f; l.t.dx+=dx*f; l.t.dy+=dy*f; }
    for (const n of nodes){ n.dx+=-n.x*0.03; n.dy+=-n.y*0.03;
      const d=Math.hypot(n.dx,n.dy)||0.01, lim=Math.min(d,temp)/d;
      n.x+=n.dx*lim; n.y+=n.dy*lim; }
    temp *= 0.96;
  }
}
function fit(){
  let a=1e9,b=1e9,c=-1e9,d=-1e9;
  for (const n of nodes){ a=Math.min(a,n.x); b=Math.min(b,n.y); c=Math.max(c,n.x); d=Math.max(d,n.y); }
  const gw=(c-a)||1, gh=(d-b)||1;
  scale=Math.max(0.12, Math.min(1.8, Math.min(W/(gw+140), H/(gh+140))));
  ox=W/2-(a+c)/2*scale; oy=H/2-(b+d)/2*scale;
}

// --- gentle live relaxation (settles, re-heats on interaction) ---
let energy = 0.5;
function step(){
  if (energy < 0.02 && !dragging) return;
  for (const n of nodes){ n.dx=0; n.dy=0; }
  for (let a=0; a<nodes.length; a++){ const na=nodes[a];
    for (let b=a+1; b<nodes.length; b++){ const nb=nodes[b];
      let dx=na.x-nb.x, dy=na.y-nb.y, d2=dx*dx+dy*dy+0.01, f=(K*K)/d2, d=Math.sqrt(d2);
      dx/=d; dy/=d; na.dx+=dx*f; na.dy+=dy*f; nb.dx-=dx*f; nb.dy-=dy*f; } }
  for (const l of links){ let dx=l.t.x-l.s.x, dy=l.t.y-l.s.y, d=Math.hypot(dx,dy)||0.01,
    f=(d-K)*0.045; dx/=d; dy/=d;
    l.s.dx+=dx*f; l.s.dy+=dy*f; l.t.dx-=dx*f; l.t.dy-=dy*f; }
  for (const n of nodes){ if (n===dragging) continue;
    n.vx=(n.vx+n.dx*0.10-n.x*0.006)*0.85; n.vy=(n.vy+n.dy*0.10-n.y*0.006)*0.85;
    n.x+=n.vx*energy; n.y+=n.vy*energy; }
  energy = Math.max(0.02, energy*0.985);
}

// --- rendering ---
let query = "", hoverNode = null, selNode = null;
function activeSet(){
  const a = selNode || hoverNode; if (!a) return null;
  const s = new Set(a.adj); s.add(a); return s;
}
function curve(x1,y1,x2,y2){
  const mx=(x1+x2)/2, my=(y1+y2)/2, dx=x2-x1, dy=y2-y1, len=Math.hypot(dx,dy)||1;
  const off=len*0.13; return [mx-dy/len*off, my+dx/len*off];
}
function draw(){
  // background glow
  const g = ctx.createRadialGradient(W/2,H*0.42,0, W/2,H*0.42, Math.max(W,H)*0.75);
  g.addColorStop(0,"#0e1622"); g.addColorStop(1,"#070a0f");
  ctx.fillStyle=g; ctx.fillRect(0,0,W,H);

  const act = activeSet();
  const vis = n => !hidden.has(n.type);

  // edges
  ctx.lineCap="round";
  for (const l of links){
    if (!vis(l.s) || !vis(l.t)) continue;
    const inc = act && (act.has(l.s) && act.has(l.t) &&
                        (l.s===(selNode||hoverNode) || l.t===(selNode||hoverNode)));
    const [x1,y1]=toScreen(l.s.x,l.s.y), [x2,y2]=toScreen(l.t.x,l.t.y);
    const [cx,cy]=curve(x1,y1,x2,y2);
    if (inc){ ctx.strokeStyle = color((selNode||hoverNode).type)+"cc"; ctx.lineWidth=1.6; }
    else if (act){ ctx.strokeStyle="rgba(125,136,150,0.05)"; ctx.lineWidth=1; }
    else { ctx.strokeStyle="rgba(125,136,150,0.16)"; ctx.lineWidth=1; }
    ctx.beginPath(); ctx.moveTo(x1,y1); ctx.quadraticCurveTo(cx,cy,x2,y2); ctx.stroke();
  }

  // nodes
  ctx.textAlign="left"; ctx.textBaseline="middle";
  for (const n of nodes){
    if (!vis(n)) continue;
    const [x,y]=toScreen(n.x,n.y);
    const hit = query && n.label.toLowerCase().includes(query);
    const dim = (act && !act.has(n)) || (query && !hit);
    ctx.globalAlpha = dim ? 0.14 : 1;
    ctx.shadowColor = color(n.type); ctx.shadowBlur = dim ? 0 : (n===selNode ? 26 : 12);
    ctx.beginPath(); ctx.arc(x,y,n.r,0,6.2832);
    ctx.fillStyle = color(n.type); ctx.fill();
    ctx.shadowBlur = 0;
    if (n===selNode || n===hoverNode || hit){
      ctx.lineWidth = 2.2; ctx.strokeStyle = "#fff"; ctx.stroke();
    } else { ctx.lineWidth = 1; ctx.strokeStyle = "rgba(255,255,255,0.18)"; ctx.stroke(); }
    ctx.globalAlpha = 1;
  }

  // labels (hubs, active neighbourhood, search hits)
  ctx.font = "600 11.5px system-ui";
  for (const n of nodes){
    if (!vis(n)) continue;
    const hit = query && n.label.toLowerCase().includes(query);
    const show = hit || n===selNode || n===hoverNode || (act && act.has(n)) ||
                 (!act && !query && n.r >= 11);
    if (!show) continue;
    const [x,y]=toScreen(n.x,n.y);
    const txt = n.label.length>30 ? n.label.slice(0,29)+"…" : n.label;
    ctx.lineWidth = 3.4; ctx.strokeStyle = "rgba(4,7,11,0.92)";
    ctx.strokeText(txt, x+n.r+5, y); ctx.fillStyle = "#d6dee8";
    ctx.fillText(txt, x+n.r+5, y);
  }
}
function frame(){ step(); draw(); requestAnimationFrame(frame); }

// --- interaction ---
let dragging=null, panning=false, lx=0, ly=0, moved=false;
function nodeAt(px,py){
  let best=null, bd=1e9;
  for (const n of nodes){ if (hidden.has(n.type)) continue;
    const [x,y]=toScreen(n.x,n.y); const d=(px-x)**2+(py-y)**2;
    if (d <= (n.r+4)**2 && d<bd){ bd=d; best=n; } }
  return best;
}
cv.addEventListener("mousedown", e => {
  moved=false; const n=nodeAt(e.offsetX,e.offsetY);
  if (n){ dragging=n; energy=Math.max(energy,0.35); }
  else { panning=true; cv.classList.add("grab"); }
  lx=e.offsetX; ly=e.offsetY;
});
addEventListener("mousemove", e => {
  const rect=cv.getBoundingClientRect(); const px=e.clientX-rect.left, py=e.clientY-rect.top;
  if (px<0||py<0||px>W||py>H){ if(!dragging&&!panning){ hoverNode=null; tip.style.display="none"; } }
  if (dragging){ const [wx,wy]=toWorld(px,py); dragging.x=wx; dragging.y=wy; dragging.vx=dragging.vy=0;
    energy=Math.max(energy,0.3); moved=true; }
  else if (panning){ ox+=px-lx; oy+=py-ly; lx=px; ly=py; moved=true; }
  else { hoverNode=nodeAt(px,py); showTip(px,py); }
});
addEventListener("mouseup", () => {
  if (dragging && !moved){ selNode = (selNode===dragging)?null:dragging; }
  dragging=null; panning=false; cv.classList.remove("grab");
});
cv.addEventListener("dblclick", () => { selNode=null; fit(); });
cv.addEventListener("wheel", e => { e.preventDefault();
  const [wx,wy]=toWorld(e.offsetX,e.offsetY);
  scale *= e.deltaY<0 ? 1.12 : 0.89; scale=Math.max(0.08, Math.min(7, scale));
  ox=e.offsetX-wx*scale; oy=e.offsetY-wy*scale;
}, {passive:false});

function showTip(px,py){
  const n=hoverNode;
  if (!n){ tip.style.display="none"; return; }
  const props=Object.entries(n.props||{}).filter(([,v])=>v!=null&&v!=="")
    .map(([k,v])=>`<div class="row"><b>${k}</b>: ${String(v).slice(0,90)}</div>`).join("");
  tip.innerHTML=`<div class="ty" style="color:${color(n.type)}">${n.type}</div>`+
    `<div class="lb">${n.label}</div>`+
    `<div class="row"><b>evidence</b>: ${n.ec} · <b>links</b>: ${n.adj.size}</div>`+props;
  tip.style.display="block";
  tip.style.left=Math.min(px+16, W-350)+"px"; tip.style.top=Math.min(py+16, H-120)+"px";
}

// --- legend ---
const counts={}; for (const n of nodes) counts[n.type]=(counts[n.type]||0)+1;
const legend=document.getElementById("legend");
Object.keys(counts).sort().forEach(t => {
  const row=document.createElement("div");
  row.style.color=color(t);
  row.innerHTML=`<span class="sw" style="background:${color(t)}"></span>`+
    `<span style="color:#e6edf3">${t}</span><span class="cnt">${counts[t]}</span>`;
  row.onclick=()=>{ hidden.has(t)?hidden.delete(t):hidden.add(t); row.classList.toggle("off");
    energy=Math.max(energy,0.2); };
  legend.appendChild(row);
});
document.getElementById("search").addEventListener("input", e => query=e.target.value.toLowerCase().trim());
document.getElementById("meta").innerHTML =
  `${META.shown_nodes} of ${META.total_nodes.toLocaleString()} nodes · `+
  `${META.shown_links} edges`+
  (META.context && META.context.hostname ? ` · host <b style="color:#c9d1d9">${META.context.hostname}</b>` : "");

resize(); layout(280); fit(); frame();
</script>
</body>
</html>
"""


if __name__ == "__main__":
    raise SystemExit(main())
