"""Step 6 entry point: export the knowledge graph as an interactive HTML page.

Usage:
    python 06_export_graph_html.py [--graph FILE] [--out FILE] [--top-files N]

The full knowledge graph has tens of thousands of file/hash nodes, which no
browser can render at once. This exporter builds a *readable investigation view*
— every core entity (client, host, session, users, applications, IPs, MACs,
artifacts) plus the top-N files by evidence — and writes a single self-contained
HTML file (embedded data + a dependency-free force-directed graph). Open it in
any browser; nothing is fetched from the network.
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
  html, body { margin: 0; height: 100%; background: #0e1116; color: #e6edf3;
    font: 13px/1.4 system-ui, -apple-system, Segoe UI, Roboto, sans-serif; }
  #wrap { display: flex; height: 100%; }
  #graph { flex: 1; position: relative; }
  canvas { display: block; width: 100%; height: 100%; cursor: grab; }
  canvas.grabbing { cursor: grabbing; }
  #side { width: 260px; padding: 14px 16px; background: #161b22; overflow-y: auto;
    border-left: 1px solid #30363d; }
  h1 { font-size: 15px; margin: 0 0 4px; }
  .sub { color: #8b949e; font-size: 11px; margin-bottom: 12px; }
  .legend div { display: flex; align-items: center; gap: 8px; padding: 3px 0; cursor: pointer;
    user-select: none; }
  .legend .sw { width: 12px; height: 12px; border-radius: 3px; flex: none; }
  .legend .off { opacity: 0.35; text-decoration: line-through; }
  .legend .cnt { margin-left: auto; color: #8b949e; }
  #tip { position: absolute; pointer-events: none; background: #1c2430; border: 1px solid #30363d;
    border-radius: 6px; padding: 8px 10px; font-size: 12px; max-width: 320px; display: none;
    box-shadow: 0 6px 20px rgba(0,0,0,.5); z-index: 5; }
  #tip b { color: #58a6ff; }
  #tip .t { color: #8b949e; text-transform: uppercase; font-size: 10px; letter-spacing: .5px; }
  .hint { color: #6e7681; font-size: 11px; margin-top: 14px; line-height: 1.6; }
  input { width: 100%; padding: 6px 8px; background: #0e1116; border: 1px solid #30363d;
    border-radius: 6px; color: #e6edf3; margin-bottom: 12px; }
</style>
</head>
<body>
<div id="wrap">
  <div id="graph">
    <canvas id="cv"></canvas>
    <div id="tip"></div>
  </div>
  <div id="side">
    <h1>Knowledge Graph</h1>
    <div class="sub" id="meta"></div>
    <input id="search" placeholder="highlight nodes…" autocomplete="off">
    <div class="legend" id="legend"></div>
    <div class="hint">
      Scroll = zoom · drag background = pan · drag a node to move it ·
      hover for details · click a legend row to hide/show a type.
    </div>
  </div>
</div>
<script>
const DATA = /*__DATA__*/;
const V = DATA.view, META = DATA.meta;
const COLORS = { client:"#f778ba", host:"#58a6ff", session:"#79c0ff", request:"#a5d6ff",
  user:"#3fb950", application:"#d29922", file:"#8b949e", hash:"#6e7681",
  ip:"#ff7b72", mac:"#ffa657", artifact:"#bc8cff", url:"#39c5cf", cve:"#f85149" };
const color = t => COLORS[t] || "#8b949e";

const cv = document.getElementById("cv"), ctx = cv.getContext("2d");
const tip = document.getElementById("tip");
let W, H, DPR = window.devicePixelRatio || 1;
function resize(){ W = cv.clientWidth; H = cv.clientHeight;
  cv.width = W*DPR; cv.height = H*DPR; ctx.setTransform(DPR,0,0,DPR,0,0); }
window.addEventListener("resize", resize);

// --- nodes / links ---
const nodes = V.nodes.map((n,i) => ({...n, i,
  x: Math.cos(i)*300 + (Math.random()-0.5)*80, y: Math.sin(i*1.3)*300 + (Math.random()-0.5)*80,
  vx:0, vy:0, r: Math.max(4, Math.min(22, 4 + Math.log2((n.ec||1)+1)*2)) }));
const links = V.links.map(l => ({...l, s: nodes[l.s], t: nodes[l.t]}));
const hidden = new Set();

// --- view transform ---
let scale = 0.8, ox = W/2, oy = H/2;
function toScreen(x,y){ return [x*scale+ox, y*scale+oy]; }
function toWorld(px,py){ return [(px-ox)/scale, (py-oy)/scale]; }

// --- Fruchterman-Reingold layout (runs to convergence once, on load) ---
const K = Math.sqrt((1400*900) / Math.max(nodes.length,1)) * 0.85;  // ideal edge length
function layout(iters){
  let temp = K * 5;
  for (let it=0; it<iters; it++){
    for (const n of nodes){ n.dx = 0; n.dy = 0; }
    for (let a=0; a<nodes.length; a++){
      const na = nodes[a];
      for (let b=a+1; b<nodes.length; b++){
        const nb = nodes[b];
        let dx = na.x-nb.x, dy = na.y-nb.y, d = Math.hypot(dx,dy)||0.01;
        const f = (K*K)/d / d;                       // repulsion, normalised
        na.dx += dx*f; na.dy += dy*f; nb.dx -= dx*f; nb.dy -= dy*f;
      }
    }
    for (const l of links){                          // attraction along edges
      let dx = l.s.x-l.t.x, dy = l.s.y-l.t.y, d = Math.hypot(dx,dy)||0.01;
      const f = (d*d)/K / d;
      l.s.dx -= dx*f; l.s.dy -= dy*f; l.t.dx += dx*f; l.t.dy += dy*f;
    }
    for (const n of nodes){
      n.dx += -n.x*0.03; n.dy += -n.y*0.03;          // gentle pull to centre
      const d = Math.hypot(n.dx,n.dy)||0.01;
      const lim = Math.min(d, temp)/d;
      n.x += n.dx*lim; n.y += n.dy*lim;
    }
    temp *= 0.965;                                    // cool down
  }
}
function fitView(){
  let mnx=1e9, mny=1e9, mxx=-1e9, mxy=-1e9;
  for (const n of nodes){ mnx=Math.min(mnx,n.x); mny=Math.min(mny,n.y);
    mxx=Math.max(mxx,n.x); mxy=Math.max(mxy,n.y); }
  const gw = (mxx-mnx)||1, gh = (mxy-mny)||1;
  scale = Math.max(0.1, Math.min(2, Math.min(W/(gw+120), H/(gh+120))));
  ox = W/2 - (mnx+mxx)/2*scale; oy = H/2 - (mny+mxy)/2*scale;
}

// --- rendering ---
let query = "";
function draw(){
  ctx.clearRect(0,0,W,H);
  ctx.lineWidth = 1;
  for (const l of links){
    if (hidden.has(l.s.type) || hidden.has(l.t.type)) continue;
    const [x1,y1] = toScreen(l.s.x,l.s.y), [x2,y2] = toScreen(l.t.x,l.t.y);
    ctx.strokeStyle = "rgba(139,148,158,0.18)";
    ctx.beginPath(); ctx.moveTo(x1,y1); ctx.lineTo(x2,y2); ctx.stroke();
  }
  for (const n of nodes){
    if (hidden.has(n.type)) continue;
    const [x,y] = toScreen(n.x,n.y);
    const hit = query && n.label.toLowerCase().includes(query);
    ctx.beginPath(); ctx.arc(x,y,n.r,0,6.2832);
    ctx.fillStyle = color(n.type); ctx.globalAlpha = (query && !hit) ? 0.25 : 1;
    ctx.fill();
    if (hit){ ctx.lineWidth = 2; ctx.strokeStyle = "#fff"; ctx.stroke(); }
    ctx.globalAlpha = 1;
    if (scale > 0.65 && (n.r > 7 || hit)){
      ctx.fillStyle = "#c9d1d9"; ctx.font = "11px system-ui";
      ctx.fillText(n.label.slice(0,26), x+n.r+3, y+4);
    }
  }
}
function render(){ draw(); requestAnimationFrame(render); }

// --- interaction ---
let dragging=null, panning=false, lastX=0, lastY=0;
function nodeAt(px,py){
  for (let i=nodes.length-1; i>=0; i--){
    const n = nodes[i]; if (hidden.has(n.type)) continue;
    const [x,y] = toScreen(n.x,n.y);
    if ((px-x)**2 + (py-y)**2 <= (n.r+3)**2) return n;
  }
  return null;
}
cv.addEventListener("mousedown", e => {
  const n = nodeAt(e.offsetX, e.offsetY);
  if (n){ dragging = n; } else { panning = true; cv.classList.add("grabbing"); }
  lastX = e.offsetX; lastY = e.offsetY;
});
window.addEventListener("mousemove", e => {
  const rect = cv.getBoundingClientRect();
  const px = e.clientX-rect.left, py = e.clientY-rect.top;
  if (dragging){ const [wx,wy] = toWorld(px,py); dragging.x = wx; dragging.y = wy; }
  else if (panning){ ox += px-lastX; oy += py-lastY; lastX=px; lastY=py; }
  else { showTip(px,py); }
});
window.addEventListener("mouseup", () => { dragging=null; panning=false; cv.classList.remove("grabbing"); });
cv.addEventListener("wheel", e => {
  e.preventDefault();
  const [wx,wy] = toWorld(e.offsetX, e.offsetY);
  scale *= e.deltaY < 0 ? 1.1 : 0.9; scale = Math.max(0.1, Math.min(6, scale));
  ox = e.offsetX - wx*scale; oy = e.offsetY - wy*scale;
}, {passive:false});

function showTip(px,py){
  const n = nodeAt(px,py);
  if (!n){ tip.style.display = "none"; return; }
  let props = Object.entries(n.props||{}).filter(([,v]) => v!=null && v!=="")
    .map(([k,v]) => `${k}: ${v}`).join("<br>");
  tip.innerHTML = `<div class="t">${n.type}</div><b>${n.label}</b><br>` +
    `evidence: ${n.ec}` + (props ? "<br>"+props : "");
  tip.style.display = "block";
  tip.style.left = Math.min(px+14, W-330) + "px"; tip.style.top = (py+14) + "px";
}

// --- legend ---
const counts = {}; for (const n of nodes) counts[n.type] = (counts[n.type]||0)+1;
const legend = document.getElementById("legend");
Object.keys(counts).sort().forEach(t => {
  const row = document.createElement("div");
  row.innerHTML = `<span class="sw" style="background:${color(t)}"></span><span>${t}</span>` +
    `<span class="cnt">${counts[t]}</span>`;
  row.onclick = () => { hidden.has(t) ? hidden.delete(t) : hidden.add(t);
    row.classList.toggle("off"); };
  legend.appendChild(row);
});
document.getElementById("search").addEventListener("input", e => query = e.target.value.toLowerCase());
document.getElementById("meta").innerHTML =
  `showing ${META.shown_nodes} of ${META.total_nodes} nodes, ${META.shown_links} of ${META.total_edges} edges` +
  (META.context && META.context.hostname ? `<br>host: ${META.context.hostname}` : "");

resize(); layout(260); fitView(); render();
</script>
</body>
</html>
"""


if __name__ == "__main__":
    raise SystemExit(main())
