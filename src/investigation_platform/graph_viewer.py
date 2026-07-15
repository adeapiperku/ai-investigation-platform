"""Generate a self-contained, browser-viewable HTML graph of the case.

This does NOT replace the GraphML export (graph.py) -- that stays as
the full, tool-interoperable graph for Gephi/yEd. This is a lighter,
overview-focused view meant to be opened directly in a browser: the
skeleton (host -> users -> artifacts) is drawn as an interactive graph,
and clicking a user reveals their files in a side panel (with
provenance), since drawing all ~25k file nodes at once is unreadable.

No external JS/CSS libraries are used, so the output file works
completely offline.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .graph import build_graph, extract_user


def build_viewer_data(case_root: Path, normalized_dir: Path) -> dict[str, Any]:
    g = build_graph(case_root, normalized_dir)

    hosts = [n for n, d in g.nodes(data=True) if d.get("kind") == "host"]
    users = [n for n, d in g.nodes(data=True) if d.get("kind") == "user"]
    artifacts = [n for n, d in g.nodes(data=True) if d.get("kind") == "artifact"]

    nodes = []
    edges = []

    for h in hosts:
        nodes.append({"id": h, "label": h, "kind": "host"})
    for a in artifacts:
        label = a.replace("artifact:", "")
        nodes.append({"id": a, "label": label, "kind": "artifact"})

    files_by_user: dict[str, list[dict[str, Any]]] = {}

    for u in users:
        udata = g.nodes[u]
        username = udata["username"]
        file_count = sum(
            1 for _, tgt in g.out_edges(u) if g.nodes[tgt].get("kind") == "file"
        )
        nodes.append({"id": u, "label": f"{username} ({file_count} files)", "kind": "user"})
        for h in hosts:
            if g.has_edge(h, u):
                edges.append({"source": h, "target": u, "relation": "has_profile"})

        user_files = []
        for _, file_node in g.out_edges(u):
            fdata = g.nodes[file_node]
            if fdata.get("kind") != "file":
                continue
            user_files.append(
                {
                    "path": file_node,
                    "size": fdata.get("size"),
                    "sha256": fdata.get("sha256"),
                    "modified": fdata.get("modified"),
                    "provenance": fdata.get("provenance"),
                }
            )
        user_files.sort(key=lambda f: (f.get("size") or 0), reverse=True)
        files_by_user[username] = user_files

        # link user to each artifact that collected at least one of their files
        linked_artifacts = set()
        for f in user_files:
            for prov in f.get("provenance") or []:
                linked_artifacts.add(f"artifact:{prov['source_file']}")
        for a in linked_artifacts:
            if g.has_node(a):
                edges.append({"source": u, "target": a, "relation": "files_collected_by"})

    return {
        "nodes": nodes,
        "edges": edges,
        "files_by_user": files_by_user,
    }


HTML_TEMPLATE = """<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>Investigation Knowledge Graph</title>
<style>
  body { margin:0; font-family: -apple-system, Segoe UI, Arial, sans-serif; background:#0f1117; color:#e6e6e6; }
  #layout { display:flex; height:100vh; }
  #graph-pane { flex: 1 1 60%; position:relative; border-right:1px solid #2a2d38; }
  #side-pane { flex: 1 1 40%; overflow-y:auto; padding:16px; box-sizing:border-box; }
  canvas { display:block; background:#0f1117; cursor:grab; }
  h2 { margin-top:0; font-size:16px; color:#9fd3ff; }
  input[type=text] { width:100%; padding:8px; box-sizing:border-box; background:#1b1e29; color:#eee; border:1px solid #333; border-radius:4px; margin-bottom:10px; }
  table { width:100%; border-collapse:collapse; font-size:12px; }
  th, td { text-align:left; padding:4px 6px; border-bottom:1px solid #24262f; word-break:break-all; }
  th { color:#9fd3ff; position:sticky; top:0; background:#0f1117; }
  .legend { position:absolute; top:10px; left:10px; font-size:12px; background:rgba(20,22,30,0.85); padding:8px 12px; border-radius:6px; }
  .dot { display:inline-block; width:10px; height:10px; border-radius:50%; margin-right:6px; }
  .empty { color:#888; font-size:13px; }
  .path { font-family: Consolas, monospace; font-size:11px; color:#cdeaff; }
  .prov { font-size:10px; color:#888; }
</style>
</head>
<body>
<div id="layout">
  <div id="graph-pane">
    <div class="legend">
      <div><span class="dot" style="background:#ff9d5c"></span>host</div>
      <div><span class="dot" style="background:#6fd08c"></span>user (click to see files)</div>
      <div><span class="dot" style="background:#7aa6ff"></span>collecting artifact</div>
    </div>
    <canvas id="cv"></canvas>
  </div>
  <div id="side-pane">
    <h2>Files</h2>
    <div class="empty">Click a user node to list their files.</div>
  </div>
</div>
<script>
const DATA = __DATA_JSON__;

const colors = { host: "#ff9d5c", user: "#6fd08c", artifact: "#7aa6ff" };
const radii = { host: 16, user: 12, artifact: 12 };

const canvas = document.getElementById("cv");
const ctx = canvas.getContext("2d");
function resize() {
  canvas.width = document.getElementById("graph-pane").clientWidth;
  canvas.height = document.getElementById("graph-pane").clientHeight;
}
resize();
window.addEventListener("resize", resize);

// simple force layout
const nodes = DATA.nodes.map((n, i) => ({
  ...n,
  x: canvas.width/2 + Math.cos(i) * 200,
  y: canvas.height/2 + Math.sin(i) * 200,
  vx: 0, vy: 0,
}));
const nodeById = Object.fromEntries(nodes.map(n => [n.id, n]));
const edges = DATA.edges.filter(e => nodeById[e.source] && nodeById[e.target]);

function step() {
  const cx = canvas.width/2, cy = canvas.height/2;
  for (const n of nodes) {
    n.vx += (cx - n.x) * 0.0015;
    n.vy += (cy - n.y) * 0.0015;
  }
  for (let i=0;i<nodes.length;i++) {
    for (let j=i+1;j<nodes.length;j++) {
      const a = nodes[i], b = nodes[j];
      let dx = a.x - b.x, dy = a.y - b.y;
      let d2 = dx*dx + dy*dy || 0.01;
      let d = Math.sqrt(d2);
      let force = 2500 / d2;
      dx /= d; dy /= d;
      a.vx += dx * force; a.vy += dy * force;
      b.vx -= dx * force; b.vy -= dy * force;
    }
  }
  for (const e of edges) {
    const a = nodeById[e.source], b = nodeById[e.target];
    let dx = b.x - a.x, dy = b.y - a.y;
    let d = Math.sqrt(dx*dx+dy*dy) || 0.01;
    const target = 140;
    const force = (d - target) * 0.02;
    dx /= d; dy /= d;
    a.vx += dx*force; a.vy += dy*force;
    b.vx -= dx*force; b.vy -= dy*force;
  }
  for (const n of nodes) {
    n.vx *= 0.85; n.vy *= 0.85;
    n.x += n.vx; n.y += n.vy;
  }
}

function draw() {
  ctx.clearRect(0,0,canvas.width,canvas.height);
  ctx.strokeStyle = "rgba(255,255,255,0.15)";
  for (const e of edges) {
    const a = nodeById[e.source], b = nodeById[e.target];
    ctx.beginPath();
    ctx.moveTo(a.x, a.y);
    ctx.lineTo(b.x, b.y);
    ctx.stroke();
  }
  for (const n of nodes) {
    ctx.beginPath();
    ctx.fillStyle = colors[n.kind] || "#999";
    ctx.arc(n.x, n.y, radii[n.kind] || 8, 0, Math.PI*2);
    ctx.fill();
    ctx.fillStyle = "#e6e6e6";
    ctx.font = "11px sans-serif";
    ctx.fillText(n.label, n.x + (radii[n.kind]||8) + 4, n.y + 4);
  }
}

let running = true;
function loop() {
  if (running) step();
  draw();
  requestAnimationFrame(loop);
}
loop();
setTimeout(() => { running = false; }, 4000); // settle then freeze

// dragging
let dragging = null;
canvas.addEventListener("mousedown", (e) => {
  const {x, y} = mousePos(e);
  dragging = nodes.find(n => Math.hypot(n.x-x, n.y-y) < (radii[n.kind]||8)+4);
  if (dragging) { dragging.fixed = true; running = true; }
});
canvas.addEventListener("mousemove", (e) => {
  if (!dragging) return;
  const {x, y} = mousePos(e);
  dragging.x = x; dragging.y = y; dragging.vx = 0; dragging.vy = 0;
});
window.addEventListener("mouseup", () => { dragging = null; });
canvas.addEventListener("click", (e) => {
  const {x, y} = mousePos(e);
  const n = nodes.find(n => Math.hypot(n.x-x, n.y-y) < (radii[n.kind]||8)+4);
  if (n && n.kind === "user") showUserFiles(n);
});
function mousePos(e) {
  const r = canvas.getBoundingClientRect();
  return { x: e.clientX - r.left, y: e.clientY - r.top };
}

function showUserFiles(n) {
  const username = n.id.replace("user:", "");
  const files = DATA.files_by_user[username] || [];
  const pane = document.getElementById("side-pane");
  let rows = files.map(f => `
    <tr>
      <td class="path">${escapeHtml(f.path)}</td>
      <td>${f.size ?? ""}</td>
      <td>${escapeHtml(f.modified || "")}</td>
    </tr>`).join("");
  pane.innerHTML = `
    <h2>${escapeHtml(username)} — ${files.length} files</h2>
    <input type="text" id="filter" placeholder="Filter by path...">
    <table id="filetable">
      <thead><tr><th>Path</th><th>Size</th><th>Modified</th></tr></thead>
      <tbody>${rows}</tbody>
    </table>`;
  document.getElementById("filter").addEventListener("input", (e) => {
    const q = e.target.value.toLowerCase();
    for (const tr of document.querySelectorAll("#filetable tbody tr")) {
      tr.style.display = tr.textContent.toLowerCase().includes(q) ? "" : "none";
    }
  });
}
function escapeHtml(s) {
  return (s || "").replace(/[&<>"]/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;","\\"":"&quot;"}[c]));
}
</script>
</body>
</html>
"""


def write_html_viewer(case_root: Path, normalized_dir: Path, out_path: Path) -> Path:
    data = build_viewer_data(case_root, normalized_dir)
    html = HTML_TEMPLATE.replace("__DATA_JSON__", json.dumps(data))
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(html, encoding="utf-8")
    return out_path


if __name__ == "__main__":
    import sys

    case_root = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(
        "TriDsk-WKS02-C.1dfcd21bd3d01cc0-F.D3JVHAK4B16NM"
    )
    normalized_dir = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("data/normalized")
    out_path = Path(sys.argv[3]) if len(sys.argv) > 3 else Path("data/graph/graph_viewer.html")
    p = write_html_viewer(case_root, normalized_dir, out_path)
    print(f"Wrote {p}")
