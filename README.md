# AI Investigation Platform

A small pipeline for turning a raw Velociraptor/KAPE forensic collection
into clean, correlated data an investigator (or an AI agent) can query
without ever guessing at facts.

## What's been done so far

1. **Understood the raw data.** The folder `TriDsk-WKS02-C.1dfcd21bd3d01cc0-F.D3JVHAK4B16NM/`
   is a real forensic evidence collection from one Windows workstation.
   It contains several different JSON file types (client info, collection
   log, file metadata, upload records) that don't share a common shape.
   This folder is real evidence (real usernames, real files) and is
   excluded from git via `.gitignore` so it never gets committed.

2. **Parsed every JSON file type.**
   [`src/investigation_platform/parsers.py`](src/investigation_platform/parsers.py)
   reads each file (single JSON object or JSON-Lines) and keeps track of
   exactly which file + line number every record came from, so later
   steps can always point back at the original evidence.

3. **Normalized and deduplicated.**
   [`src/investigation_platform/normalize.py`](src/investigation_platform/normalize.py)
   merges the three file-level sources (file metadata, upload records,
   upload index) into one clean record per unique file path, dropping
   duplicates caused by overlapping collection rules.

   Result: **77,694 raw lines → 25,030 unique files**, 2,778 duplicate
   lines removed. Output: `data/normalized/files.jsonl` (git-ignored,
   contains evidence data).

4. **Detected collection anomalies.**
   [`src/investigation_platform/anomalies.py`](src/investigation_platform/anomalies.py)
   checks the cleaned data for problems and writes `data/reports/anomalies.json`
   (git-ignored). Findings on this case:

   - **Collection was incomplete**: only 82.76% of expected data was
     actually collected (4.55 GB out of 5.50 GB expected — 947 MB missing).
   - **119 files** have a size mismatch between what was expected and what
     was actually uploaded (partial/truncated copies).
   - **50 files** appear in the upload records but have no matching file
     metadata record (worth a closer look).
   - **7 log entries** flagged as non-default level, but all are benign
     internal engine notices (worker startup, tempfile buffering), not
     real errors — no fatal failures found in the collection log.

   Every finding above links back to the exact source file + line number
   it came from, so nothing here is a guess.

5. **Built a knowledge graph.**
   [`src/investigation_platform/graph.py`](src/investigation_platform/graph.py)
   turns the normalized files into a graph: `host -> user profile -> file
   -> collecting artifact`. This is what lets later questions like "what
   files belong to user X" be answered by walking real edges instead of
   guessing.

   Result on this case: **25,040 nodes / 99,072 edges** — 1 host, 6 real
   user profiles found (`Abdallah.Kh`, `administrator`, `dallen`, `it01`,
   `wayne`, `yscott`), 25,030 files, 3 collecting artifacts. System/default
   folders (Public, Default, defaultuser0) are excluded since they aren't
   real people. Exported to `data/graph/knowledge_graph.graphml` (git-ignored).

6. **Built the AI agent's query tools.**
   [`src/investigation_platform/agent.py`](src/investigation_platform/agent.py)
   gives an agent a fixed set of "tools" (list users, files by user,
   collection completeness, size mismatches, log problems, anomaly
   summary) that only ever return facts pulled straight from the
   normalized data / graph / anomaly report, each with its source
   attached. A real LLM can sit on top of these as function-calling
   tools to phrase natural answers, but it can only state what a tool
   actually returned — nothing is invented. Tested with real questions
   ("how complete was the collection?", "which users are on this
   machine?", "what files belong to wayne?") — all answered correctly
   with citations back to specific source file + line numbers.

7. **Added a browser-viewable graph.**
   [`src/investigation_platform/graph_viewer.py`](src/investigation_platform/graph_viewer.py)
   generates `data/graph/graph_viewer.html` (git-ignored) — a single,
   self-contained HTML file (no internet/CDN needed) you can just
   double-click to open. It draws the host → user → artifact skeleton
   as an interactive graph; clicking a user shows their files in a
   searchable table with size, modified time, and provenance. This is
   separate from the full `knowledge_graph.graphml` export (unchanged,
   still there for Gephi/yEd) — the HTML view is for a quick look
   without extra software, since the full graph has 25k+ file nodes and
   isn't readable rendered all at once.

The agent stays terminal-only for now (no Azure/Foundry/hosted API) —
just `agent.py` answering questions locally against the normalized data,
graph, and anomaly report.

## What's next

- Final evidence-based investigation report generation (a written-up
  summary of findings that pulls together anomalies + graph + agent
  answers, still citing sources).

## How to run it

### 1. Create and activate the virtual environment

```
py 3.10 -m venv .venv
.venv\Scripts\activate      # Windows (Git Bash)
pip install -r requirements.txt
```

### 2. Run the pipeline scripts

Each script is a Python **module**, run with `-m` and its dotted module
path (no `.py`, no slashes) — with `src` on `PYTHONPATH` so
`investigation_platform` can be found. Replace `<case_folder>` with your
actual case folder name (e.g. `TriDsk-WKS02-C.1dfcd21bd3d01cc0-F.D3JVHAK4B16NM`).

How you set `PYTHONPATH` depends on your shell:

**cmd.exe** (`VAR=value command` doesn't work here — set it first):
```
set PYTHONPATH=src
python -m investigation_platform.normalize <case_folder> data/normalized
python -m investigation_platform.anomalies <case_folder> data/normalized data/reports
python -m investigation_platform.graph <case_folder> data/normalized data/graph
python -m investigation_platform.agent <case_folder> data/normalized data/reports "your question"
```

**PowerShell:**
```
$env:PYTHONPATH = "src"
python -m investigation_platform.normalize <case_folder> data/normalized
python -m investigation_platform.anomalies <case_folder> data/normalized data/reports
python -m investigation_platform.graph <case_folder> data/normalized data/graph
python -m investigation_platform.agent <case_folder> data/normalized data/reports "your question"
```

`data/normalized` and `data/reports` need to exist (from steps 2 and 4
above) before you can ask the agent questions.
