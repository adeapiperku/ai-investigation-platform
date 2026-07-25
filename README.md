# AI-Assisted Investigation Platform

Turns a messy Velociraptor / KapeFiles forensic collection into normalized data,
a knowledge graph, and an **evidence-grounded agent** that answers investigation
questions — every answer cites the exact record it came from, and the agent never
invents evidence.

---

## How to run

python -m venv .venv

.venv\Scripts\activate

pip install -r requirements.txt

Run these five scripts **from the project root, in order**:

```bash
python 01_build_dataset.py          # normalize all JSON/JSONL evidence
python 02_parse_artifacts.py        # add browser history/downloads (Edge SQLite)
python 03_build_knowledge_graph.py  # build the knowledge graph
python 04_detect_anomalies.py       # remove duplicates + flag anomalies
python 05_answer_questions.py       # answer the investigation questions
python 06_export_graph_html.py      # (optional) interactive HTML of the graph
```

Order matters — each step reads the previous step's output.

Step 6 writes `data/processed/knowledge_graph.html` — open it in any browser
(no internet needed) to explore the graph: scroll to zoom, drag to pan, drag a
node to move it, hover for details, click a legend row to hide a type.

The agent also has extra modes:

```bash
python 05_answer_questions.py --interactive        # ask questions in the terminal
python 05_answer_questions.py "what CVE was used"  # one-off question
python 05_answer_questions.py --json               # also write answers.json
```

---

## What each step produces

| Step | Script | Output |
|------|--------|--------|
| 1 | `01_build_dataset.py` | `data/processed/normalized_dataset.json` |
| 2 | `02_parse_artifacts.py` | (enriches the dataset in place with browser evidence) |
| 3 | `03_build_knowledge_graph.py` | `data/processed/knowledge_graph.json` |
| 4 | `04_detect_anomalies.py` | `data/processed/cleaned_dataset.json` |
| 5 | `05_answer_questions.py` | prints answers (`--json` writes `answers.json`) |
| 6 | `06_export_graph_html.py` | `data/processed/knowledge_graph.html` (optional) |

---

## The investigation answers

| # | Question | Answer |
|---|----------|--------|
| 1 | Incident-response agent name/version | **Velociraptor 0.74.3** |
| 2 | Domain-user login time before infection | **Not in the data** — no event-log/registry logon artifacts were collected, so the agent reports "insufficient evidence" instead of guessing |
| 3 | Malicious repository URL downloaded | **`https://github.com/saqua-ai/sequa-mcp/archive/refs/heads/main.zip`** (typosquat of `sequa-ai`, downloaded by user `yscott`) |
| 4 | CVE that triggered the stealer | **CVE-2022-30190** (Follina / MSDT) |

---

## Project structure

```
ai-investigation-platform/
├── data/
│   ├── raw/         # input: the forensic collection (JSON + collected artifacts)
│   └── processed/   # generated outputs (the 3 JSON files above)
├── src/             # the logic (imported by steps 1–4)
│   ├── 01_loaders.py            # find + parse JSON/JSONL
│   ├── 02_normalizers.py        # normalize timestamps + paths
│   ├── 03_extractors.py         # extract identifiers + evidence type
│   ├── 04_validators.py         # detect collection problems
│   ├── 05_dataset_builder.py    # assemble the normalized dataset
│   ├── 06_graph_schema.py       # graph vocabulary
│   ├── 07_graph_model.py        # in-memory graph
│   ├── 08_graph_builder.py      # build the graph
│   ├── 09_anomaly_detector.py   # remove duplicates + flag anomalies
│   └── 10_artifact_parser.py    # parse Edge History SQLite databases
├── 01_build_dataset.py          # ─┐
├── 02_parse_artifacts.py        #  │ run these five,
├── 03_build_knowledge_graph.py  #  │ in order,
├── 04_detect_anomalies.py       #  │ from the project root
├── 05_answer_questions.py       # ─┘
└── 06_export_graph_html.py      # optional: interactive HTML graph
```

**Steps 1–4 need `src/`** (it holds the actual logic; the numbered root scripts
are thin runners). **Step 5 is standalone** — it only reads the processed JSON.

---
