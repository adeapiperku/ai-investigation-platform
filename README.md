# AI-Assisted Investigation Platform

Turns a messy Velociraptor / KapeFiles forensic collection into **twelve
independently normalized datasets**, a knowledge graph, and an
**evidence-grounded agent** — every answer cites the exact record it came from,
and the agent never invents evidence.

---

## The core idea: normalize each dataset on its own

The collection is not one dataset. It is twelve, each with its own structure,
timestamp convention and meaning — client metadata, collection logs, upload
manifests, browser history, OneDrive sync logs, shell links, registry hives.

Each one is normalized **separately, into its own file**, all sharing one record
schema:

```json
{
  "record_id":     "browser_downloads:10:e0ed04bc3cab",
  "dataset":       "browser_downloads",
  "source_file":   "uploads/auto/C%3A/Users/yscott/.../History",
  "evidence_type": "browser_download",
  "timestamp":     "2025-10-08T15:14:17.112612Z",
  "identifiers":   { "url": "...", "username": "yscott", "file_path": "..." },
  "path":          { "drive": "C:", "directory": "Users/yscott/Downloads", "...": "..." },
  "original_data": { "...": "the dataset's own payload" }
}
```

Same shape everywhere, so the records are comparable — but never concatenated on
disk. That buys three things: a corrupt source file costs you one dataset
instead of the whole run; re-normalizing one dataset takes seconds
(`--only browser_downloads`); and each file is small enough to upload to a
retrieval index on its own.

---

## How to run

```bash
python -m venv .venv
```

```bash
.venv\Scripts\activate
```

```bash
pip install -r requirements.txt
```

Run these from the project root, in order:

```bash
python 01_normalize_datasets.py
```

```bash
python 02_build_knowledge_graph.py
```

```bash
python 03_detect_anomalies.py
```

```bash
python 04_answer_questions.py
```

```bash
python 05_export_graph_html.py
```

```bash
python 06_build_foundry_bundle.py
```

Order matters — each step reads the previous step's output.

Useful flags:

```bash
python 01_normalize_datasets.py --list
```

```bash
python 01_normalize_datasets.py --only browser_downloads
```

```bash
python 04_answer_questions.py --interactive
```

Step 5 writes `data/processed/knowledge_graph.html` — open it in any browser (no
internet needed): scroll to zoom, drag to pan, hover for details, click a legend
row to hide a type.

---

## The dataset catalogue

Defined in `src/11_dataset_registry.py`. Adding a new evidence source means
adding one `DatasetSpec` — no other stage changes.

| Dataset | Evidence | Source | Bears on |
|---|---|---|---|
| `client_info` | endpoint + IR agent identity | `client_info.json` | Q1 |
| `collection_context` | what was collected, when | `collection_context.json` | Q1 |
| `collection_log` | collector execution log | `log.json` | — |
| `collection_requests` | server-side artifact request | `requests.json` | — |
| `upload_transcript` | per-file upload stream | `uploads.json` | — |
| `file_metadata` | MACB + size for every matched file | KAPE *All File Metadata* | Q10, Q11 |
| `upload_manifest` | collected files + SHA-256 | KAPE *Uploads* | Q10 |
| `browser_history` | Edge visited URLs | Edge `History` SQLite | Q3, Q5, Q6 |
| `browser_downloads` | downloads + full redirect chain | Edge `History` SQLite | Q3, Q5, Q9 |
| `onedrive_sync` | OneDrive ODL sync logs | `*.odl` / `*.odlgz` | Q9, Q10, Q11 |
| `shell_links` | shortcuts / jump lists | `*.lnk` | Q2, Q10, Q13 |
| `registry_user` | logon, UserAssist, RecentDocs, persistence | `NTUSER.DAT`, `UsrClass.dat` | Q2, Q12, Q13 |

Two more are **derived** from the datasets above rather than from a raw source
(`src/17_derived_datasets.py`), because each is real evidence that is invisible
while spread across 26 000 rows of a bulk dataset:

| Dataset | Evidence | Derived from | Bears on |
|---|---|---|---|
| `program_execution` | what ran on this host and when, from Prefetch file metadata | `file_metadata` | Q1, Q2, Q12, Q13 |
| `collection_gap` | files Velociraptor collected that are **absent from this extract** | `upload_manifest` + disk | Q4, Q5, Q7, Q8, Q12, Q13 |

`collection_gap` exists because 14 493 of the 26 362 collected files did not
survive into this copy. Without it an analyst cannot distinguish "this file
never existed" from "this file was collected and lost in transit" — and will
report absence of evidence as evidence of absence.

The binary parsers are **standard library only** — no `python-evtx`,
`python-registry` or `LnkParse3` required.

See [QUESTIONS.md](QUESTIONS.md) for the question set itself.

---

## What each step produces

| Step | Script | Output |
|---|---|---|
| 1 | `01_normalize_datasets.py` | `data/normalized/<dataset>.normalized.json` ×12 + `_manifest.json` |
| 2 | `02_build_knowledge_graph.py` | `data/processed/knowledge_graph.json` |
| 3 | `03_detect_anomalies.py` | `data/processed/cleaned_dataset.json` |
| 4 | `04_answer_questions.py` | prints answers (`--json` writes `answers.json`) |
| 5 | `05_export_graph_html.py` | `data/processed/knowledge_graph.html` |
| 6 | `06_build_foundry_bundle.py` | `data/foundry_upload/` — the agent upload set |

Steps 2–4 combine the datasets **in memory** via `src/15_normalized_loader.py`.
Nothing merges them on disk.

---

## Uploading to Azure AI Foundry

`python 06_build_foundry_bundle.py` writes `data/foundry_upload/`. Upload
**every file in that directory** to the agent's vector store (file search):

| File | Records | ~MB |
|---|---|---|
| `_manifest.json` | — | 0.01 |
| `QUESTIONS.md` | — | 0.01 |
| `client_info.json` | 1 | 0.00 |
| `collection_context.json` | 1 | 0.00 |
| `collection_requests.json` | 1 | 0.30 |
| `collection_log.json` | 2 340 | 1.56 |
| `browser_downloads.json` | 13 | 0.02 |
| `registry_user.json` | 63 | 0.10 |
| `browser_history.json` | 177 | 0.21 |
| `onedrive_sync.json` | 181 | 0.78 |
| `shell_links.json` | 268 | 0.29 |
| `upload_transcript.json` | 14 706 | 14.34 |
| `file_metadata.json` | 15 804 | 18.37 |
| `upload_manifest.json` | 15 804 | 22.83 |

**≈59 MB across 14 files.** The three bulk datasets are reduced to the
investigation-relevant subset (user / ProgramData / Temp / Downloads / OneDrive
paths with execution-, delivery- or credential-relevant extensions, plus every
record carrying a URL, IP or CVE; Windows servicing noise dropped). Each reduced
file records how many records were dropped and by what rule, inside
`dataset.foundry_reduction` — a filtered file never poses as complete evidence.

`_manifest.json` carries the shared record schema, a description of every file
and the grounding rule. Point the agent's system prompt at it.

### For the code interpreter tool: `--csv`

```bash
python 06_build_foundry_bundle.py --csv
```

Writes `data/foundry_upload_csv/` — every dataset as a **complete, unfiltered**
CSV, ~33 MB total against 94 MB of JSON. Code interpreter reads files instead of
embedding them, so there is no reason to filter, and pandas reads CSV natively.

Two column-level reductions, both recorded in `_manifest.json` so nothing is
lost:

- **`constant_columns`** — a column with one identical value on every row is
  stored once in the manifest instead of 26 000 times in the file.
- **`aliased_columns`** — `{dropped: equivalent}`. A column that duplicated
  another on *every* row is dropped; read the named column instead. One
  divergent row anywhere keeps the column, because a `Modified` that usually
  matches `Created` but differs once is exactly the row that matters.

Cells are never blanked for deduplication: **a blank cell means absent.**

Use both bundles together — CSVs on code interpreter for ordering, counting and
filtering; the JSON set on file search for semantic lookup and citations.

---

## Project structure

```
ai-investigation-platform/
├── data/
│   ├── raw/              # input: the forensic collection
│   ├── normalized/       # step 1: one file per dataset  <-- the deliverable
│   ├── processed/        # steps 2-3: graph + cleaned view
│   └── foundry_upload/   # step 6: the Azure AI Foundry upload set
├── src/
│   ├── 01_loaders.py             # structure-tolerant JSON/JSONL loading
│   ├── 02_normalizers.py         # timestamp + path normalization
│   ├── 03_extractors.py          # correlation identifiers
│   ├── 04_validators.py          # data-quality checks
│   ├── 05_dataset_builder.py     # per-dataset normalization
│   ├── 06_graph_schema.py        # graph vocabulary
│   ├── 07_graph_model.py         # in-memory graph
│   ├── 08_graph_builder.py       # build the graph
│   ├── 09_anomaly_detector.py    # dedupe + flag anomalies
│   ├── 10_artifact_parser.py     # Edge History (SQLite)
│   ├── 11_dataset_registry.py    # the dataset catalogue  <-- start here
│   ├── 12_lnk_parser.py          # shell links (MS-SHLLINK)
│   ├── 13_onedrive_parser.py     # OneDrive ODL sync logs
│   ├── 14_registry_parser.py     # regf hives (nk/vk/lf/lh/li/ri)
│   ├── 15_normalized_loader.py   # read the per-dataset files back
│   └── 16_foundry_bundle.py      # build the upload set
├── QUESTIONS.md
└── 01_normalize_datasets.py … 07_forensic_report.py
```

---

## Known limits

- The local agent (`04_answer_questions.py`) has hand-written resolvers for
  Q1–Q4 only. Q5–Q13 are for the Foundry agent to answer over the uploaded
  datasets; this script reports "insufficient evidence" rather than guessing.
- ODL logs are recovered by inflation plus string extraction. Full field
  decoding needs the per-build `ObfuscationStringMap`, which this collection
  does not contain — so ODL records are reported as recovered strings, URLs and
  paths, never as decoded events.
- No `Security.evtx`, prefetch or `$MFT` was collected, so execution and logon
  timelines rest on registry UserAssist, shell links and file MACB times.
