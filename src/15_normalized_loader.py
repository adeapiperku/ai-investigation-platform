"""Reading the per-dataset normalized files back in.

Normalization writes one file per dataset. The graph, cleaning and agent stages
work across evidence types, so they need a combined view — but the combining
happens **here, in memory, at read time**, not on disk. The normalized files
stay separate and independently regenerable.

Callers can narrow to the datasets they care about, which is the point of
splitting them: answering "what did the user download" reads one small file.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

# Written alongside the dataset files by the normalization step.
MANIFEST_NAME = "_manifest.json"
DATASET_SUFFIX = ".normalized.json"


def dataset_files(normalized_dir: Path) -> List[Path]:
    """List every per-dataset normalized file, in catalogue order when known."""
    files = sorted(normalized_dir.glob(f"*{DATASET_SUFFIX}"))
    manifest = normalized_dir / MANIFEST_NAME
    if not manifest.is_file():
        return files

    try:
        with manifest.open(encoding="utf-8") as handle:
            order = [entry["name"] for entry in json.load(handle).get("datasets", [])]
    except (OSError, ValueError, KeyError, TypeError):
        return files

    by_name = {path.name[: -len(DATASET_SUFFIX)]: path for path in files}
    ordered = [by_name.pop(name) for name in order if name in by_name]
    return ordered + sorted(by_name.values())


def load_dataset(path: Path) -> Dict[str, Any]:
    """Load one normalized dataset document."""
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def load_normalized(
    normalized_dir: Path, only: Optional[Iterable[str]] = None
) -> Dict[str, Any]:
    """Load the normalized datasets into one combined in-memory dataset.

    ``only`` restricts the load to named datasets. The returned structure keeps
    the ``normalized_records`` key the downstream stages expect, plus a
    ``datasets`` map describing what was combined and where each record's
    dataset boundary lies.
    """
    wanted = set(only) if only is not None else None

    records: List[Dict[str, Any]] = []
    problems: List[Dict[str, Any]] = []
    descriptors: List[Dict[str, Any]] = []

    for path in dataset_files(normalized_dir):
        name = path.name[: -len(DATASET_SUFFIX)]
        if wanted is not None and name not in wanted:
            continue
        document = load_dataset(path)
        descriptor = dict(document.get("dataset", {}))
        descriptor["summary"] = document.get("summary", {})
        descriptor["file"] = path.name
        descriptors.append(descriptor)
        records.extend(document.get("records", []))
        problems.extend(document.get("collection_problems", []))

    return {
        "dataset_metadata": {
            "phase": "Phase 1 - Per-dataset normalization",
            "normalized_dir": str(normalized_dir),
            "datasets": descriptors,
            "num_datasets": len(descriptors),
        },
        "collection_problems": problems,
        "normalized_records": records,
    }


def require_normalized(normalized_dir: Path) -> Dict[str, Any]:
    """Load the normalized datasets, raising a clear error when absent."""
    if not normalized_dir.is_dir() or not dataset_files(normalized_dir):
        raise FileNotFoundError(
            f"no normalized datasets in {normalized_dir}\n"
            "run normalization first:  python 01_normalize_datasets.py"
        )
    return load_normalized(normalized_dir)
