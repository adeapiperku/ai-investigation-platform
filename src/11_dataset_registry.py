"""The dataset catalogue: what a *dataset* is, and how each one is read.

The collection is not one dataset — it is twelve, each with its own structure,
timestamp convention and meaning. This module names them explicitly and gives
each one a discovery function and a reader. The builder then normalizes them
**one at a time**, into one shared record schema, writing one output file per
dataset. Nothing is concatenated: a question about browser downloads reads the
browser-download dataset, not a 160 MB haystack.

Adding a new evidence source means adding one :class:`DatasetSpec` here — the
builder, graph, cleaner and agent stages need no changes.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Tuple

from .artifact_parser import (
    collect_browser_downloads,
    collect_browser_history,
    discover_browser_history,
)
from .loaders import CollectionProblem, load_file
from .lnk_parser import collect_lnk_records
from .onedrive_parser import collect_onedrive_records
from .registry_parser import collect_registry_records

# A reader takes the discovered files plus the raw root and returns
# (raw payload dicts, collection problems).
Reader = Callable[[List[Path], Path], Tuple[List[Dict[str, Any]], List[CollectionProblem]]]
Discoverer = Callable[[Path], List[Path]]


@dataclass(frozen=True)
class DatasetSpec:
    """One logical dataset: where it lives, how to read it, what it means."""

    name: str
    evidence_type: str
    description: str
    discover: Discoverer
    read: Reader
    # Where this dataset comes from. "endpoint_evidence" describes the machine
    # under investigation. "collection_tooling" describes the *collector* — its
    # request, its configuration, its own log. The distinction matters: KAPE's
    # target definitions quote CVE numbers and URLs in their description text
    # ("Payloads for CVE-2022-30190 ('Follina') will be in this log"), and those
    # strings appear in every collection ever taken, on clean and infected hosts
    # alike. Scraping them as indicators manufactures evidence, so identifier
    # extraction is suppressed for tooling datasets.
    provenance: str = "endpoint_evidence"
    # Which questions this dataset is expected to bear on (see QUESTIONS.md).
    answers_questions: Tuple[int, ...] = ()
    # Fields to drop from every record's payload: high-volume, low-signal noise.
    drop_fields: Tuple[str, ...] = ()
    # How this dataset is treated when building the Azure AI Foundry bundle:
    # "full" ships every record, "filtered" ships only the relevant subset.
    foundry: str = "full"


# --------------------------------------------------------------------------- #
# Discovery helpers
# --------------------------------------------------------------------------- #


def _exact(relative: str) -> Discoverer:
    """Discover a single known file, relative to the raw root."""

    def discover(raw_dir: Path) -> List[Path]:
        path = raw_dir / relative
        return [path] if path.is_file() else []

    return discover


def _by_suffix(*suffixes: str, under: str = "uploads") -> Discoverer:
    """Discover every file under ``under`` whose suffix matches."""
    wanted = {s.lower() for s in suffixes}

    def discover(raw_dir: Path) -> List[Path]:
        base = raw_dir / under
        if not base.is_dir():
            return []
        return sorted(
            p for p in base.rglob("*") if p.is_file() and p.suffix.lower() in wanted
        )

    return discover


def _by_name(*names: str, under: str = "uploads") -> Discoverer:
    """Discover every file under ``under`` whose filename matches."""
    wanted = {n.lower() for n in names}

    def discover(raw_dir: Path) -> List[Path]:
        base = raw_dir / under
        if not base.is_dir():
            return []
        return sorted(p for p in base.rglob("*") if p.is_file() and p.name.lower() in wanted)

    return discover


# --------------------------------------------------------------------------- #
# Readers for the structured (JSON/JSONL) datasets
# --------------------------------------------------------------------------- #


def _read_json(files: List[Path], root: Path) -> Tuple[List[Dict[str, Any]], List[CollectionProblem]]:
    """Read JSON / JSONL files with the structure-tolerant loader.

    Every record is tagged with ``_artifact_source`` so the builder can attribute
    it to its file uniformly, exactly as the binary-artifact readers do.
    """
    records: List[Dict[str, Any]] = []
    problems: List[CollectionProblem] = []
    for path in files:
        loaded = load_file(path, root)
        try:
            source = path.relative_to(root).as_posix()
        except ValueError:
            source = path.name
        records.extend({**record, "_artifact_source": source} for record in loaded.records)
        problems.extend(loaded.problems)
    return records, problems


# --------------------------------------------------------------------------- #
# The catalogue
# --------------------------------------------------------------------------- #

DATASETS: Tuple[DatasetSpec, ...] = (
    DatasetSpec(
        name="client_info",
        evidence_type="client_info",
        description=(
            "Velociraptor's record of the endpoint itself: hostname, FQDN, OS "
            "build, network identity, and the IR agent's name and version."
        ),
        discover=_exact("client_info.json"),
        read=_read_json,
        answers_questions=(1,),
    ),
    DatasetSpec(
        name="collection_context",
        provenance="collection_tooling",
        evidence_type="collection_context",
        description=(
            "The collection request and its outcome: which artifacts were asked "
            "for, when the collection ran, and how much it actually retrieved."
        ),
        discover=_exact("collection_context.json"),
        read=_read_json,
        answers_questions=(1,),
    ),
    DatasetSpec(
        name="collection_log",
        provenance="collection_tooling",
        evidence_type="log_entry",
        description="Per-line execution log emitted by the collector on the endpoint.",
        discover=_exact("log.json"),
        read=_read_json,
    ),
    DatasetSpec(
        name="collection_requests",
        provenance="collection_tooling",
        evidence_type="flow_request",
        description="The artifact request(s) sent to the endpoint by the server.",
        discover=_exact("requests.json"),
        read=_read_json,
    ),
    DatasetSpec(
        name="upload_transcript",
        evidence_type="upload_event",
        description=(
            "One row per file the collector streamed off the endpoint, with the "
            "source path, accessor and byte counts."
        ),
        discover=_exact("uploads.json"),
        read=_read_json,
        drop_fields=("_Components", "_client_components"),
        foundry="filtered",
    ),
    DatasetSpec(
        name="file_metadata",
        evidence_type="file_metadata",
        description=(
            "MACB timestamps and size for every file the KAPE targets matched. "
            "The timeline backbone: when files appeared, changed and were touched."
        ),
        discover=_exact("results/Windows.KapeFiles.Targets%2FAll File Metadata.json"),
        read=_read_json,
        answers_questions=(10, 11),
        foundry="filtered",
    ),
    DatasetSpec(
        name="upload_manifest",
        evidence_type="uploaded_file",
        description=(
            "The collected-file manifest: source path, destination path, size and "
            "SHA-256 for every artifact preserved by the collection."
        ),
        discover=_exact("results/Windows.KapeFiles.Targets%2FUploads.json"),
        read=_read_json,
        answers_questions=(10,),
        foundry="filtered",
    ),
    DatasetSpec(
        name="browser_history",
        evidence_type="browser_history",
        description=(
            "Edge/Chromium visited-URL history per user profile, with visit and "
            "typed counts and the last visit time."
        ),
        discover=discover_browser_history,
        read=collect_browser_history,
        answers_questions=(3, 5, 6),
    ),
    DatasetSpec(
        name="browser_downloads",
        evidence_type="browser_download",
        description=(
            "Edge/Chromium download records including the full redirect chain, "
            "referrer, target path on disk and byte counts."
        ),
        discover=discover_browser_history,
        read=collect_browser_downloads,
        answers_questions=(3, 5, 9),
    ),
    DatasetSpec(
        name="onedrive_sync",
        evidence_type="cloud_sync_log",
        description=(
            "OneDrive ODL sync logs, inflated and mined for the URLs, paths and "
            "filenames the sync client handled — the cloud-push evidence."
        ),
        discover=_by_suffix(".odl", ".odlgz", ".aodl", ".aodlgz"),
        read=collect_onedrive_records,
        answers_questions=(9, 10, 11),
    ),
    DatasetSpec(
        name="shell_links",
        evidence_type="shell_link",
        description=(
            "Shortcut (.lnk) and jump-list evidence of files the user opened, "
            "carrying each target's path and its MACB times at that moment."
        ),
        discover=_by_suffix(".lnk"),
        read=collect_lnk_records,
        answers_questions=(2, 10, 13),
    ),
    DatasetSpec(
        name="registry_user",
        evidence_type="registry_key",
        description=(
            "Keys of interest from the collected NTUSER.DAT / UsrClass.dat hives: "
            "logon session, UserAssist execution, RecentDocs, RunMRU, persistence."
        ),
        discover=_by_name("ntuser.dat", "usrclass.dat"),
        read=collect_registry_records,
        answers_questions=(2, 12, 13),
    ),
)


DATASETS_BY_NAME: Dict[str, DatasetSpec] = {spec.name: spec for spec in DATASETS}


def get_dataset(name: str) -> DatasetSpec:
    """Look up a dataset spec by name, raising ``KeyError`` when unknown."""
    return DATASETS_BY_NAME[name]
