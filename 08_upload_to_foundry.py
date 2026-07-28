# python 08_upload_to_foundry.py
"""Step 8: upload the bundle to Azure AI Foundry and wire up the agent.

Usage:
    python 08_upload_to_foundry.py [--bundle DIR] [--name NAME] [--replace]

Uploads every file in ``data/foundry_upload/`` to a single vector store, then
creates a file-search agent grounded on it. Re-run after regenerating the
bundle; ``--replace`` tears down the previous vector store and agent first so
you do not accumulate orphaned copies of the evidence.

Prerequisites:
    pip install azure-ai-agents azure-identity
    az login
    set PROJECT_ENDPOINT=https://<resource>.services.ai.azure.com/api/projects/<project>
    set MODEL_DEPLOYMENT_NAME=<your model deployment, e.g. gpt-4.1>

The endpoint is on your Foundry project's overview page under "Project details".
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

DEFAULT_BUNDLE = Path("data/foundry_upload")
# Records what was created, so --replace can clean up on the next run.
STATE_FILE = Path("data/foundry_upload/.deployment.json")

INSTRUCTIONS = """\
You are a digital-forensics analyst answering questions about a single Windows \
endpoint (TriDsk-WKS02) from a Velociraptor/KAPE collection.

Your evidence is the uploaded files. Each is one normalized dataset; every \
record has the same schema:
  record_id, dataset, source_file, evidence_type, timestamp (UTC ISO-8601),
  identifiers, path, original_data

Read _manifest.json first: it lists what each file contains and which questions \
it bears on. QUESTIONS.md holds the question set.

Rules you must follow:
1. Ground every answer in specific records. Cite the record_id and dataset for
   each claim.
2. If no record supports an answer, say "insufficient evidence" and name the
   artifact that would have been needed. Never infer a value that no record
   contains, and never fill a gap with general knowledge about malware families.
3. Some files are filtered subsets. Check dataset.foundry_reduction before
   concluding that something is absent — "not in this file" is not "not on the
   endpoint".
4. Report all times in UTC, as stored.
5. When several records conflict, show both and say which artifact is more
   reliable and why.
"""


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description="Upload the bundle to Azure AI Foundry")
    parser.add_argument("--bundle", type=Path, default=DEFAULT_BUNDLE)
    parser.add_argument("--name", default="forensic-collection")
    parser.add_argument(
        "--replace",
        action="store_true",
        help="delete the vector store and agent from the previous run first",
    )
    return parser.parse_args(argv)


def _load_state() -> dict:
    """Read the previous run's created-resource ids, if any."""
    if not STATE_FILE.is_file():
        return {}
    try:
        with STATE_FILE.open(encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, ValueError):
        return {}


def _teardown(client, state: dict) -> None:
    """Delete the resources a previous run created, ignoring what is gone."""
    for kind, delete in (
        ("agent_id", lambda i: client.delete_agent(i)),
        ("vector_store_id", lambda i: client.vector_stores.delete(i)),
    ):
        resource_id = state.get(kind)
        if not resource_id:
            continue
        try:
            delete(resource_id)
            print(f"  deleted previous {kind}: {resource_id}")
        except Exception as exc:  # noqa: BLE001 - cleanup must not block the run
            print(f"  could not delete previous {kind} ({resource_id}): {exc}")

    for file_id in state.get("file_ids", []):
        try:
            client.files.delete(file_id=file_id)
        except Exception:  # noqa: BLE001, S110 - already gone is fine
            pass


def main(argv: list[str] | None = None) -> int:
    """Upload the bundle, build the vector store, and create the agent."""
    args = parse_args(argv)

    try:
        from azure.ai.agents import AgentsClient
        from azure.ai.agents.models import FilePurpose, FileSearchTool
        from azure.identity import DefaultAzureCredential
    except ImportError:
        print(
            "error: missing SDK. Install it with:\n"
            "  pip install azure-ai-agents azure-identity",
            file=sys.stderr,
        )
        return 1

    endpoint = os.environ.get("PROJECT_ENDPOINT")
    model = os.environ.get("MODEL_DEPLOYMENT_NAME")
    if not endpoint or not model:
        print(
            "error: set PROJECT_ENDPOINT and MODEL_DEPLOYMENT_NAME first.\n"
            "  PROJECT_ENDPOINT is on your Foundry project overview page.\n"
            "  MODEL_DEPLOYMENT_NAME is your deployed model's name.",
            file=sys.stderr,
        )
        return 1

    files = sorted(p for p in args.bundle.iterdir() if p.is_file() and not p.name.startswith("."))
    if not files:
        print(
            f"error: no files in {args.bundle}\n"
            "build the bundle first:  python 06_build_foundry_bundle.py",
            file=sys.stderr,
        )
        return 1

    client = AgentsClient(endpoint=endpoint, credential=DefaultAzureCredential())

    with client:
        if args.replace:
            print("Removing the previous deployment ...")
            _teardown(client, _load_state())

        total_mb = sum(p.stat().st_size for p in files) / (1024 * 1024)
        print(f"\nUploading {len(files)} file(s), {total_mb:.1f} MB ...")
        file_ids = []
        for path in files:
            size_mb = path.stat().st_size / (1024 * 1024)
            print(f"  {path.name:<32}{size_mb:>7.2f} MB ... ", end="", flush=True)
            uploaded = client.files.upload_and_poll(
                file_path=str(path), purpose=FilePurpose.AGENTS
            )
            file_ids.append(uploaded.id)
            print(uploaded.id)

        print(f"\nCreating vector store '{args.name}' (chunking + embedding) ...")
        vector_store = client.vector_stores.create_and_poll(
            file_ids=file_ids, name=args.name
        )
        print(f"  vector store: {vector_store.id}")

        file_search = FileSearchTool(vector_store_ids=[vector_store.id])
        agent = client.create_agent(
            model=model,
            name=f"{args.name}-analyst",
            instructions=INSTRUCTIONS,
            tools=file_search.definitions,
            tool_resources=file_search.resources,
        )
        print(f"  agent:        {agent.id}")

    state = {
        "agent_id": agent.id,
        "vector_store_id": vector_store.id,
        "file_ids": file_ids,
        "endpoint": endpoint,
        "model": model,
    }
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    with STATE_FILE.open("w", encoding="utf-8") as handle:
        json.dump(state, handle, indent=2)

    print(
        f"\nDone. Open the agent in the Foundry portal (Agents -> {agent.id}) "
        "and ask it the questions from QUESTIONS.md."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
