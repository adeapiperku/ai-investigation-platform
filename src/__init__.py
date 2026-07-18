"""Investigation platform package.

The module files in this package are prefixed with a two-digit number that
reflects the order in which the pipeline uses them (``01_loaders`` runs first,
``09_anomaly_detector`` last). A numeric prefix is not a valid Python module
name, so this loader registers each numbered file under its clean name
(``src.loaders``, ``src.normalizers``, ...). That keeps every import such as
``from src.loaders import load_file`` or ``from .normalizers import
normalize_path`` working exactly as before, while the folder listing shows the
execution order at a glance.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

# Clean import name -> numbered file, in pipeline / dependency order. Each
# module is executed after the ones it depends on, so ordinary relative
# imports inside the numbered files resolve against sys.modules.
_MODULES = [
    ("loaders", "01_loaders.py"),
    ("normalizers", "02_normalizers.py"),
    ("extractors", "03_extractors.py"),
    ("validators", "04_validators.py"),
    ("dataset_builder", "05_dataset_builder.py"),
    ("graph_schema", "06_graph_schema.py"),
    ("graph_model", "07_graph_model.py"),
    ("graph_builder", "08_graph_builder.py"),
    ("anomaly_detector", "09_anomaly_detector.py"),
    ("artifact_parser", "10_artifact_parser.py"),
]

_here = Path(__file__).resolve().parent


def _load_numbered_modules() -> None:
    """Register each numbered file under its clean ``src.<name>`` import path."""
    package = sys.modules[__name__]
    for name, filename in _MODULES:
        qualified = f"{__name__}.{name}"
        if qualified in sys.modules:
            continue
        spec = importlib.util.spec_from_file_location(qualified, _here / filename)
        if spec is None or spec.loader is None:  # pragma: no cover - defensive
            raise ImportError(f"cannot load {filename}")
        module = importlib.util.module_from_spec(spec)
        # Register before execution so relative imports resolve immediately.
        sys.modules[qualified] = module
        setattr(package, name, module)
        spec.loader.exec_module(module)


_load_numbered_modules()
