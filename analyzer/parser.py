"""Input parsing utilities for TXT and CSV IOC datasets."""

from __future__ import annotations

import csv
from pathlib import Path


def _normalize_values(values: list[str]) -> list[str]:
    """Strip whitespace and drop empty entries while preserving order."""
    cleaned: list[str] = []
    for value in values:
        stripped = value.strip()
        if stripped:
            cleaned.append(stripped)
    return cleaned


def load_iocs(path: Path) -> list[str]:
    """Load IOC values from a TXT or CSV file."""
    if not path.exists():
        raise FileNotFoundError(f"Input file not found: {path}")

    suffix = path.suffix.lower()
    if suffix == ".txt":
        return _normalize_values(path.read_text(encoding="utf-8").splitlines())

    if suffix == ".csv":
        with path.open("r", encoding="utf-8", newline="") as handle:
            reader = csv.reader(handle)
            values: list[str] = []
            for row in reader:
                for cell in row:
                    values.append(cell)
            return _normalize_values(values)

    raise ValueError("Unsupported file format. Use .txt or .csv inputs.")
