"""Export utilities for SentryNode synthetic security logs."""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Dict, Iterable, List

from engine import MITIGATION_MAP

SCHEMA_FIELDS: List[str] = [
    "timestamp",
    "device_id",
    "priority",
    "event_type",
    "source_ip",
    "status",
    "mitigation_recommendation",
]


def _normalize_event(event: Dict[str, str]) -> Dict[str, str]:
    """Normalize event shape and ensure homeowner-readable mitigation text."""

    normalized = {field: event.get(field, "") for field in SCHEMA_FIELDS}

    # If mitigation is missing, infer from event_type where possible.
    if not normalized["mitigation_recommendation"]:
        normalized["mitigation_recommendation"] = MITIGATION_MAP.get(
            normalized["event_type"], "Review device logs and consult vendor support guidance."
        )

    return normalized


def export_events_to_json(events: Iterable[Dict[str, str]], output_path: str) -> Path:
    """Export events to structured JSON format suitable for audit evidence."""

    normalized_events = [_normalize_event(event) for event in events]
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("w", encoding="utf-8") as handle:
        json.dump(normalized_events, handle, indent=2)

    return path


def export_events_to_csv(events: Iterable[Dict[str, str]], output_path: str) -> Path:
    """Export events to CSV with a fixed schema for SIEM and spreadsheet tooling."""

    normalized_events = [_normalize_event(event) for event in events]
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=SCHEMA_FIELDS)
        writer.writeheader()
        writer.writerows(normalized_events)

    return path
