"""NIST IR 8425-style compliance auditor for SentryNode event batches."""

from __future__ import annotations

from typing import Dict, Iterable, List


HIGH_PRIORITY_ALLOWED_TYPES = {
    "aisuru_volumetric_spike",
    "cve_2025_4008_injection",
}


def audit_log_compliance(events: Iterable[Dict[str, str]]) -> Dict[str, object]:
    """Audit event quality for Identity, Traceability, and Signaling controls.

    Controls assessed (aligned to requested interpretation of NIST IR 8425):
    - Identity: each event contains a non-empty device_id
    - Traceability: each event contains a non-empty mac_address
    - Signaling: high-priority events are correctly categorized
    """

    findings: List[str] = []
    total_checks = 0
    passed_checks = 0

    for idx, event in enumerate(events, start=1):
        event_label = f"event#{idx}"

        total_checks += 1
        if event.get("device_id"):
            passed_checks += 1
        else:
            findings.append(f"Identity failure: {event_label} missing device_id.")

        total_checks += 1
        if event.get("mac_address"):
            passed_checks += 1
        else:
            findings.append(f"Traceability failure: {event_label} missing mac_address.")

        priority = event.get("priority", "")
        if priority in {"High", "Critical"}:
            total_checks += 1
            event_type = event.get("event_type", "")
            if event_type in HIGH_PRIORITY_ALLOWED_TYPES:
                passed_checks += 1
            else:
                findings.append(
                    f"Signaling failure: {event_label} has {priority} priority with unsupported event_type '{event_type}'."
                )

    score = int(round((passed_checks / total_checks) * 100)) if total_checks else 0
    audit_status = "COMPLIANT" if score == 100 else "NON-COMPLIANT"

    if audit_status == "COMPLIANT":
        findings.append("All assessed Identity, Traceability, and Signaling controls passed.")

    return {
        "score": score,
        "audit_status": audit_status,
        "findings": findings,
    }
