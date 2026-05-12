"""
NIST IR 8425 Compliance Auditor - SentryNode v1.0
Evaluates event batches against Identity, Traceability, and Signaling controls.
"""

from __future__ import annotations
from typing import Dict, Iterable, List

# These must match the 'High' or 'Critical' events defined in engine.py
HIGH_PRIORITY_ALLOWED_TYPES = {
    "aisuru_volumetric_spike",
    "aisuru_bruteforce_attempt",
    "cve_2025_4008_injection",
}

def audit_log_compliance(events: Iterable[Dict[str, str]]) -> Dict[str, object]:
    """
    Assesses log quality based on NIST IR 8425 Core Baseline.
    - Identity: Existence of device_id.
    - Traceability: Existence of mac_address.
    - Signaling: Alignment of priority levels with event categories.
    """
    findings: List[str] = []
    total_checks = 0
    passed_checks = 0

    for idx, event in enumerate(events, start=1):
        event_label = f"event#{idx}"

        # 1. Identity Check
        total_checks += 1
        if event.get("device_id"):
            passed_checks += 1
        else:
            findings.append(f"Identity failure: {event_label} missing device_id.")

        # 2. Traceability Check
        total_checks += 1
        if event.get("mac_address"):
            passed_checks += 1
        else:
            findings.append(f"Traceability failure: {event_label} missing mac_address.")

        # 3. Signaling Check (Severity Alignment)
        priority = event.get("priority", "")
        if priority in {"High", "Critical"}:
            total_checks += 1
            event_type = event.get("event_type", "")
            if event_type in HIGH_PRIORITY_ALLOWED_TYPES:
                passed_checks += 1
            else:
                findings.append(
                    f"Signaling failure: {event_label} categorized as {priority} but type '{event_type}' is not in the NIST high-priority baseline."
                )

    # Score calculation (Handles empty event batches)
    score = int(round((passed_checks / total_checks) * 100)) if total_checks else 100
    audit_status = "COMPLIANT" if score == 100 else "NON-COMPLIANT"

    if audit_status == "COMPLIANT":
        findings.append("All Identity, Traceability, and Signaling controls satisfied.")

    return {
        "score": score,
        "audit_status": audit_status,
        "findings": findings,
    }