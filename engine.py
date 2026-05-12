"""Core simulation and risk scoring engine for SentryNode.

Simulates contemporary IoT threat patterns and returns audit-ready events using
an explicit seven-field schema:
    timestamp, device_id, priority, event_type,
    source_ip, status, mitigation_recommendation
"""

from __future__ import annotations

from dataclasses import dataclass, asdict
from datetime import datetime, timezone, timedelta
import random
from typing import Dict, Iterable, List, Set

from assets import get_device_ids


@dataclass
class SecurityEvent:
    """Structured security event aligned to the required seven-field schema."""

    timestamp: str
    device_id: str
    priority: str
    event_type: str
    source_ip: str
    status: str
    mitigation_recommendation: str


# Documented 2026 fingerprinting sequence used by Aisuru campaigns.
# The sequence is emitted in this exact order for each device.
AISURU_PORT_PROBE_SEQUENCE: List[int] = [
    23,
    22,
    80,
    8080,
    443,
    7547,
    81,
    5555,
    8443,
    8883,
    1883,
    49152,
    37215,
    52869,
    62078,
]

# Mitigation guidance written for non-technical homeowners while preserving
# professional security intent.
MITIGATION_MAP: Dict[str, str] = {
    "aisuru_volumetric_spike": (
        "Enable router DDoS protection, reboot impacted devices, and contact your ISP "
        "to request temporary upstream traffic filtering."
    ),
    "aisuru_bruteforce_attempt": (
        "Disable remote admin login, enforce unique passwords, and enable multi-factor "
        "authentication where available."
    ),
    "aisuru_port_probe": (
        "Restrict exposed device services, disable unused ports, and apply geo-IP or "
        "firewall blocking for repeated scan sources."
    ),
    "cve_2025_4008_injection": (
        "Apply firmware updates immediately, disable exposed command interfaces, and "
        "isolate the affected device on a separate IoT network."
    ),
    "smart_lock_unsecured": (
        "Immediately engage a physical deadbolt or manual backup lock, then disconnect "
        "the smart lock from remote access until credentials and firmware are remediated."
    ),
}

SEVERITY_WEIGHTS: Dict[str, int] = {
    "Low": 1,
    "Medium": 3,
    "High": 6,
    "Critical": 10,
}

EVENT_PRIORITY: Dict[str, str] = {
    "aisuru_volumetric_spike": "High",
    "aisuru_bruteforce_attempt": "Medium",
    "aisuru_port_probe": "Medium",
    "cve_2025_4008_injection": "Critical",
}


def _random_public_ipv4() -> str:
    """Generate a synthetic public source IP for event realism."""

    return ".".join(str(random.randint(1, 254)) for _ in range(4))


def _random_timestamp(base_time: datetime, spread_minutes: int = 180) -> str:
    """Generate an ISO-8601 UTC timestamp within a configurable lookback window."""

    offset = random.randint(0, spread_minutes * 60)
    ts = base_time - timedelta(seconds=offset)
    return ts.replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")


def _is_smart_lock(device_id: str) -> bool:
    """Infer whether a device is the smart lock profile."""

    return device_id.startswith("LOCK-")


def _derive_mitigation(event_type: str, device_id: str, status: str) -> str:
    """Resolve context-aware mitigation recommendations for each event."""

    if _is_smart_lock(device_id) and "PHYSICAL_LOCK_STATE: UNSECURED" in status:
        return MITIGATION_MAP["smart_lock_unsecured"]
    return MITIGATION_MAP[event_type]


def _build_event(
    base_time: datetime,
    device_id: str,
    event_type: str,
    status: str,
) -> SecurityEvent:
    """Construct a normalized SecurityEvent object."""

    return SecurityEvent(
        timestamp=_random_timestamp(base_time),
        device_id=device_id,
        priority=EVENT_PRIORITY[event_type],
        event_type=event_type,
        source_ip=_random_public_ipv4(),
        status=status,
        mitigation_recommendation=_derive_mitigation(event_type, device_id, status),
    )


def simulate_threat_events(seed: int | None = None) -> List[Dict[str, str]]:
    """Generate a batch of synthetic events with realistic variability.

    Threats modeled:
    - Aisuru botnet volumetric traffic spikes
    - Aisuru botnet brute-force authentication attempts
    - Aisuru botnet port-probe fingerprint sequence (15 ports per device)
    - CVE-2025-4008-style command injection attempts
    """

    if seed is not None:
        random.seed(seed)

    now = datetime.utcnow()
    device_ids = get_device_ids()

    volumetric_count = random.randint(8, 25)
    bruteforce_count = random.randint(12, 40)
    injection_count = random.randint(4, 14)

    events: List[SecurityEvent] = []

    for device_id in device_ids:
        for port in AISURU_PORT_PROBE_SEQUENCE:
            events.append(
                _build_event(
                    now,
                    device_id=device_id,
                    event_type="aisuru_port_probe",
                    status=f"probe_detected port={port}",
                )
            )

    for _ in range(volumetric_count):
        events.append(
            _build_event(
                now,
                device_id=random.choice(device_ids),
                event_type="aisuru_volumetric_spike",
                status=random.choice(["blocked", "degraded_service"]),
            )
        )

    for _ in range(bruteforce_count):
        events.append(
            _build_event(
                now,
                device_id=random.choice(device_ids),
                event_type="aisuru_bruteforce_attempt",
                status=random.choice(["blocked", "credential_failure", "rate_limited"]),
            )
        )

    for _ in range(injection_count):
        device_id = random.choice(device_ids)
        base_status = random.choice(["blocked", "quarantined", "command_rejected", "success"])
        if base_status == "success" and _is_smart_lock(device_id):
            status = "success | PHYSICAL_LOCK_STATE: UNSECURED"
        else:
            status = base_status

        events.append(
            _build_event(
                now,
                device_id=device_id,
                event_type="cve_2025_4008_injection",
                status=status,
            )
        )

    random.shuffle(events)
    return [asdict(event) for event in events]


def calculate_system_threat_level(events: Iterable[Dict[str, str]]) -> str:
    """Assess event severity and frequency to produce a System Threat Level.

    Scoring model:
    - Weighted sum by event priority for severity.
    - Frequency escalation bonus for sustained event volume.
    - Persistence bonus: critical override when one device is targeted by
      multiple distinct attack families in the same batch.
    """

    weighted_score = 0
    event_count = 0
    attack_families_by_device: Dict[str, Set[str]] = {}

    for event in events:
        event_count += 1
        priority = event.get("priority", "Low")
        weighted_score += SEVERITY_WEIGHTS.get(priority, 1)

        device_id = event.get("device_id", "")
        event_type = event.get("event_type", "")
        if event_type.startswith("aisuru_"):
            family = "aisuru"
        elif event_type.startswith("cve_"):
            family = "cve"
        else:
            family = event_type

        attack_families_by_device.setdefault(device_id, set()).add(family)

    if any(len(families) >= 2 for families in attack_families_by_device.values()):
        return "Critical"

    if event_count >= 60:
        weighted_score += 30
    elif event_count >= 40:
        weighted_score += 20
    elif event_count >= 20:
        weighted_score += 10

    if weighted_score >= 220:
        return "Critical"
    if weighted_score >= 120:
        return "High"
    if weighted_score >= 50:
        return "Medium"
    return "Low"
