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

from assets import get_device_ids, get_profile_map


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
    mac_address: str


AISURU_PORT_PROBE_SEQUENCE: List[int] = [23, 22, 80, 8080, 443, 7547, 81, 5555, 8443, 8883, 1883, 49152, 37215, 52869, 62078]

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

SEVERITY_WEIGHTS: Dict[str, int] = {"Low": 1, "Medium": 3, "High": 6, "Critical": 10}

EVENT_PRIORITY: Dict[str, str] = {
    "aisuru_volumetric_spike": "High",
    "aisuru_bruteforce_attempt": "Medium",
    "aisuru_port_probe": "Medium",
    "cve_2025_4008_injection": "Critical",
}


def _random_public_ipv4() -> str:
    return ".".join(str(random.randint(1, 254)) for _ in range(4))


def _to_iso8601_utc(ts: datetime) -> str:
    return ts.replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")


def _clustered_timestamp(base_time: datetime) -> str:
    """Return a timestamp in a high-density burst (seconds apart)."""
    cluster_anchor = base_time - timedelta(minutes=random.randint(1, 20))
    offset_seconds = random.randint(0, 90)
    return _to_iso8601_utc(cluster_anchor + timedelta(seconds=offset_seconds))


def _isolated_probe_timestamp(base_time: datetime) -> str:
    """Return a timestamp spaced farther apart for reconnaissance probes."""
    isolated_anchor = base_time - timedelta(minutes=random.randint(20, 360))
    offset_seconds = random.randint(0, 30)
    return _to_iso8601_utc(isolated_anchor + timedelta(seconds=offset_seconds))


def _general_timestamp(base_time: datetime) -> str:
    offset = random.randint(0, 180 * 60)
    return _to_iso8601_utc(base_time - timedelta(seconds=offset))


def _is_smart_lock(device_id: str) -> bool:
    return device_id.startswith("LOCK-")


def _derive_mitigation(event_type: str, device_id: str, status: str) -> str:
    if _is_smart_lock(device_id) and "PHYSICAL_LOCK_STATE: UNSECURED" in status:
        return MITIGATION_MAP["smart_lock_unsecured"]
    return MITIGATION_MAP[event_type]


def _event_timestamp(base_time: datetime, event_type: str) -> str:
    """Apply timeline semantics per attack category for forensic realism."""
    if event_type == "aisuru_port_probe":
        return _isolated_probe_timestamp(base_time)
    if event_type.startswith("aisuru_"):
        return _clustered_timestamp(base_time)
    return _general_timestamp(base_time)


def _build_event(base_time: datetime, device_id: str, event_type: str, status: str) -> SecurityEvent:
    profile_map = get_profile_map()
    mac_address = profile_map.get(device_id, {}).get("mac_address", "")

    return SecurityEvent(
        timestamp=_event_timestamp(base_time, event_type),
        device_id=device_id,
        priority=EVENT_PRIORITY[event_type],
        event_type=event_type,
        source_ip=_random_public_ipv4(),
        status=status,
        mitigation_recommendation=_derive_mitigation(event_type, device_id, status),
        mac_address=mac_address,
    )


def simulate_threat_events(seed: int | None = None) -> List[Dict[str, str]]:
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
            events.append(_build_event(now, device_id, "aisuru_port_probe", f"probe_detected port={port}"))

    for _ in range(volumetric_count):
        events.append(_build_event(now, random.choice(device_ids), "aisuru_volumetric_spike", random.choice(["blocked", "degraded_service"])))

    for _ in range(bruteforce_count):
        events.append(_build_event(now, random.choice(device_ids), "aisuru_bruteforce_attempt", random.choice(["blocked", "credential_failure", "rate_limited"])))

    for _ in range(injection_count):
        device_id = random.choice(device_ids)
        base_status = random.choice(["blocked", "quarantined", "command_rejected", "success"])
        status = "success | PHYSICAL_LOCK_STATE: UNSECURED" if base_status == "success" and _is_smart_lock(device_id) else base_status
        events.append(_build_event(now, device_id, "cve_2025_4008_injection", status))

    random.shuffle(events)
    return [asdict(event) for event in events]


def calculate_system_threat_level(events: Iterable[Dict[str, str]]) -> str:
    weighted_score = 0
    event_count = 0
    attack_families_by_device: Dict[str, Set[str]] = {}

    for event in events:
        event_count += 1
        weighted_score += SEVERITY_WEIGHTS.get(event.get("priority", "Low"), 1)

        device_id = event.get("device_id", "")
        event_type = event.get("event_type", "")
        family = "aisuru" if event_type.startswith("aisuru_") else "cve" if event_type.startswith("cve_") else event_type
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
