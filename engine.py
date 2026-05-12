"""Core simulation and risk scoring engine for SentryNode."""

from __future__ import annotations

from dataclasses import dataclass, asdict
from datetime import datetime, timezone, timedelta
import random
from typing import Dict, Iterable, List, Set

from assets import get_device_ids, get_profile_map


@dataclass
class SecurityEvent:
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
    "system_ping": "No immediate action required. Continue standard monitoring.",
    "aisuru_port_probe": "Restrict exposed device services, disable unused ports, and apply firewall blocking for repeated scan sources.",
    "aisuru_volumetric_spike": "Enable router DDoS protection and contact your ISP for upstream filtering.",
    "aisuru_bruteforce_attempt": "Disable remote admin login and enforce unique credentials with MFA.",
    "cve_2025_4008_injection": "Apply firmware updates immediately and isolate affected devices.",
    "smart_lock_unsecured": "Immediately engage a physical deadbolt or manual backup lock and disable remote lock access.",
}

EVENT_PRIORITY: Dict[str, str] = {
    "system_ping": "Low",
    "aisuru_port_probe": "Medium",
    "aisuru_volumetric_spike": "High",
    "aisuru_bruteforce_attempt": "High",
    "cve_2025_4008_injection": "Critical",
}

SEVERITY_WEIGHTS: Dict[str, int] = {"Low": 1, "Medium": 3, "High": 6, "Critical": 10}


def _to_iso8601_utc(ts: datetime) -> str:
    return ts.replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")


def _random_public_ipv4() -> str:
    return ".".join(str(random.randint(1, 254)) for _ in range(4))


def _clustered_timestamp(base_time: datetime) -> str:
    return _to_iso8601_utc(base_time - timedelta(minutes=random.randint(1, 20)) + timedelta(seconds=random.randint(0, 90)))


def _isolated_probe_timestamp(base_time: datetime) -> str:
    return _to_iso8601_utc(base_time - timedelta(minutes=random.randint(20, 360)) + timedelta(seconds=random.randint(0, 30)))


def _general_timestamp(base_time: datetime) -> str:
    return _to_iso8601_utc(base_time - timedelta(seconds=random.randint(0, 180 * 60)))


def _event_timestamp(base_time: datetime, event_type: str) -> str:
    if event_type == "aisuru_port_probe":
        return _isolated_probe_timestamp(base_time)
    if event_type.startswith("aisuru_"):
        return _clustered_timestamp(base_time)
    return _general_timestamp(base_time)


def _is_smart_lock(device_id: str) -> bool:
    return device_id.startswith("LOCK-")


def _derive_mitigation(event_type: str, device_id: str, status: str) -> str:
    if _is_smart_lock(device_id) and "PHYSICAL_LOCK_STATE: UNSECURED" in status:
        return MITIGATION_MAP["smart_lock_unsecured"]
    return MITIGATION_MAP[event_type]


def _build_event(base_time: datetime, device_id: str, event_type: str, status: str) -> SecurityEvent:
    mac_address = get_profile_map().get(device_id, {}).get("mac_address", "")
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


def simulate_threat_events(scenario: str = "BREACH", seed: int | None = None) -> List[Dict[str, str]]:
    if seed is not None:
        random.seed(seed)
    scenario = (scenario or "BREACH").upper()

    now = datetime.utcnow()
    device_ids = get_device_ids()
    events: List[SecurityEvent] = []

    if scenario == "SAFE":
        for _ in range(random.randint(2, 5)):
            events.append(_build_event(now, random.choice(device_ids), "system_ping", "success"))

    elif scenario == "PROBING":
        # Exactly 15 reconnaissance events total.
        target_device = random.choice(device_ids)
        for port in AISURU_PORT_PROBE_SEQUENCE:
            events.append(_build_event(now, target_device, "aisuru_port_probe", f"probe_detected port={port}"))

    elif scenario == "ATTACK":
        for _ in range(random.randint(10, 16)):
            events.append(_build_event(now, random.choice(device_ids), "aisuru_volumetric_spike", random.choice(["blocked", "degraded_service"])))
        for _ in range(random.randint(12, 20)):
            events.append(_build_event(now, random.choice(device_ids), "aisuru_bruteforce_attempt", random.choice(["blocked", "credential_failure", "rate_limited"])))

    else:  # BREACH + fallback
        for device_id in device_ids:
            for port in AISURU_PORT_PROBE_SEQUENCE:
                events.append(_build_event(now, device_id, "aisuru_port_probe", f"probe_detected port={port}"))
        for _ in range(random.randint(8, 25)):
            events.append(_build_event(now, random.choice(device_ids), "aisuru_volumetric_spike", random.choice(["blocked", "degraded_service"])))
        for _ in range(random.randint(12, 40)):
            events.append(_build_event(now, random.choice(device_ids), "aisuru_bruteforce_attempt", random.choice(["blocked", "credential_failure", "rate_limited"])))
        for _ in range(random.randint(4, 14)):
            device_id = random.choice(device_ids)
            base_status = random.choice(["blocked", "quarantined", "command_rejected", "success"])
            status = "success | PHYSICAL_LOCK_STATE: UNSECURED" if base_status == "success" and _is_smart_lock(device_id) else base_status
            events.append(_build_event(now, device_id, "cve_2025_4008_injection", status))

    random.shuffle(events)
    return [asdict(event) for event in events]


def calculate_system_threat_level(events: Iterable[Dict[str, str]]) -> str:
    events = list(events)
    if not events:
        return "Low"

    types = {e.get("event_type", "") for e in events}
    if types == {"system_ping"}:
        return "Low"
    if types == {"aisuru_port_probe"}:
        return "Medium"
    if "cve_2025_4008_injection" in types:
        return "Critical"

    weighted_score = sum(SEVERITY_WEIGHTS.get(e.get("priority", "Low"), 1) for e in events)

    attack_families_by_device: Dict[str, Set[str]] = {}
    for event in events:
        family = "aisuru" if event.get("event_type", "").startswith("aisuru_") else "cve" if event.get("event_type", "").startswith("cve_") else event.get("event_type", "")
        attack_families_by_device.setdefault(event.get("device_id", ""), set()).add(family)

    if any(len(families) >= 2 for families in attack_families_by_device.values()) and "cve_2025_4008_injection" in types:
        return "Critical"

    if weighted_score >= 140:
        return "High"
    if weighted_score >= 50:
        return "Medium"
    return "Low"
