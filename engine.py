"""
Core Simulation and Risk Scoring Engine - SentryNode v1.0
Developed for SentryAI Dynamics
"""

from __future__ import annotations
from dataclasses import dataclass, asdict
from datetime import datetime, timezone, timedelta
import random
from typing import Dict, Iterable, List, Set
from assets import get_device_ids

@dataclass
class SecurityEvent:
    """Structured security event aligned to a professional seven-field schema."""
    timestamp: str
    device_id: str
    priority: str
    event_type: str
    source_ip: str
    status: str
    mitigation_recommendation: str

# 2026 Aisuru Forensic Fingerprint Sequence
AISURU_PORT_PROBE_SEQUENCE: List[int] = [
    23, 22, 80, 8080, 443, 7547, 81, 5555, 8443, 8883, 1883, 49152, 37215, 52869, 62078
]

MITIGATION_MAP: Dict[str, str] = {
    "aisuru_volumetric_spike": "Enable router DDoS protection and contact ISP for upstream filtering.",
    "aisuru_bruteforce_attempt": "Disable remote admin login, update credentials, and enable MFA.",
    "aisuru_port_probe": "Restrict exposed services and apply geo-IP firewall blocking.",
    "cve_2025_4008_injection": "Apply firmware updates and isolate device on a separate IoT VLAN.",
    "smart_lock_unsecured": "IMMEDIATE: Engage physical deadbolt and disconnect lock from remote access."
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
    """Simulates high-density attack bursts."""
    cluster_anchor = base_time - timedelta(minutes=random.randint(1, 20))
    return _to_iso8601_utc(cluster_anchor + timedelta(seconds=random.randint(0, 90)))

def _isolated_probe_timestamp(base_time: datetime) -> str:
    """Simulates spaced-out reconnaissance activity."""
    isolated_anchor = base_time - timedelta(minutes=random.randint(20, 360))
    return _to_iso8601_utc(isolated_anchor + timedelta(seconds=random.randint(0, 30)))

def _general_timestamp(base_time: datetime) -> str:
    return _to_iso8601_utc(base_time - timedelta(seconds=random.randint(0, 10800)))

def _is_smart_lock(device_id: str) -> bool:
    return device_id.startswith("LOCK-")

def _derive_mitigation(event_type: str, device_id: str, status: str) -> str:
    if _is_smart_lock(device_id) and "PHYSICAL_LOCK_STATE: UNSECURED" in status:
        return MITIGATION_MAP["smart_lock_unsecured"]
    return MITIGATION_MAP.get(event_type, "Consult vendor security documentation.")

def _event_timestamp(base_time: datetime, event_type: str) -> str:
    if event_type == "aisuru_port_probe":
        return _isolated_probe_timestamp(base_time)
    if event_type.startswith("aisuru_"):
        return _clustered_timestamp(base_time)
    return _general_timestamp(base_time)

def _build_event(base_time: datetime, device_id: str, event_type: str, status: str) -> SecurityEvent:
    return SecurityEvent(
        timestamp=_event_timestamp(base_time, event_type),
        device_id=device_id,
        priority=EVENT_PRIORITY.get(event_type, "Low"),
        event_type=event_type,
        source_ip=_random_public_ipv4(),
        status=status,
        mitigation_recommendation=_derive_mitigation(event_type, device_id, status)
    )

def simulate_threat_events(seed: int | None = None) -> List[Dict[str, str]]:
    if seed is not None:
        random.seed(seed)
    now = datetime.utcnow()
    device_ids = get_device_ids()
    events: List[SecurityEvent] = []

    # Forensic Fingerprinting (15 ports per device)
    for d_id in device_ids:
        for port in AISURU_PORT_PROBE_SEQUENCE:
            events.append(_build_event(now, d_id, "aisuru_port_probe", f"probe_detected port={port}"))

    # Volumetric and Brute-force Simulation
    for _ in range(random.randint(20, 50)):
        e_type = random.choice(["aisuru_volumetric_spike", "aisuru_bruteforce_attempt"])
        events.append(_build_event(now, random.choice(device_ids), e_type, "blocked"))

    # Injection Attempts with Physical Impact logic
    for _ in range(random.randint(5, 15)):
        d_id = random.choice(device_ids)
        outcome = "success" if random.random() < 0.15 else "blocked"
        status = "success | PHYSICAL_LOCK_STATE: UNSECURED" if outcome == "success" and _is_smart_lock(d_id) else outcome
        events.append(_build_event(now, d_id, "cve_2025_4008_injection", status))

    random.shuffle(events)
    return [asdict(e) for e in events]

def calculate_system_threat_level(events: Iterable[Dict[str, str]]) -> str:
    weighted_score = 0
    attack_families_by_device: Dict[str, Set[str]] = {}

    for event in events:
        weighted_score += SEVERITY_WEIGHTS.get(event.get("priority", "Low"), 1)
        d_id, e_type = event.get("device_id", ""), event.get("event_type", "")
        family = "aisuru" if e_type.startswith("aisuru_") else "cve"
        attack_families_by_device.setdefault(d_id, set()).add(family)

    # Persistence Bonus: Multi-vector targeting triggers Critical status
    if any(len(families) >= 2 for families in attack_families_by_device.values()):
        return "Critical"

    if weighted_score >= 250: return "Critical"
    if weighted_score >= 150: return "High"
    if weighted_score >= 70: return "Medium"
    return "Low"