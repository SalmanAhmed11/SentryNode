"""
Core Simulation and Risk Scoring Engine - SentryNode v1.0
Developed for SentryAI Dynamics
"""

from __future__ import annotations
from dataclasses import dataclass, asdict
from datetime import datetime, timezone, timedelta
import random
from typing import Dict, Iterable, List, Set
from assets import get_device_ids, get_profile_map

@dataclass
class SecurityEvent:
    """Structured security event aligned to NIST IR 8425 traceability standards."""
    timestamp: str
    device_id: str
    mac_address: str
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
    "system_ping": "No immediate action required. Continue standard monitoring.",
    "aisuru_port_probe": "Restrict exposed device services and apply firewall blocking.",
    "aisuru_volumetric_spike": "Enable router DDoS protection and contact ISP for filtering.",
    "aisuru_bruteforce_attempt": "Disable remote login and enforce unique credentials with MFA.",
    "cve_2025_4008_injection": "Apply firmware updates immediately and isolate affected devices.",
    "smart_lock_unsecured": "IMMEDIATE: Engage physical deadbolt and disconnect lock from remote access."
}

EVENT_PRIORITY: Dict[str, str] = {
    "system_ping": "Low",
    "aisuru_port_probe": "Medium",
    "aisuru_volumetric_spike": "High",
    "aisuru_bruteforce_attempt": "High",
    "cve_2025_4008_injection": "Critical",
}

SEVERITY_WEIGHTS: Dict[str, int] = {"Low": 1, "Medium": 3, "High": 6, "Critical": 10}

# --- Internal Helper Functions ---

def _to_iso8601_utc(ts: datetime) -> str:
    return ts.replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")

def _random_public_ipv4() -> str:
    return ".".join(str(random.randint(1, 254)) for _ in range(4))

def _event_timestamp(base_time: datetime, event_type: str) -> str:
    """Apply forensic timing: Bursts for attacks, spreads for reconnaissance."""
    if event_type == "aisuru_port_probe":
        # Recon is usually spread out over hours
        offset = random.randint(20, 360)
        return _to_iso8601_utc(base_time - timedelta(minutes=offset))
    if event_type.startswith("aisuru_"):
        # Active attacks happen in high-density clusters
        offset = random.randint(0, 90)
        return _to_iso8601_utc(base_time - timedelta(seconds=offset))
    return _to_iso8601_utc(base_time - timedelta(seconds=random.randint(0, 10800)))

def _is_smart_lock(device_id: str) -> bool:
    return device_id.startswith("LOCK-")

def _derive_mitigation(event_type: str, device_id: str, status: str) -> str:
    if _is_smart_lock(device_id) and "PHYSICAL_LOCK_STATE: UNSECURED" in status:
        return MITIGATION_MAP["smart_lock_unsecured"]
    return MITIGATION_MAP.get(event_type, "Consult vendor security documentation.")

def _build_event(base_time: datetime, device_id: str, event_type: str, status: str) -> SecurityEvent:
    profile = get_profile_map().get(device_id, {})
    return SecurityEvent(
        timestamp=_event_timestamp(base_time, event_type),
        device_id=device_id,
        mac_address=profile.get("mac_address", "00:00:00:00:00:00"),
        priority=EVENT_PRIORITY.get(event_type, "Low"),
        event_type=event_type,
        source_ip=_random_public_ipv4(),
        status=status,
        mitigation_recommendation=_derive_mitigation(event_type, device_id, status)
    )

# --- Primary Logic ---

def simulate_threat_events(scenario: str = "BREACH", seed: int | None = None) -> List[Dict[str, str]]:
    """Generate synthetic events based on the selected Scenario Control."""
    if seed is not None:
        random.seed(seed)
    
    scenario = (scenario or "BREACH").upper()
    now = datetime.utcnow()
    device_ids = get_device_ids()
    events: List[SecurityEvent] = []

    if scenario == "SAFE":
        # Normal household background noise
        for _ in range(random.randint(3, 6)):
            events.append(_build_event(now, random.choice(device_ids), "system_ping", "success"))

    elif scenario == "PROBING":
        # Reconnaissance fingerprint: 15-port probe on a single device
        target = random.choice(device_ids)
        for port in AISURU_PORT_PROBE_SEQUENCE:
            events.append(_build_event(now, target, "aisuru_port_probe", f"probe port={port}"))

    elif scenario == "ATTACK":
        # Active botnet volumetric and brute-force activity
        for _ in range(random.randint(15, 30)):
            etype = random.choice(["aisuru_volumetric_spike", "aisuru_bruteforce_attempt"])
            events.append(_build_event(now, random.choice(device_ids), etype, "blocked"))

    else:  # BREACH
        # The 'worst-case' scenario: Full chain + successful compromise
        for d_id in device_ids:
            events.append(_build_event(now, d_id, "aisuru_port_probe", "recon_detected"))
        for _ in range(20):
            events.append(_build_event(now, random.choice(device_ids), "aisuru_volumetric_spike", "blocked"))
        
        # Successful physical breach marker
        lock_id = "LOCK-RES-2026-003"
        events.append(_build_event(now, lock_id, "cve_2025_4008_injection", "success | PHYSICAL_LOCK_STATE: UNSECURED"))

    random.shuffle(events)
    return [asdict(e) for e in events]

def calculate_system_threat_level(events: Iterable[Dict[str, str]]) -> str:
    """Evaluate risk based on event density, priority, and multi-vector targeting."""
    events_list = list(events)
    if not events_list:
        return "Low"

    types = {e.get("event_type") for e in events_list}
    
    # 1. Immediate Critical Overrides
    if any("PHYSICAL_LOCK_STATE: UNSECURED" in e.get("status", "") for e in events_list):
        return "Critical"

    # 2. Persistence Bonus: Multiple attack families on one device
    attack_families_by_device: Dict[str, Set[str]] = {}
    for event in events_list:
        d_id = event.get("device_id", "")
        etype = event.get("event_type", "")
        family = "aisuru" if etype.startswith("aisuru_") else "cve" if etype.startswith("cve_") else "system"
        attack_families_by_device.setdefault(d_id, set()).add(family)

    if any(len(fams) >= 2 for fams in attack_families_by_device.values()):
        return "Critical"

    # 3. Weighted Scoring
    total_score = sum(SEVERITY_WEIGHTS.get(e.get("priority", "Low"), 1) for e in events_list)
    
    if total_score >= 180: return "Critical"
    if total_score >= 100: return "High"
    if total_score >= 40: return "Medium"
    return "Low"