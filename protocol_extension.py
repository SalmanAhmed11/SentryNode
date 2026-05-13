"""
Sidecar protocol extension for SentryNode.
Extends simulation to include Zigbee and Z-Wave without touching core files.
"""

from __future__ import annotations
from datetime import datetime, timezone, timedelta
import random
from typing import Dict, List
from engine import simulate_threat_events

EXTENSION_PROFILES: List[Dict[str, str]] = [
    {
        "device_id": "ZIG-MOTION-2026-001",
        "mac_address": "0E:71:2C:4A:98:10",
        "device_type": "zigbee_motion_sensor",
    },
    {
        "device_id": "ZWAVE-BULB-2026-001",
        "mac_address": "12:8B:5F:33:CD:44",
        "device_type": "zwave_smart_bulb",
    },
]

def _to_iso8601_utc(ts: datetime) -> str:
    return ts.replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")

def _random_public_ipv4() -> str:
    return ".".join(str(random.randint(1, 254)) for _ in range(4))

def _extension_timestamp(base_time: datetime) -> str:
    return _to_iso8601_utc(base_time - timedelta(seconds=random.randint(0, 900)))

def _build_extension_event(base_time: datetime, profile: Dict[str, str], event_type: str) -> Dict[str, str]:
    if event_type == "zigbee_replay_attack":
        return {
            "timestamp": _extension_timestamp(base_time),
            "device_id": profile["device_id"],
            "priority": "High",
            "event_type": "zigbee_replay_attack",
            "source_ip": _random_public_ipv4(),
            "status": random.choice(["blocked", "replay_signature_detected"]),
            "mitigation_recommendation": "Rotate Zigbee network keys and re-pair trusted devices.",
            "mac_address": profile["mac_address"],
        }
    return {
        "timestamp": _extension_timestamp(base_time),
        "device_id": profile["device_id"],
        "priority": "High",
        "event_type": "zwave_jamming_detected",
        "source_ip": _random_public_ipv4(),
        "status": random.choice(["channel_interference", "signal_recovery_in_progress"]),
        "mitigation_recommendation": "Reposition Z-Wave controller and reduce RF interference sources.",
        "mac_address": profile["mac_address"],
    }

def simulate_with_extensions(scenario: str = "BREACH") -> List[Dict[str, str]]:
    """Run core simulation and append protocol-extension events."""
    events = simulate_threat_events(scenario=scenario)
    normalized_scenario = (scenario or "BREACH").upper()
    
    if normalized_scenario not in {"ATTACK", "BREACH"}:
        return events

    now = datetime.now(timezone.utc)
    extension_events: List[Dict[str, str]] = []

    extension_events.append(_build_extension_event(now, EXTENSION_PROFILES[0], "zigbee_replay_attack"))
    extension_events.append(_build_extension_event(now, EXTENSION_PROFILES[1], "zwave_jamming_detected"))

    combined = events + extension_events
    random.shuffle(combined)
    return combined