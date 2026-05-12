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
from typing import Dict, Iterable, List

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
    "cve_2025_4008_injection": (
        "Apply firmware updates immediately, disable exposed command interfaces, and "
        "isolate the affected device on a separate IoT network."
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
        mitigation_recommendation=MITIGATION_MAP[event_type],
    )


def simulate_threat_events(seed: int | None = None) -> List[Dict[str, str]]:
    """Generate a batch of synthetic events with realistic variability.

    Threats modeled:
    - Aisuru botnet volumetric traffic spikes
    - Aisuru botnet brute-force authentication attempts
    - CVE-2025-4008-style command injection attempts
    """

    if seed is not None:
        random.seed(seed)

    now = datetime.utcnow()
    device_ids = get_device_ids()

    # Randomized ranges tuned for realistic household burst behavior in 2026.
    volumetric_count = random.randint(8, 25)
    bruteforce_count = random.randint(12, 40)
    injection_count = random.randint(4, 14)

    events: List[SecurityEvent] = []

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
        events.append(
            _build_event(
                now,
                device_id=random.choice(device_ids),
                event_type="cve_2025_4008_injection",
                status=random.choice(["blocked", "quarantined", "command_rejected"]),
            )
        )

    random.shuffle(events)
    return [asdict(event) for event in events]


def calculate_system_threat_level(events: Iterable[Dict[str, str]]) -> str:
    """Assess event severity and frequency to produce a System Threat Level.

    Scoring model:
    - Weighted sum by event priority for severity.
    - Frequency escalation bonus for sustained event volume.
    """

    weighted_score = 0
    event_count = 0

    for event in events:
        event_count += 1
        priority = event.get("priority", "Low")
        weighted_score += SEVERITY_WEIGHTS.get(priority, 1)

    # Frequency multiplier to represent concentrated attack windows.
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
