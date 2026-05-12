"""Asset library for SentryNode synthetic security simulations.

Defines static device profiles for a representative residential IoT environment.
Each profile includes:
- unique device identifier
- locally administered unicast MAC address
- device type classification
"""

from dataclasses import dataclass, asdict
from typing import Dict, List


@dataclass(frozen=True)
class DeviceProfile:
    """ Immutable profile for a single simulated IoT device."""

    device_id: str
    mac_address: str
    device_type: str


# Locally administered unicast MAC addresses:
# - least significant bit of first octet = 0 (unicast)
# - second least significant bit of first octet = 1 (locally administered)
DEVICE_PROFILES: List[DeviceProfile] = [
    DeviceProfile(
        device_id="RTR-RES-2026-001",
        mac_address="02:3A:7C:91:5E:10",
        device_type="home_router",
    ),
    DeviceProfile(
        device_id="CAM-RES-2026-014",
        mac_address="06:4F:22:B8:C1:7A",
        device_type="smart_camera",
    ),
    DeviceProfile(
        device_id="LOCK-RES-2026-003",
        mac_address="0A:9D:11:6E:42:F5",
        device_type="smart_lock",
    ),
]


def get_device_profiles() -> List[Dict[str, str]]:
    """Return all device profiles in dictionary form for serialisation workflows."""

    return [asdict(profile) for profile in DEVICE_PROFILES]


def get_device_ids() -> List[str]:
    """Return the list of known device IDs."""

    return [profile.device_id for profile in DEVICE_PROFILES]


def get_profile_map() -> Dict[str, Dict[str, str]]:
    """Return a lookup map keyed by device_id for fast enrichment."""

    return {profile.device_id: asdict(profile) for profile in DEVICE_PROFILES}
