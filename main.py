"""SentryNode v1.0 master controller.

Provides a one-command workflow to simulate events, score risk, export reports,
and print an executive summary for homeowners and analysts.
"""

from __future__ import annotations

from typing import Dict, List

from assets import get_device_profiles
from engine import EVENT_PRIORITY, calculate_system_threat_level, simulate_threat_events
from formatter import export_events_to_csv, export_events_to_json


def _print_banner() -> None:
    print("=" * 70)
    print("SentryNode v1.0 | Synthetic IoT Security Forensics Simulator")
    print("SentryAI Dynamics - Residential Exposure Analysis")
    print("=" * 70)


def _highest_priority_event(events: List[Dict[str, str]]) -> Dict[str, str]:
    rank = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}
    return max(events, key=lambda e: rank.get(e.get("priority", "Low"), 1))


def _physical_security_risk_count(events: List[Dict[str, str]]) -> int:
    return sum(1 for e in events if "PHYSICAL_LOCK_STATE: UNSECURED" in e.get("status", ""))


def run() -> None:
    _print_banner()

    profiles = get_device_profiles()
    events = simulate_threat_events()
    threat_level = calculate_system_threat_level(events)

    json_path = export_events_to_json(events, "/output/sentry_report.json")
    csv_path = export_events_to_csv(events, "/output/sentry_report.csv")

    highest_event = _highest_priority_event(events)
    first_aid_action = highest_event.get("mitigation_recommendation", "Review generated report for mitigation guidance.")

    print("\nExecutive Summary")
    print("-" * 70)
    print(f"System Threat Level         : {threat_level}")
    print(f"Total Events Detected       : {len(events)}")
    print(f"Physical Security Risks     : {_physical_security_risk_count(events)}")
    print(f"Top First Aid Action        : {first_aid_action}")
    print(f"Profiles in Scope           : {len(profiles)} residential IoT assets")
    print(f"JSON Report                 : {json_path}")
    print(f"CSV Report                  : {csv_path}")


if __name__ == "__main__":
    run()
