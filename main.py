"""
SentryNode v1.0 | Master Command-Line Controller
Provides high-fidelity simulation, risk scoring, and NIST auditing.
"""

from __future__ import annotations
import sys
from typing import Dict, List

from assets import get_device_profiles
from engine import calculate_system_threat_level, simulate_threat_events
from formatter import export_events_to_csv, export_events_to_json
from auditor import audit_log_compliance

def _print_banner() -> None:
    print("=" * 70)
    print("SentryNode v1.0 | Synthetic IoT Security Forensics Simulator")
    print("SentryAI Dynamics - Residential Exposure Analysis")
    print("=" * 70)

def _physical_security_risk_count(events: List[Dict[str, str]]) -> int:
    return sum(1 for e in events if "PHYSICAL_LOCK_STATE: UNSECURED" in e.get("status", ""))

def run() -> None:
    _print_banner()

    # Allow user to pass scenario as an argument (e.g., python main.py SAFE)
    # Default to BREACH if no argument is provided
    scenario = sys.argv[1].upper() if len(sys.argv) > 1 else "BREACH"
    
    print(f"[*] Initializing Simulation: [SCENARIO: {scenario}]")
    
    profiles = get_device_profiles()
    events = simulate_threat_events(scenario=scenario)
    threat_level = calculate_system_threat_level(events)
    
    # NEW: Run NIST Compliance Audit
    audit_results = audit_log_compliance(events)

    # Export reports with relative paths
    json_path = export_events_to_json(events, "output/sentry_report.json")
    csv_path = export_events_to_csv(events, "output/sentry_report.csv")

    print("\nExecutive Summary")
    print("-" * 70)
    print(f"System Threat Level         : {threat_level}")
    print(f"NIST Compliance Score       : {audit_results['score']}% ({audit_results['audit_status']})")
    print(f"Total Events Detected       : {len(events)}")
    print(f"Physical Security Risks     : {_physical_security_risk_count(events)}")
    print(f"Profiles in Scope           : {len(profiles)} residential IoT assets")
    print(f"JSON Report Generated       : {json_path}")
    print(f"CSV Report Generated        : {csv_path}")
    
    if audit_results['findings']:
        print("\nAudit Findings:")
        for finding in audit_results['findings']:
            print(f" - {finding}")

if __name__ == "__main__":
    run()