"""Flask dashboard server for SentryNode."""

from __future__ import annotations

from flask import Flask, render_template, request

"""
SentryNode v1.0 | SaaS Dashboard Controller
Developed for SentryAI Dynamics
"""

from __future__ import annotations  # MUST BE AT THE TOP

from flask import Flask, render_template, request
from assets import get_device_profiles
from auditor import audit_log_compliance
from engine import calculate_system_threat_level, simulate_threat_events

app = Flask(__name__)


# Normalizes the scenario names from the URL buttons
SCENARIO_ALIASES = {
    "QUIET": "SAFE",
    "RECON": "PROBING",
    "ATTACK": "ATTACK",
    "BREACH": "BREACH",
    "SAFE": "SAFE",
    "PROBING": "PROBING",
}


def _count_physical_security_risks(events: list[dict[str, str]]) -> int:
    return sum(1 for e in events if "PHYSICAL_LOCK_STATE: UNSECURED" in e.get("status", ""))


def _top_first_aid_action(events: list[dict[str, str]], scenario: str) -> str:
def _count_physical_security_risks(events: list[dict[str, str]]) -> int:
    """Helper to count how many smart locks were compromised."""
    return sum(1 for e in events if "PHYSICAL_LOCK_STATE: UNSECURED" in e.get("status", ""))

def _top_first_aid_action(events: list[dict[str, str]], scenario: str) -> str:
    """Identifies the single most urgent recommendation for the homeowner."""
    if scenario == "SAFE":
        return "No immediate action required. Continue routine monitoring."

    priority_rank = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}
    
    # Sort by priority, then by physical risk importance
    sorted_events = sorted(
        events,
        key=lambda e: (
            priority_rank.get(e.get("priority", "Low"), 1),
            1 if "PHYSICAL_LOCK_STATE: UNSECURED" in e.get("status", "") else 0,
        ),
        reverse=True,
    )
    return sorted_events[0].get("mitigation_recommendation", "Review generated alerts.") if sorted_events else "No immediate action required."


@app.route("/")
def dashboard():
    requested = (request.args.get("scenario", "BREACH") or "BREACH").upper()
    scenario = SCENARIO_ALIASES.get(requested, "BREACH")

    return sorted_events[0].get("mitigation_recommendation", "Review generated alerts.") if sorted_events else "Monitor system status."

@app.route("/")
def dashboard():
    """Renders the dark-mode SaaS interface based on the selected scenario."""
    
    # Capture the scenario from the URL (defaults to BREACH)
    requested = (request.args.get("scenario", "BREACH") or "BREACH").upper()
    scenario = SCENARIO_ALIASES.get(requested, "BREACH")

    # Execute simulation and assessment
    events = simulate_threat_events(scenario=scenario)
    threat_level = calculate_system_threat_level(events)
    physical_security_risks = _count_physical_security_risks(events)
    first_aid_action = _top_first_aid_action(events, scenario)
    
    # Run the NIST IR 8425 Compliance Audit
    audit_result = audit_log_compliance(events)

    return render_template(
        "index.html",
        scenario=scenario,
        events=events,
        threat_level=threat_level,
        physical_security_risks=physical_security_risks,
        total_alerts=len(events),
        first_aid_action=first_aid_action,
        device_profiles=get_device_profiles(),
        compliance_score=audit_result["score"],
        audit_status=audit_result["audit_status"],
        audit_findings=audit_result["findings"],
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=False)
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=False)
