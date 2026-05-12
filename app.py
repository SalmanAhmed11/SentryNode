"""Flask dashboard server for SentryNode."""

from __future__ import annotations

from flask import Flask, render_template, request
"""Flask dashboard server for SentryNode.

Renders a dark-mode SaaS view for synthetic residential IoT security events.
"""

from __future__ import annotations

from flask import Flask, render_template

from assets import get_device_profiles
from auditor import audit_log_compliance
from engine import calculate_system_threat_level, simulate_threat_events

app = Flask(__name__)


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
    if scenario == "SAFE":
        return "No immediate action required. Continue routine monitoring."

    priority_rank = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}
def _count_physical_security_risks(events: list[dict[str, str]]) -> int:
    """Count successful smart lock exploit outcomes."""

    return sum(1 for e in events if "PHYSICAL_LOCK_STATE: UNSECURED" in e.get("status", ""))


def _top_first_aid_action(events: list[dict[str, str]]) -> str:
    """Select the single most urgent mitigation recommendation."""

    priority_rank = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}
    if not events:
        return "Review device logs and maintain firmware updates across all connected devices."

    # Highest priority first, then prefer physical security compromise signals.
    sorted_events = sorted(
        events,
        key=lambda e: (
            priority_rank.get(e.get("priority", "Low"), 1),
            1 if "PHYSICAL_LOCK_STATE: UNSECURED" in e.get("status", "") else 0,
        ),
        reverse=True,
    )
    return sorted_events[0].get("mitigation_recommendation", "Review generated alerts.") if sorted_events else "No immediate action required."
    return sorted_events[0].get(
        "mitigation_recommendation",
        "Review generated alert details for immediate containment steps.",
    )


@app.route("/")
def dashboard():
    requested = (request.args.get("scenario", "BREACH") or "BREACH").upper()
    scenario = SCENARIO_ALIASES.get(requested, "BREACH")

    events = simulate_threat_events(scenario=scenario)
    threat_level = calculate_system_threat_level(events)
    physical_security_risks = _count_physical_security_risks(events)
    first_aid_action = _top_first_aid_action(events, scenario)
    """Render the SentryNode dashboard with a fresh simulation window."""

    events = simulate_threat_events()
    threat_level = calculate_system_threat_level(events)
    physical_security_risks = _count_physical_security_risks(events)
    first_aid_action = _top_first_aid_action(events)

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
