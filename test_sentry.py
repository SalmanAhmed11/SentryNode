#!/usr/bin/env python3
"""Unit tests for SentryNode simulation and protocol sidecar.

This test suite is intentionally standalone and validates existing modules
through external imports only, without modifying production code.
"""

from datetime import datetime, timezone
import unittest
from unittest.mock import patch

from auditor import audit_log_compliance
from engine import calculate_system_threat_level, simulate_threat_events
from protocol_extension import simulate_with_extensions

SCHEMA_FIELDS = {
    "timestamp",
    "device_id",
    "mac_address",
    "priority",
    "event_type",
    "source_ip",
    "status",
    "mitigation_recommendation",
}


class TestSentryNodeSimulation(unittest.TestCase):
    """Validation suite for deterministic behavior, variance, and schema integrity."""

    def test_deterministic_seeding_breach(self) -> None:
        """Same seed + scenario must produce identical event logs."""
        fixed_now = datetime(2026, 5, 17, 12, 0, 0, tzinfo=timezone.utc)
        
        # FIXED: Patching .now instead of .utcnow to match engine.py implementation
        with patch("engine.datetime") as mock_datetime:
            mock_datetime.now.return_value = fixed_now
            run_a = simulate_threat_events(scenario="BREACH", seed=101)
            
        with patch("engine.datetime") as mock_datetime:
            mock_datetime.now.return_value = fixed_now
            run_b = simulate_threat_events(scenario="BREACH", seed=101)

        self.assertEqual(run_a, run_b)
        self.assertGreater(len(run_a), 0)

    def test_stochastic_variance_unseeded(self) -> None:
        """Unseeded runs should naturally vary to preserve simulation dynamism."""
        run_a = simulate_threat_events(scenario="BREACH")
        run_b = simulate_threat_events(scenario="BREACH")

        # Compare canonicalized payloads (sorted tuples) to avoid order-only variance.
        canon_a = sorted(tuple(sorted(event.items())) for event in run_a)
        canon_b = sorted(tuple(sorted(event.items())) for event in run_b)

        self.assertNotEqual(canon_a, canon_b)

    def test_schema_contract_integrity_core_and_extension(self) -> None:
        """Every event must conform exactly to the required 8-field schema."""
        core_events = simulate_threat_events(scenario="BREACH", seed=202)
        extension_events = simulate_with_extensions(scenario="BREACH")

        self.assertGreater(len(core_events), 0)
        self.assertGreater(len(extension_events), 0)

        for event in core_events + extension_events:
            self.assertEqual(set(event.keys()), SCHEMA_FIELDS)
            for field in SCHEMA_FIELDS:
                self.assertIsNotNone(event[field])

    def test_threat_escalation_thresholds(self) -> None:
        """Threat scoring should remain Low for nominal pings and Critical on breach override."""
        nominal_events = [
            {
                "timestamp": "2026-05-17T12:00:00Z",
                "device_id": "RTR-RES-2026-001",
                "mac_address": "02:3A:7C:91:5E:10",
                "priority": "Low",
                "event_type": "system_ping",
                "source_ip": "10.0.0.1",
                "status": "success",
                "mitigation_recommendation": "No immediate action required.",
            },
            {
                "timestamp": "2026-05-17T12:00:10Z",
                "device_id": "CAM-RES-2026-014",
                "mac_address": "06:4F:22:B8:C1:7A",
                "priority": "Low",
                "event_type": "system_ping",
                "source_ip": "10.0.0.2",
                "status": "success",
                "mitigation_recommendation": "No immediate action required.",
            },
        ]
        self.assertEqual(calculate_system_threat_level(nominal_events), "Low")

        physical_compromise_events = nominal_events + [
            {
                "timestamp": "2026-05-17T12:02:00Z",
                "device_id": "LOCK-RES-2026-003",
                "mac_address": "0A:9D:11:6E:42:F5",
                "priority": "Critical",
                "event_type": "cve_2025_4008_injection",
                "source_ip": "203.0.113.5",
                "status": "success | PHYSICAL_LOCK_STATE: UNSECURED",
                "mitigation_recommendation": "Immediately engage a physical deadbolt.",
            }
        ]
        self.assertEqual(calculate_system_threat_level(physical_compromise_events), "Critical")


if __name__ == "__main__":
    unittest.main()