"""Unit tests for SI-05 SOC REST API 12 endpoints (Direct Async Handlers)."""

import asyncio
import os
import sys
import unittest

# Ensure repo root and service package paths are in sys.path for unittest discovery
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

API_SRC = os.path.join(REPO_ROOT, "services/api/src")
if API_SRC not in sys.path:
    sys.path.insert(0, API_SRC)

WORKFLOW_SRC = os.path.join(REPO_ROOT, "services/workflow/src")
if WORKFLOW_SRC not in sys.path:
    sys.path.insert(0, WORKFLOW_SRC)

from dcim_api.soc import (
    DryRunActionRequest,
    IncidentCaseClose,
    IncidentCaseCreate,
    IncidentCaseUpdate,
    TriageRequest,
    close_incident_case,
    create_incident_case,
    get_alert_detail,
    get_incident_case,
    get_soc_metrics,
    get_threat_intel_matches,
    list_alerts,
    list_detection_rules,
    list_incident_cases,
    simulate_containment_action,
    triage_alert,
    update_incident_case,
)


class TestSOCAPIHandlers(unittest.TestCase):

    def test_01_list_alerts(self) -> None:
        alerts = asyncio.run(list_alerts())
        self.assertIsInstance(alerts, list)
        self.assertGreaterEqual(len(alerts), 1)

    def test_02_get_alert_detail(self) -> None:
        alert = asyncio.run(get_alert_detail("alt-100600-01"))
        self.assertEqual(alert.id, "alt-100600-01")
        self.assertEqual(alert.rule_id, "100600")

    def test_03_triage_alert(self) -> None:
        req = TriageRequest(status="Escalated", analyst_notes="Confirmed brute force", assignee="tier2-analyst")
        result = asyncio.run(triage_alert("alt-100600-01", req))
        self.assertEqual(result.triage_status, "Escalated")

    def test_04_list_cases(self) -> None:
        cases = asyncio.run(list_incident_cases())
        self.assertIsInstance(cases, list)
        self.assertGreaterEqual(len(cases), 1)

    def test_05_create_case(self) -> None:
        req = IncidentCaseCreate(
            title="Suspicious FIM Alteration on Gateway",
            severity="CRITICAL",
            source_alert_id="alt-100608-01",
            description="sshd_config modified unexpectedly",
            assignee="lead-secops",
        )
        case = asyncio.run(create_incident_case(req))
        self.assertTrue(case.case_id.startswith("INC-2026-"))
        self.assertEqual(case.status, "NEW")

    def test_06_get_case(self) -> None:
        case = asyncio.run(get_incident_case("INC-2026-001"))
        self.assertEqual(case.case_id, "INC-2026-001")

    def test_07_update_case(self) -> None:
        req = IncidentCaseUpdate(status="CONTAINED", assignee="ir-responder-2")
        case = asyncio.run(update_incident_case("INC-2026-001", req))
        self.assertEqual(case.status, "CONTAINED")
        self.assertEqual(case.assignee, "ir-responder-2")

    def test_08_close_case(self) -> None:
        req = IncidentCaseClose(
            resolution_summary="Attacker IP blocked at firewall, password reset completed.",
            is_false_positive=False,
            closing_analyst="secops-lead",
        )
        case = asyncio.run(close_incident_case("INC-2026-001", req))
        self.assertEqual(case.status, "CLOSED")
        self.assertEqual(case.resolution_summary, req.resolution_summary)

    def test_09_threat_intel_matches(self) -> None:
        matches = asyncio.run(get_threat_intel_matches(ioc_type="ip"))
        self.assertIsInstance(matches, list)
        for m in matches:
            self.assertEqual(m.ioc_type, "ip")

    def test_10_list_rules(self) -> None:
        rules = asyncio.run(list_detection_rules())
        self.assertIsInstance(rules, list)
        self.assertGreaterEqual(len(rules), 6)

    def test_11_get_metrics(self) -> None:
        metrics = asyncio.run(get_soc_metrics())
        self.assertEqual(metrics.total_alerts_24h, 142)
        self.assertEqual(metrics.mttd_minutes, 4.2)
        self.assertEqual(metrics.mttr_minutes, 18.5)

    def test_12_dry_run_action(self) -> None:
        req = DryRunActionRequest(
            action_type="isolate_host",
            target_identifier="srv-db-prod-01",
            reason="Contain compromised host",
            requested_by="ir-commander",
        )
        resp = asyncio.run(simulate_containment_action(req))
        self.assertTrue(resp.dry_run)
        self.assertFalse(resp.executed)
        self.assertIn("OT-Safe", resp.ot_safety_status)


if __name__ == "__main__":
    unittest.main()
