"""Unit tests for DFIR IRIS Bi-directional Sync Bridge and Dynamic Severity Mapping."""

import unittest
import sys
import os

# Add required paths to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../services/workflow/src")))

from dcim_workflow.incident_response import IncidentCase, IncidentState, SeverityLevel
from dcim_workflow.iris_sync import (
    IRISSyncBridge,
    map_rule_level_to_iris_severity,
    map_incident_state_to_iris_status,
)
from connectors.iris.adapter import IRISConnector


class TestIRISSyncBridge(unittest.TestCase):

    def setUp(self):
        self.bridge = IRISSyncBridge()
        self.connector = IRISConnector()

    def test_dynamic_severity_mapping(self):
        self.assertEqual(map_rule_level_to_iris_severity(3), 1)   # Low
        self.assertEqual(map_rule_level_to_iris_severity(8), 2)   # Medium
        self.assertEqual(map_rule_level_to_iris_severity(12), 3)  # High
        self.assertEqual(map_rule_level_to_iris_severity(15), 4)  # Critical
        self.assertEqual(map_rule_level_to_iris_severity(18), 4)  # Critical

    def test_incident_state_to_iris_status_mapping(self):
        self.assertEqual(map_incident_state_to_iris_status(IncidentState.NEW), 1)
        self.assertEqual(map_incident_state_to_iris_status(IncidentState.TRIAGED), 2)
        self.assertEqual(map_incident_state_to_iris_status(IncidentState.CONTAINED), 2)
        self.assertEqual(map_incident_state_to_iris_status(IncidentState.ERADICATED), 2)
        self.assertEqual(map_incident_state_to_iris_status(IncidentState.RECOVERED), 3)
        self.assertEqual(map_incident_state_to_iris_status(IncidentState.CLOSED), 4)

    def test_create_case_dry_run(self):
        res = self.bridge.create_case("Unusual Login Activity", "Multiple failed SSH attempts", rule_level=12, dry_run=True)
        self.assertEqual(res["status"], "success")
        self.assertTrue(res["dry_run"])
        self.assertEqual(res["case_severity_id"], 3)
        self.assertIn("IRIS-TICKET-", res["iris_ticket_id"])

    def test_update_case_status_dry_run(self):
        res = self.bridge.update_case_status("IRIS-8840", IncidentState.CONTAINED, note="Host isolated via EDR", dry_run=True)
        self.assertEqual(res["status"], "success")
        self.assertEqual(res["iris_status_id"], 2)
        self.assertEqual(res["incident_state"], "CONTAINED")

    def test_sync_incident_case_lifecycle(self):
        case = IncidentCase(
            case_id="INC-2026-901",
            title="Ransomware Outbreak on Workstation-02",
            severity=SeverityLevel.CRITICAL,
            source_event_id="EVT-8819",
        )
        self.assertIsNone(case.iris_ticket_id)

        # 1. First sync -> creates IRIS ticket
        res1 = self.bridge.sync_incident_case(case, rule_level=15, dry_run=True)
        self.assertIsNotNone(case.iris_ticket_id)
        self.assertEqual(res1["case_severity_id"], 4)

        # 2. State transition NEW -> TRIAGED -> sync
        case.transition_to(IncidentState.TRIAGED, actor="soc-analyst", reason="Threat confirmed")
        case.assignee = "analyst-john"
        res2 = self.bridge.sync_incident_case(case, dry_run=True)
        self.assertEqual(res2["action"], "update_case_status")
        self.assertEqual(res2["iris_status_id"], 2)

        # 3. State transition TRIAGED -> CONTAINED -> sync
        case.transition_to(IncidentState.CONTAINED, actor="soar-bot", reason="Host isolated", dry_run=False)
        res3 = self.bridge.sync_incident_case(case, dry_run=True)
        self.assertEqual(res3["iris_status_id"], 2)

        # 4. State transition CONTAINED -> ERADICATED -> RECOVERED -> CLOSED -> sync
        case.transition_to(IncidentState.ERADICATED, actor="soc-lead", reason="Malware deleted")
        case.transition_to(IncidentState.RECOVERED, actor="sysadmin", reason="OS restored")
        case.transition_to(IncidentState.CLOSED, actor="soc-lead", reason="Case closed")

        res4 = self.bridge.sync_incident_case(case, dry_run=True)
        self.assertEqual(res4["iris_status_id"], 4)  # IRIS status Closed

    def test_iris_connector_execution(self):
        res = self.connector.execute(
            "create_case",
            {"case_name": "Phishing Incident", "description": "Suspicious email link clicked", "rule_level": 9},
            dry_run=True,
        )
        self.assertEqual(res["status"], "success")
        self.assertEqual(res["case_severity_id"], 2)


if __name__ == "__main__":
    unittest.main()
