"""Unit tests for SOAR Connector Registry and 6 Concrete Connectors (unittest)."""

import unittest
import sys
import os

# Ensure dcim-core-platform is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from connectors.soar_registry import (
    SOARConnectorRegistry,
    ConnectorValidationError,
    ConnectorExecutionError,
)
from connectors.misp.adapter import MISPConnector
from connectors.thehive.adapter import TheHiveConnector
from connectors.slack.adapter import SlackConnector
from connectors.email.adapter import EmailConnector
from connectors.firewall.adapter import FirewallConnector
from connectors.edr.adapter import EDRConnector


class TestSOARConnectors(unittest.TestCase):

    def setUp(self):
        self.registry = SOARConnectorRegistry()
        self.registry.register(MISPConnector())
        self.registry.register(TheHiveConnector())
        self.registry.register(SlackConnector())
        self.registry.register(EmailConnector())
        self.registry.register(FirewallConnector())
        self.registry.register(EDRConnector())

    def test_registry_list_connectors(self):
        connectors = self.registry.list_connectors()
        self.assertEqual(len(connectors), 6)
        connector_ids = [c["connector_id"] for c in connectors]
        self.assertIn("misp", connector_ids)
        self.assertIn("thehive", connector_ids)
        self.assertIn("slack", connector_ids)
        self.assertIn("email", connector_ids)
        self.assertIn("firewall", connector_ids)
        self.assertIn("edr", connector_ids)

    def test_unregistered_connector_raises(self):
        with self.assertRaises(ConnectorExecutionError):
            self.registry.execute_action("unknown_connector", "some_action", {})

    def test_misp_connector(self):
        res = self.registry.execute_action("misp", "search_iocs", {"value": "198.51.100.100"}, dry_run=True)
        self.assertEqual(res["status"], "success")
        self.assertTrue(res["dry_run"])
        self.assertEqual(res["connector"], "misp")

        with self.assertRaises(ConnectorValidationError):
            self.registry.execute_action("misp", "search_iocs", {})

        with self.assertRaises(ConnectorValidationError):
            self.registry.execute_action("misp", "invalid_action", {})

    def test_thehive_connector(self):
        res = self.registry.execute_action("thehive", "create_case", {"title": "Ransomware outbreak"}, dry_run=True)
        self.assertEqual(res["status"], "success")
        self.assertEqual(res["mock_response"]["title"], "Ransomware outbreak")

        with self.assertRaises(ConnectorValidationError):
            self.registry.execute_action("thehive", "create_case", {})

    def test_slack_connector(self):
        res = self.registry.execute_action(
            "slack",
            "send_alert_notification",
            {"channel": "#soc-alerts", "message": "High severity alert"},
            dry_run=True,
        )
        self.assertEqual(res["status"], "success")
        self.assertEqual(res["mock_response"]["channel"], "#soc-alerts")

        with self.assertRaises(ConnectorValidationError):
            self.registry.execute_action("slack", "send_alert_notification", {"channel": "#soc-alerts"})

    def test_email_connector(self):
        res = self.registry.execute_action(
            "email",
            "send_incident_digest",
            {"recipient": "soc@example.com", "incident_id": "INC-889"},
            dry_run=True,
        )
        self.assertEqual(res["status"], "success")
        self.assertEqual(res["mock_response"]["recipient"], "soc@example.com")

        with self.assertRaises(ConnectorValidationError):
            self.registry.execute_action("email", "send_incident_digest", {"recipient": "soc@example.com"})

    def test_firewall_connector(self):
        res = self.registry.execute_action("firewall", "block_ip", {"ip": "198.51.100.99"}, dry_run=True)
        self.assertEqual(res["status"], "success")
        self.assertEqual(res["mock_response"]["ip"], "198.51.100.99")
        self.assertEqual(res["mock_response"]["reason"], "DRY_RUN_DEFAULT (ADR-0005)")

        with self.assertRaises(ConnectorValidationError):
            self.registry.execute_action("firewall", "block_ip", {})

    def test_edr_connector(self):
        res = self.registry.execute_action("edr", "isolate_host", {"hostname": "workstation-01"}, dry_run=True)
        self.assertEqual(res["status"], "success")
        self.assertEqual(res["mock_response"]["target"], "workstation-01")
        self.assertEqual(res["mock_response"]["reason"], "DRY_RUN_DEFAULT (ADR-0005)")

        with self.assertRaises(ConnectorValidationError):
            self.registry.execute_action("edr", "isolate_host", {})


if __name__ == "__main__":
    unittest.main()

