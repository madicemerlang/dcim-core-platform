"""Tests for Wazuh SIEM → Kafka dcim.siem.alerts → SOAR Consumer Pipeline (SO-02)."""

from pathlib import Path
import json
import unittest

from connectors.wazuh.adapter import parse_wazuh_event
from connectors.wazuh.kafka_producer import (
    WazuhKafkaAlertProducer,
    build_siem_alert_envelope,
)
from connectors.wazuh.soar_kafka_consumer import (
    SOARKafkaConsumer,
    transform_envelope_to_soar_payload,
)

FIXTURE_DIR = Path("fixtures/synthetic/wazuh")


class TestWazuhKafkaSOARPipeline(unittest.TestCase):
    """Unit test suite for SO-02: Wazuh -> Kafka dcim.siem.alerts -> SOAR pipeline."""

    def test_build_siem_alert_envelope(self) -> None:
        raw_alert = {
            "timestamp": "2026-08-11T10:00:00Z",
            "rule": {
                "id": 100608,
                "level": 9,
                "description": "FIM Alert: /etc/ssh/sshd_config modified",
                "groups": ["syscheck", "fim"],
            },
            "agent": {
                "id": "002",
                "name": "gateway-02",
                "ip": "198.51.100.20",
            },
            "data": {
                "file": "/etc/ssh/sshd_config",
                "sha256_after": "a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e",
            },
        }

        envelope = build_siem_alert_envelope(raw_alert, observed_at="2026-08-11T10:00:05Z")

        self.assertEqual(envelope["schema_version"], "0.1.0")
        self.assertIn("event_id", envelope)
        self.assertEqual(envelope["event_type"], "wazuh.alert.security")
        self.assertEqual(envelope["priority"], "high")  # level 9 -> high
        self.assertEqual(envelope["source"]["system"], "wazuh-siem")
        self.assertEqual(envelope["source"]["connector"], "custom-wazuh2kafka")
        self.assertEqual(envelope["enrichment"]["rule_level"], 9)
        self.assertEqual(envelope["enrichment"]["rule_description"], "FIM Alert: /etc/ssh/sshd_config modified")

    def test_priority_level_mapping(self) -> None:
        levels_and_expected = [
            (3, "low"),
            (7, "medium"),
            (10, "high"),
            (14, "critical"),
        ]
        for level, expected_priority in levels_and_expected:
            raw_alert = {"rule": {"id": 1, "level": level, "description": "Test"}}
            env = build_siem_alert_envelope(raw_alert)
            self.assertEqual(env["priority"], expected_priority, f"Level {level} should map to {expected_priority}")

    def test_wazuh_kafka_producer_dry_run(self) -> None:
        producer = WazuhKafkaAlertProducer(dry_run=True)
        fixture_path = FIXTURE_DIR / "alert-fim-checksum.json"
        alert_json = fixture_path.read_text(encoding="utf-8")

        published = producer.publish_alert(alert_json)

        self.assertEqual(len(producer._published_history), 1)
        self.assertEqual(published["event_type"], "wazuh.alert.security")
        self.assertEqual(published["enrichment"]["rule_level"], 9)

    def test_soar_kafka_consumer_level_filtering(self) -> None:
        consumer = SOARKafkaConsumer(min_level=7, dry_run=True)

        low_alert = build_siem_alert_envelope({"rule": {"id": 1, "level": 3, "description": "Low severity"}})
        high_alert = build_siem_alert_envelope({"rule": {"id": 2, "level": 9, "description": "High severity"}})

        res_low = consumer.process_envelope(low_alert)
        res_high = consumer.process_envelope(high_alert)

        self.assertIsNone(res_low, "Low severity alert (<7) should be filtered out")
        self.assertIsNotNone(res_high, "High severity alert (>=7) should be processed")
        self.assertEqual(len(consumer.dispatched_events), 1)
        self.assertEqual(consumer.dispatched_events[0]["rule"]["level"], 9)

    def test_transform_envelope_to_soar_payload(self) -> None:
        raw_alert = {
            "rule": {"id": 100608, "level": 9, "description": "FIM Modified", "groups": ["fim"]},
            "agent": {"id": "002", "name": "srv02", "ip": "198.51.100.50"},
            "data": {"sha256_after": "abcdef1234567890"},
        }
        envelope = build_siem_alert_envelope(raw_alert)
        soar_payload = transform_envelope_to_soar_payload(envelope)

        self.assertEqual(soar_payload["event_id"], envelope["event_id"])
        self.assertEqual(soar_payload["rule"]["id"], 100608)
        self.assertEqual(soar_payload["rule"]["level"], 9)
        self.assertEqual(soar_payload["agent"]["name"], "srv02")
        self.assertEqual(soar_payload["data"]["sha256_after"], "abcdef1234567890")

    def test_end_to_end_wazuh_fixtures_replay(self) -> None:
        """Replay all synthetic Wazuh fixtures through Producer -> Topic -> Consumer -> SOAR Payload."""
        producer = WazuhKafkaAlertProducer(dry_run=True)
        consumer = SOARKafkaConsumer(min_level=7, dry_run=True)

        fixture_paths = sorted(FIXTURE_DIR.glob("alert-*.json"))
        self.assertGreaterEqual(len(fixture_paths), 3)

        envelopes = []
        for path in fixture_paths:
            alert_data = path.read_text(encoding="utf-8")
            env = producer.publish_alert(alert_data)
            envelopes.append(env)

        self.assertEqual(len(envelopes), len(fixture_paths))

        dispatched = consumer.poll_and_process_batch(envelopes)
        self.assertGreaterEqual(len(dispatched), 1)

        for item in dispatched:
            self.assertIn("rule", item)
            self.assertGreaterEqual(item["rule"]["level"], 7)
            self.assertIn("agent", item)
            self.assertIn("envelope", item)


if __name__ == "__main__":
    unittest.main()
