"""Tests for Wazuh SIEM connector adapter and synthetic fixtures."""

from pathlib import Path
import unittest

from connectors.wazuh import (
    WAZUH_MAX_READ_TIMEOUT_SECONDS,
    WAZUH_MIN_POLL_INTERVAL_SECONDS,
    WazuhFixtureAdapter,
)
from connectors.wazuh.adapter import WazuhFixtureError, parse_wazuh_event
from scripts.phase2.errors import ConnectorCeilingError, KillSwitchEngaged

FIXTURE_DIR = Path("fixtures/synthetic/wazuh")


class TestWazuhConnector(unittest.TestCase):
    def test_wazuh_adapter_iterates_fixtures(self) -> None:
        fixture_paths = sorted(FIXTURE_DIR.glob("*.json"))
        self.assertGreaterEqual(len(fixture_paths), 4)

        adapter = WazuhFixtureAdapter(
            fixture_paths=fixture_paths,
            clock="2026-08-10T14:00:00Z",
            kill_flag=lambda: False,
            stop_file=None,
        )

        envelopes = list(adapter)
        self.assertEqual(len(envelopes), len(fixture_paths))
        for env in envelopes:
            self.assertIn("event_id", env)
            self.assertIn("timestamp", env)
            self.assertEqual(env["observed_at"], "2026-08-10T14:00:00Z")
            self.assertIn("source", env)
            self.assertIn("wazuh", env)

    def test_wazuh_adapter_ceiling_validation(self) -> None:
        fixture_paths = sorted(FIXTURE_DIR.glob("*.json"))

        with self.assertRaises(ConnectorCeilingError):
            WazuhFixtureAdapter(
                fixture_paths=fixture_paths,
                clock="2026-08-10T14:00:00Z",
                kill_flag=lambda: False,
                stop_file=None,
                poll_interval_seconds=10,  # Below min 30s
            )

        with self.assertRaises(ConnectorCeilingError):
            WazuhFixtureAdapter(
                fixture_paths=fixture_paths,
                clock="2026-08-10T14:00:00Z",
                kill_flag=lambda: False,
                stop_file=None,
                read_timeout_seconds=20,  # Above max 10s
            )

    def test_wazuh_adapter_kill_switch(self) -> None:
        fixture_paths = sorted(FIXTURE_DIR.glob("*.json"))
        stop_file = Path("/tmp/wazuh_stop.flag")
        stop_file.touch()

        try:
            adapter = WazuhFixtureAdapter(
                fixture_paths=fixture_paths,
                clock="2026-08-10T14:00:00Z",
                kill_flag=lambda: False,
                stop_file=stop_file,
            )

            with self.assertRaises(KillSwitchEngaged):
                list(adapter)
        finally:
            if stop_file.exists():
                stop_file.unlink()

    def test_parse_wazuh_event_raw_json(self) -> None:
        raw_json = '{"rule": {"id": "100600", "level": 10}, "agent": {"id": "001", "name": "test-agent"}}'
        envelope = parse_wazuh_event(raw_json, observed_at="2026-08-10T14:00:00Z")

        self.assertEqual(envelope["observed_at"], "2026-08-10T14:00:00Z")
        self.assertEqual(envelope["source"]["native_event_id"], "100600")
        self.assertEqual(envelope["wazuh"]["agent"]["name"], "test-agent")

    def test_parse_wazuh_event_invalid_json(self) -> None:
        with self.assertRaises(WazuhFixtureError):
            parse_wazuh_event("invalid json {", observed_at="2026-08-10T14:00:00Z")


if __name__ == "__main__":
    unittest.main()
