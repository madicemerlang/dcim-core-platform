"""SOAR Kafka Consumer Service.

Consumes security alert envelopes from Kafka topic `dcim.siem.alerts`,
filters alerts by minimum level (default >= 7), formats the payload into
SOAR-compatible format, and dispatches to SOAR Ingestion Webhook / HTTP trigger.
"""

from __future__ import annotations

import json
import os
import urllib.request
import urllib.error
from typing import Any, Dict, List, Optional, Tuple

from scripts.phase2.errors import Phase2Error

DEFAULT_KAFKA_BOOTSTRAP: str = "198.51.100.56:9092"
DEFAULT_KAFKA_TOPIC: str = "dcim.siem.alerts"
DEFAULT_SOAR_WEBHOOK_URL: str = "http://localhost:5678/webhook/341f0a50-a4be-41fb-b93f-217712c95238"
MIN_ALERT_LEVEL: int = 7


class SOARConsumerError(Phase2Error):
    """Raised when consuming from Kafka or dispatching to SOAR fails."""
    pass


def transform_envelope_to_soar_payload(envelope: Dict[str, Any]) -> Dict[str, Any]:
    """Transform a DCIM Canonical Event Envelope into SOAR n8n/Tracecat webhook format."""
    payload = envelope.get("payload", {})
    wazuh_data = payload.get("wazuh", {}) if isinstance(payload, dict) else {}

    # Extract rule info
    rule = wazuh_data.get("rule", {}) if isinstance(wazuh_data, dict) else {}

    # Extract agent info
    agent = wazuh_data.get("agent", {}) if isinstance(wazuh_data, dict) else {}

    # Extract data & IOCs
    data = wazuh_data.get("data", {}) if isinstance(wazuh_data, dict) else {}

    soar_payload: Dict[str, Any] = {
        "event_id": envelope.get("event_id"),
        "timestamp": envelope.get("timestamp") or wazuh_data.get("timestamp"),
        "rule": {
            "id": rule.get("id"),
            "level": rule.get("level", 0),
            "description": rule.get("description", "Security Alert"),
            "groups": rule.get("groups", []),
        },
        "agent": {
            "id": agent.get("id", "000"),
            "name": agent.get("name", "unknown-agent"),
            "ip": agent.get("ip", "127.0.0.1"),
        },
        "data": data,
        "source_system": envelope.get("source", {}).get("system", "wazuh-siem"),
        "envelope": envelope,
    }
    return soar_payload


class SOARKafkaConsumer:
    """Consumes alerts from `dcim.siem.alerts` and dispatches to SOAR endpoint."""

    def __init__(
        self,
        bootstrap_servers: Optional[str] = None,
        topic: str = DEFAULT_KAFKA_TOPIC,
        soar_webhook_url: str = DEFAULT_SOAR_WEBHOOK_URL,
        min_level: int = MIN_ALERT_LEVEL,
        dry_run: bool = False,
    ) -> None:
        self.bootstrap_servers = bootstrap_servers or os.environ.get("DCIM_KAFKA_BOOTSTRAP", DEFAULT_KAFKA_BOOTSTRAP)
        self.topic = topic
        self.soar_webhook_url = soar_webhook_url or os.environ.get("SOAR_WEBHOOK_URL", DEFAULT_SOAR_WEBHOOK_URL)
        self.min_level = min_level
        self.dry_run = dry_run
        self.processed_events: List[Dict[str, Any]] = []
        self.dispatched_events: List[Dict[str, Any]] = []

    def process_envelope(self, envelope: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Process a single event envelope: check alert level and dispatch to SOAR if eligible."""
        self.processed_events.append(envelope)

        soar_payload = transform_envelope_to_soar_payload(envelope)
        rule_level = soar_payload["rule"]["level"]

        if rule_level < self.min_level:
            # Skip alerts below threshold
            return None

        if self.dry_run:
            self.dispatched_events.append(soar_payload)
            return soar_payload

        # Dispatch via HTTP POST to SOAR webhook
        try:
            body = json.dumps(soar_payload).encode("utf-8")
            req = urllib.request.Request(
                self.soar_webhook_url,
                data=body,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=5.0) as resp:
                status = resp.status
                if status not in (200, 201, 202):
                    raise SOARConsumerError(f"SOAR webhook returned unexpected HTTP status: {status}")

            self.dispatched_events.append(soar_payload)
            return soar_payload
        except Exception as exc:
            # Log failure and raise exception
            raise SOARConsumerError(f"Failed to dispatch alert {envelope.get('event_id')} to SOAR: {exc}") from exc

    def poll_and_process_batch(self, messages: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Process a batch of envelope dicts (used in consumer loop or test replay)."""
        dispatched: List[Dict[str, Any]] = []
        for msg in messages:
            res = self.process_envelope(msg)
            if res is not None:
                dispatched.append(res)
        return dispatched
