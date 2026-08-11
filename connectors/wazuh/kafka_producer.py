"""Wazuh SIEM to Kafka Alert Producer.

Enforces ADR-0004 inbound normalization and ADR-0023 contract schemas.
Publishes normalized Wazuh security alerts to Kafka topic `dcim.siem.alerts`.
"""

from __future__ import annotations

import json
import os
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Optional

from connectors.wazuh.adapter import parse_wazuh_event, WazuhFixtureError
from scripts.phase2.errors import Phase2Error


DEFAULT_KAFKA_BOOTSTRAP: str = "198.51.100.56:9092"
DEFAULT_KAFKA_TOPIC: str = "dcim.siem.alerts"


class KafkaPublishError(Phase2Error):
    """Raised when publishing a Wazuh alert to Kafka fails."""
    pass


def build_siem_alert_envelope(
    wazuh_alert: Dict[str, Any],
    observed_at: Optional[str] = None,
    instance: str = "wazuh-manager-01",
) -> Dict[str, Any]:
    """Wrap a Wazuh alert dict into a canonical DCIM Event Envelope.

    Refers to `schemas/event-envelope.schema.json`.
    """
    now_utc = observed_at or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # Use adapter to normalize source & wazuh payload
    normalized = parse_wazuh_event(raw_payload=wazuh_alert, observed_at=now_utc, default_instance=instance)

    wazuh_data = normalized.get("wazuh", {})
    rule_data = wazuh_data.get("rule", {}) if isinstance(wazuh_data, dict) else {}
    rule_level = rule_data.get("level", 0) if isinstance(rule_data, dict) else 0

    # Determine priority based on rule level
    if rule_level >= 12:
        priority = "critical"
    elif rule_level >= 9:
        priority = "high"
    elif rule_level >= 7:
        priority = "medium"
    else:
        priority = "low"

    event_id = str(uuid.uuid4())
    envelope: Dict[str, Any] = {
        "schema_version": "0.1.0",
        "event_id": event_id,
        "occurred_at": wazuh_alert.get("timestamp") or now_utc,
        "observed_at": now_utc,
        "source": {
            "system": "wazuh-siem",
            "instance": instance,
            "connector": "custom-wazuh2kafka",
            "transport": "rest",
            "native_event_id": str(rule_data.get("id", "unknown")),
        },
        "event_type": "wazuh.alert.security",
        "priority": priority,
        "correlation_id": f"corr-wazuh-{event_id[:8]}",
        "payload": normalized,
        "enrichment": {
            "rule_level": rule_level,
            "rule_description": rule_data.get("description", "Wazuh Security Alert"),
            "groups": rule_data.get("groups", []),
        },
    }
    return envelope


class WazuhKafkaAlertProducer:
    """Producer for emitting Wazuh alerts to Kafka `dcim.siem.alerts`."""

    def __init__(
        self,
        bootstrap_servers: Optional[str] = None,
        topic: str = DEFAULT_KAFKA_TOPIC,
        dry_run: bool = False,
    ) -> None:
        self.bootstrap_servers = bootstrap_servers or os.environ.get("DCIM_KAFKA_BOOTSTRAP", DEFAULT_KAFKA_BOOTSTRAP)
        self.topic = topic
        self.dry_run = dry_run
        self._published_history: list[Dict[str, Any]] = []

    def publish_alert(self, alert_payload: str | bytes | Dict[str, Any]) -> Dict[str, Any]:
        """Normalize, envelope, and publish a Wazuh alert."""
        if isinstance(alert_payload, (str, bytes)):
            try:
                alert_dict = json.loads(alert_payload if isinstance(alert_payload, str) else alert_payload.decode("utf-8"))
            except Exception as exc:
                raise WazuhFixtureError(f"Failed to decode alert JSON: {exc}") from exc
        else:
            alert_dict = alert_payload

        envelope = build_siem_alert_envelope(alert_dict)

        if self.dry_run:
            self._published_history.append(envelope)
            return envelope

        # Live publishing via confluent_kafka or kafka-python
        try:
            try:
                from confluent_kafka import Producer
                p = Producer({"bootstrap.servers": self.bootstrap_servers})
                p.produce(
                    self.topic,
                    key=envelope["event_id"].encode("utf-8"),
                    value=json.dumps(envelope).encode("utf-8"),
                )
                p.flush(timeout=5.0)
            except ImportError:
                from kafka import KafkaProducer
                p = KafkaProducer(
                    bootstrap_servers=[self.bootstrap_servers],
                    value_serializer=lambda v: json.dumps(v).encode("utf-8"),
                )
                p.send(self.topic, key=envelope["event_id"].encode("utf-8"), value=envelope)
                p.flush()
                p.close()

            self._published_history.append(envelope)
            return envelope
        except Exception as exc:
            # Record in history for fallback inspectability and raise
            self._published_history.append(envelope)
            raise KafkaPublishError(f"Failed to publish Wazuh alert to Kafka topic '{self.topic}': {exc}") from exc


def main() -> None:
    """CLI entrypoint for Wazuh Manager `<integration>` script."""
    if len(sys.argv) < 2:
        print("Usage: python -m connectors.wazuh.kafka_producer <alert_json_path> [bootstrap_servers]", file=sys.stderr)
        sys.exit(1)

    alert_path = Path(sys.argv[1])
    bootstrap = sys.argv[2] if len(sys.argv) > 2 else None

    if not alert_path.exists():
        print(f"Error: Alert file '{alert_path}' not found.", file=sys.stderr)
        sys.exit(1)

    try:
        alert_content = alert_path.read_text(encoding="utf-8")
        producer = WazuhKafkaAlertProducer(bootstrap_servers=bootstrap)
        published = producer.publish_alert(alert_content)
        print(f"Successfully published alert {published['event_id']} to topic '{producer.topic}'")
    except Exception as exc:
        print(f"Error publishing alert to Kafka: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
