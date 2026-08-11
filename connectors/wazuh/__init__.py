"""Wazuh SIEM connector package."""

from connectors.wazuh.adapter import (
    WAZUH_MAX_READ_TIMEOUT_SECONDS,
    WAZUH_MIN_POLL_INTERVAL_SECONDS,
    WazuhFixtureAdapter,
)
from connectors.wazuh.kafka_producer import (
    WazuhKafkaAlertProducer,
    build_siem_alert_envelope,
)
from connectors.wazuh.soar_kafka_consumer import (
    SOARKafkaConsumer,
    transform_envelope_to_soar_payload,
)

__all__ = [
    "WAZUH_MAX_READ_TIMEOUT_SECONDS",
    "WAZUH_MIN_POLL_INTERVAL_SECONDS",
    "WazuhFixtureAdapter",
    "WazuhKafkaAlertProducer",
    "build_siem_alert_envelope",
    "SOARKafkaConsumer",
    "transform_envelope_to_soar_payload",
]
