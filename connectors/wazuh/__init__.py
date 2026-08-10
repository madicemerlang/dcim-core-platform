"""Wazuh SIEM connector package."""

from connectors.wazuh.adapter import (
    WAZUH_MAX_READ_TIMEOUT_SECONDS,
    WAZUH_MIN_POLL_INTERVAL_SECONDS,
    WazuhFixtureAdapter,
)

__all__ = [
    "WAZUH_MAX_READ_TIMEOUT_SECONDS",
    "WAZUH_MIN_POLL_INTERVAL_SECONDS",
    "WazuhFixtureAdapter",
]
