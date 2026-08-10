# Wazuh SIEM Connector

## Overview
This connector provides the ingestion boundary and fixture replay adapter for Wazuh Manager integration into DCIM Core Platform.

## Architecture
- **Direction**: Inbound-only (ADR-0004)
- **Transport**: JSON / Avro payload over Kafka (`dcim.siem.events`) or Syslog
- **Replay**: `WazuhFixtureAdapter` replays synthetic JSON envelopes compliant with ADR-0023 connector controls and ADR-0029 decision record.

## Contract Ceilings (ADR-0023 / ADR-0029)
- `poll_interval_seconds`: Minimum 30s
- `read_timeout_seconds`: Maximum 10s

## Usage Example
```python
from pathlib import Path
from connectors.wazuh import WazuhFixtureAdapter

adapter = WazuhFixtureAdapter(
    fixture_paths=[Path("fixtures/synthetic/wazuh/alert-service-stop.json")],
    clock="2026-08-10T14:00:00Z",
    kill_flag=lambda: False,
    stop_file=None,
)

for event in adapter:
    print(event["event_id"], event["source"]["system"])
```
