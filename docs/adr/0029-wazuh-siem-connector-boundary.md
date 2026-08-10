# ADR-0029: Wazuh SIEM Connector Boundary and Integration Architecture

- Status: Accepted
- Date: 2026-08-10
- Owner: Security & Platform Architecture Team

## Context and Problem Statement
DCIM Core Platform requires visibility into telemetry, syslog, security events, and infrastructure alerts managed by external SIEM (Security Information and Event Management) systems such as Wazuh Manager v4.14.5. How should DCIM ingest, parse, and correlate Wazuh alerts and inventory events without violating read-only safety constraints and boundary isolation?

## Decision Drivers
* **ADR-0004 Compliance**: Read-only integration plane. Inbound event ingestion only; zero write-back or active response from DCIM to Wazuh.
* **ADR-0023 Controls**: Connectors must enforce contract ceilings (minimum poll interval = 30s, maximum read timeout = 10s) and kill-switch capabilities.
* **Kafka Ingestion Pipeline**: Ingest Wazuh alerts asynchronously via Kafka topic `dcim.siem.events`.
* **Synthetic & Sanitized Replay**: Full unit and integration testing without live SIEM endpoints.

## Considered Options
1. **Direct Wazuh REST API Polling**: DCIM polls Wazuh Manager REST API directly. (Rejected: Adds polling load, requires credential management, violates push preference).
2. **Kafka Asynchronous Integration (Push) + Replay Adapter**: Wazuh integrator script publishes alerts to Kafka `dcim.siem.events`, ingested by DCIM `connectors/wazuh/adapter.py`. (Accepted).

## Decision Outcome
Accepted Option 2:
- Implement `WazuhFixtureAdapter` in `connectors/wazuh/adapter.py` for synthetic replay and JSON/Avro normalization.
- Ingest live alerts via Kafka topic `dcim.siem.events` originating from `/home/infra/SIEM/wazuh-manager/integrations/custom-kafka`.
- Enforce strict read-only boundary (ADR-0004) and ceiling limits (ADR-0023).

## Consequences
* **Positive**: Asynchronous push architecture guarantees zero performance penalty on Wazuh Manager.
* **Positive**: Synthetic fixtures in `fixtures/synthetic/wazuh/` enable RFC 5737 compliant public testing.
* **Negative**: Downstream SOAR automation (n8n/Shuffle) must operate outside DCIM boundaries.
