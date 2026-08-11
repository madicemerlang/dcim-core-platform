# Wazuh SIEM Integration Architecture

## Architectural Overview

```mermaid
graph TD
    subgraph SIEM Satellite Domain [/home/infra/SIEM]
        A[Syslog Devices: MikroTik, pfSense, Linux] -->|Syslog 514/UDP| B[rsyslog daemon]
        B -->|Local Socket| C[Wazuh Manager v4.14.5]
        C -->|local_decoder.xml| D[Wazuh Decoders]
        D -->|local_rules.xml & CDB lists| E[Wazuh Engine]
        E -->|integrations/custom-kafka| F[Kafka Producer]
    end

    subgraph Messaging Infrastructure
        F -->|Topic: dcim.siem.events| G[Kafka Cluster 198.51.100.56:9092]
    end

    subgraph DCIM Core Platform [/home/infra/dcim-core-platform]
        G -->|Ingestion Plane| H[connectors/wazuh/adapter.py]
        H -->|CanonicalEnvelope| I[CMDB / Event Repository]
    end
```

## Correlation & Data Mapping Matrix

| SIEM Log Source | Wazuh Decoder | Wazuh Rule ID | Target Topic / Event Class | DCIM Platform Mapping |
|---|---|---|---|---|
| MikroTik Router Reboot | `mikrotik-router-reboot` | `100402` | `dcim.siem.events` | System Lifecycle Event |
| MikroTik User Auth | `mikrotik-user-login` / `100401` | `100401` | `dcim.siem.events` | Access Management Audit |
| pfSense WebGUI Auth | `pfsense-webgui-failed` / `logout` | `100501` / `100502` | `dcim.siem.events` | Gateway Security Event |
| Threat Intel Matches | `alienvault-cdb` / `malicious-ip` | `100604` / `100605` | `dcim.siem.events` | Incident Trigger |
| Systemd Service Fail | `systemd-service-status` | `100200` | `dcim.siem.events` | Service Availability Event |
| FIM Integrity | `syscheck_integrity` | `100608` | `dcim.siem.events` | Change Control Audit |

## Compliance & Governance
- **ADR-0004**: Read-Only integration plane (Inbound event stream only).
- **ADR-0023**: Connector controls (Ceilings and Kill-switch support).
- **ADR-0029**: Direct connector boundary specification.
