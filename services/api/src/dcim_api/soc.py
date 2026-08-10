"""SOC API 12 endpoints for Security Alert Triage, Incident Response, Case Management, and Threat Intel (SI-05).

Conforms to ADR-0004 (Read-Only Integration Plane), ADR-0005 (Dry-Run Automation),
and ADR-0025 (Execution Preconditions).
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal
from uuid import uuid4

# --- Graceful Imports & Minimal Shim for Environments without FastAPI/Pydantic ---
try:
    from fastapi import APIRouter, HTTPException, Query, status
    from pydantic import BaseModel, Field
except ModuleNotFoundError:
    class BaseModel:
        def __init__(self, **kwargs: Any) -> None:
            for k, v in kwargs.items():
                setattr(self, k, v)

        def model_dump(self) -> dict[str, Any]:
            return {k: v for k, v in self.__dict__.items() if not k.startswith("_")}

    def Field(default: Any = None, default_factory: Any = None, **kwargs: Any) -> Any:
        if default_factory is not None:
            return default_factory()
        return default

    def Query(default: Any = None, **kwargs: Any) -> Any:
        return default

    class HTTPException(Exception):
        def __init__(self, status_code: int, detail: str) -> None:
            self.status_code = status_code
            self.detail = detail
            super().__init__(f"HTTP {status_code}: {detail}")

    class _Status:
        HTTP_200_OK = 200
        HTTP_201_CREATED = 201
        HTTP_404_NOT_FOUND = 404
        HTTP_500_INTERNAL_SERVER_ERROR = 500

    status = _Status()

    class APIRouter:
        def __init__(self, prefix: str = "", tags: list[str] | None = None) -> None:
            self.prefix = prefix
            self.tags = tags or []

        def get(self, path: str, **kwargs: Any) -> Any:
            def decorator(func: Any) -> Any:
                return func
            return decorator

        def post(self, path: str, **kwargs: Any) -> Any:
            def decorator(func: Any) -> Any:
                return func
            return decorator

        def patch(self, path: str, **kwargs: Any) -> Any:
            def decorator(func: Any) -> Any:
                return func
            return decorator


router = APIRouter(prefix="/api/v1/soc", tags=["SOC Management"])


# --- Schemas ---

class AlertSummary(BaseModel):
    id: str
    timestamp: str
    rule_id: str
    rule_description: str
    level: int
    agent_id: str
    agent_name: str
    src_ip: str | None = None
    triage_status: Literal["New", "In-Progress", "False-Positive", "Escalated"] = "New"


class AlertDetail(AlertSummary):
    full_log: str | None = None
    decoder_name: str | None = None
    groups: list[str] = Field(default_factory=list)
    raw_payload: dict[str, Any] = Field(default_factory=dict)


class TriageRequest(BaseModel):
    status: Literal["New", "In-Progress", "False-Positive", "Escalated"]
    analyst_notes: str | None = None
    assignee: str | None = None


class IncidentCaseCreate(BaseModel):
    title: str
    severity: Literal["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    source_alert_id: str
    description: str | None = None
    assignee: str | None = None


class IncidentCaseUpdate(BaseModel):
    title: str | None = None
    severity: Literal["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"] | None = None
    status: Literal["NEW", "TRIAGED", "CONTAINED", "ERADICATED", "RECOVERED", "CLOSED"] | None = None
    assignee: str | None = None
    notes: str | None = None


class IncidentCaseClose(BaseModel):
    resolution_summary: str
    is_false_positive: bool = False
    closing_analyst: str


class IncidentCaseResponse(BaseModel):
    case_id: str
    title: str
    severity: str
    status: str
    source_alert_id: str
    created_at: str
    updated_at: str
    assignee: str | None = None
    description: str | None = None
    resolution_summary: str | None = None
    is_false_positive: bool = False
    iris_ticket_id: str | None = None


class ThreatIntelMatch(BaseModel):
    id: str
    timestamp: str
    ioc_type: Literal["ip", "domain", "hash"]
    ioc_value: str
    matched_list: str
    rule_id: str
    agent_name: str
    severity_level: int


class WazuhRuleInfo(BaseModel):
    rule_id: str
    level: int
    description: str
    groups: list[str]
    category: str


class SOCMetricsResponse(BaseModel):
    total_alerts_24h: int
    critical_alerts_count: int
    open_cases_count: int
    true_positive_rate_percent: float
    mttd_minutes: float
    mttr_minutes: float
    top_triggered_rules: list[dict[str, Any]]


class DryRunActionRequest(BaseModel):
    action_type: Literal["isolate_host", "block_ip", "disable_user", "revoke_session"]
    target_identifier: str
    reason: str
    requested_by: str


class DryRunActionResponse(BaseModel):
    action_id: str
    action_type: str
    target_identifier: str
    dry_run: bool = True
    executed: bool = False
    simulated_at: str
    ot_safety_status: str
    message: str


# --- In-Memory Pre-populated Datastores for Phase 2 API Façade ---

_DEMO_ALERTS: dict[str, AlertDetail] = {
    "alt-100600-01": AlertDetail(
        id="alt-100600-01",
        timestamp="2026-08-10T14:10:00Z",
        rule_id="100600",
        rule_description="SSH Brute Force: 5+ failed SSH login attempts from 203.0.113.45 within 2 minutes.",
        level=10,
        agent_id="003",
        agent_name="synthetic-agent-server-03",
        src_ip="203.0.113.45",
        triage_status="New",
        full_log="Aug 10 14:10:00 server sshd[1234]: Failed password for invalid_user from 203.0.113.45 port 54321 ssh2",
        decoder_name="sshd",
        groups=["sshd", "authentication_failures", "bruteforce"],
    ),
    "alt-100608-01": AlertDetail(
        id="alt-100608-01",
        timestamp="2026-08-10T14:05:00Z",
        rule_id="100608",
        rule_description="FIM Alert: Critical system configuration file '/etc/ssh/sshd_config' was modified.",
        level=9,
        agent_id="002",
        agent_name="synthetic-agent-gateway-02",
        src_ip="198.51.100.20",
        triage_status="In-Progress",
        full_log="Integrity check change detected on /etc/ssh/sshd_config",
        decoder_name="syscheck_integrity",
        groups=["syscheck", "fim"],
    ),
}

_DEMO_CASES: dict[str, IncidentCaseResponse] = {
    "INC-2026-001": IncidentCaseResponse(
        case_id="INC-2026-001",
        title="SSH Brute Force Attack Investigation",
        severity="HIGH",
        status="TRIAGED",
        source_alert_id="alt-100600-01",
        created_at="2026-08-10T14:15:00Z",
        updated_at="2026-08-10T14:20:00Z",
        assignee="soc-analyst-1",
        description="Multiple failed SSH authentications from external IP range.",
        iris_ticket_id="IRIS-8841",
    )
}


# --- 12 Endpoints Implementation ---

# 1. List Alerts
@router.get("/alerts", response_model=list[AlertSummary])
async def list_alerts(
    min_level: int = Query(default=0, ge=0, le=15),
    rule_id: str | None = Query(default=None),
    triage_status: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=500),
) -> list[AlertSummary]:
    """1. Get list of security alerts from SIEM pipeline."""
    results = []
    for alert in _DEMO_ALERTS.values():
        if alert.level < min_level:
            continue
        if rule_id and alert.rule_id != rule_id:
            continue
        if triage_status and alert.triage_status != triage_status:
            continue
        results.append(alert)
        if len(results) >= limit:
            break
    return results


# 2. Get Single Alert Detail
@router.get("/alerts/{alert_id}", response_model=AlertDetail)
async def get_alert_detail(alert_id: str) -> AlertDetail:
    """2. Get detailed security alert info by Alert ID."""
    if alert_id not in _DEMO_ALERTS:
        raise HTTPException(status_code=404, detail=f"Alert '{alert_id}' not found")
    return _DEMO_ALERTS[alert_id]


# 3. Triage Alert
@router.post("/alerts/{alert_id}/triage", response_model=AlertSummary)
async def triage_alert(alert_id: str, payload: TriageRequest) -> AlertSummary:
    """3. Triage and update alert status (New, In-Progress, False-Positive, Escalated)."""
    if alert_id not in _DEMO_ALERTS:
        raise HTTPException(status_code=404, detail=f"Alert '{alert_id}' not found")
    alert = _DEMO_ALERTS[alert_id]
    _DEMO_ALERTS[alert_id] = AlertDetail(
        **{**alert.model_dump(), "triage_status": payload.status}
    )
    return _DEMO_ALERTS[alert_id]


# 4. List Cases
@router.get("/cases", response_model=list[IncidentCaseResponse])
async def list_incident_cases(
    status_filter: str | None = Query(default=None, alias="status"),
    severity: str | None = Query(default=None),
) -> list[IncidentCaseResponse]:
    """4. List SOC incident cases."""
    results = []
    for case in _DEMO_CASES.values():
        if status_filter and case.status != status_filter:
            continue
        if severity and case.severity != severity:
            continue
        results.append(case)
    return results


# 5. Create Case
@router.post("/cases", response_model=IncidentCaseResponse, status_code=status.HTTP_201_CREATED)
async def create_incident_case(payload: IncidentCaseCreate) -> IncidentCaseResponse:
    """5. Create a new incident case (linked to DFIR IRIS / Internal Case Management)."""
    case_id = f"INC-2026-{uuid4().hex[:4].upper()}"
    now = datetime.now(timezone.utc).isoformat()
    new_case = IncidentCaseResponse(
        case_id=case_id,
        title=payload.title,
        severity=payload.severity,
        status="NEW",
        source_alert_id=payload.source_alert_id,
        created_at=now,
        updated_at=now,
        assignee=payload.assignee,
        description=payload.description,
        iris_ticket_id=f"IRIS-{uuid4().hex[:4].upper()}",
    )
    _DEMO_CASES[case_id] = new_case
    return new_case


# 6. Get Single Case
@router.get("/cases/{case_id}", response_model=IncidentCaseResponse)
async def get_incident_case(case_id: str) -> IncidentCaseResponse:
    """6. Get specific incident case details."""
    if case_id not in _DEMO_CASES:
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found")
    return _DEMO_CASES[case_id]


# 7. Update Case
@router.patch("/cases/{case_id}", response_model=IncidentCaseResponse)
async def update_incident_case(case_id: str, payload: IncidentCaseUpdate) -> IncidentCaseResponse:
    """7. Update incident case status, assignee, or priority."""
    if case_id not in _DEMO_CASES:
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found")
    case = _DEMO_CASES[case_id]
    updated_data = case.model_dump()
    if getattr(payload, "title", None) is not None:
        updated_data["title"] = payload.title
    if getattr(payload, "severity", None) is not None:
        updated_data["severity"] = payload.severity
    if getattr(payload, "status", None) is not None:
        updated_data["status"] = payload.status
    if getattr(payload, "assignee", None) is not None:
        updated_data["assignee"] = payload.assignee
    updated_data["updated_at"] = datetime.now(timezone.utc).isoformat()

    updated_case = IncidentCaseResponse(**updated_data)
    _DEMO_CASES[case_id] = updated_case
    return updated_case


# 8. Close Case
@router.post("/cases/{case_id}/close", response_model=IncidentCaseResponse)
async def close_incident_case(case_id: str, payload: IncidentCaseClose) -> IncidentCaseResponse:
    """8. Close an incident case with resolution summary."""
    if case_id not in _DEMO_CASES:
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found")
    case = _DEMO_CASES[case_id]
    now = datetime.now(timezone.utc).isoformat()
    closed_case = IncidentCaseResponse(
        **{
            **case.model_dump(),
            "status": "CLOSED",
            "resolution_summary": payload.resolution_summary,
            "is_false_positive": payload.is_false_positive,
            "updated_at": now,
        }
    )
    _DEMO_CASES[case_id] = closed_case
    return closed_case


# 9. Query Threat Intel Matches
@router.get("/threat-intel/matches", response_model=list[ThreatIntelMatch])
async def get_threat_intel_matches(
    ioc_type: Literal["ip", "domain", "hash"] | None = Query(default=None),
) -> list[ThreatIntelMatch]:
    """9. Query threat intel matches against 450K+ IOC CDB lists."""
    matches = [
        ThreatIntelMatch(
            id="ti-match-001",
            timestamp="2026-08-10T14:12:00Z",
            ioc_type="ip",
            ioc_value="203.0.113.45",
            matched_list="malicious-ip",
            rule_id="100604",
            agent_name="synthetic-agent-server-03",
            severity_level=10,
        ),
        ThreatIntelMatch(
            id="ti-match-002",
            timestamp="2026-08-10T14:14:00Z",
            ioc_type="domain",
            ioc_value="malicious-phishing-domain.example",
            matched_list="Alienvault-malicious-domains",
            rule_id="100605",
            agent_name="synthetic-agent-gateway-02",
            severity_level=10,
        ),
    ]
    if ioc_type:
        return [m for m in matches if m.ioc_type == ioc_type]
    return matches


# 10. List Detection Rules
@router.get("/rules", response_model=list[WazuhRuleInfo])
async def list_detection_rules() -> list[WazuhRuleInfo]:
    """10. List active Wazuh detection rules & severity levels."""
    return [
        WazuhRuleInfo(rule_id="100200", level=7, description="Systemd service stopped", groups=["systemd"], category="Availability"),
        WazuhRuleInfo(rule_id="100401", level=3, description="MikroTik User Login", groups=["mikrotik"], category="Authentication"),
        WazuhRuleInfo(rule_id="100501", level=7, description="pfSense WebGUI Failed Login", groups=["pfsense"], category="Authentication"),
        WazuhRuleInfo(rule_id="100600", level=10, description="SSH Brute Force 5+ Failed Logins", groups=["sshd", "bruteforce"], category="Security"),
        WazuhRuleInfo(rule_id="100604", level=10, description="Threat Intel IOC Match - Malicious IP", groups=["threat_intel"], category="ThreatIntel"),
        WazuhRuleInfo(rule_id="100608", level=9, description="FIM Alert - Critical Configuration Modified", groups=["fim"], category="Integrity"),
    ]


# 11. SOC Metrics
@router.get("/metrics", response_model=SOCMetricsResponse)
async def get_soc_metrics() -> SOCMetricsResponse:
    """11. Get aggregated SOC operational metrics (MTTD, MTTR, TP/FP rate)."""
    return SOCMetricsResponse(
        total_alerts_24h=142,
        critical_alerts_count=5,
        open_cases_count=len([c for c in _DEMO_CASES.values() if c.status != "CLOSED"]),
        true_positive_rate_percent=92.5,
        mttd_minutes=4.2,
        mttr_minutes=18.5,
        top_triggered_rules=[
            {"rule_id": "100600", "description": "SSH Brute Force", "count": 58},
            {"rule_id": "100501", "description": "pfSense WebGUI Failed Login", "count": 24},
            {"rule_id": "100604", "description": "Threat Intel Malicious IP", "count": 12},
        ],
    )


# 12. Dry-Run Containment Action
@router.post("/actions/dry-run", response_model=DryRunActionResponse)
async def simulate_containment_action(payload: DryRunActionRequest) -> DryRunActionResponse:
    """12. Execute dry-run containment simulation (ADR-0005 & ADR-0025 OT-safe policy)."""
    now = datetime.now(timezone.utc).isoformat()
    return DryRunActionResponse(
        action_id=f"act-{uuid4().hex[:6]}",
        action_type=payload.action_type,
        target_identifier=payload.target_identifier,
        dry_run=True,
        executed=False,
        simulated_at=now,
        ot_safety_status="PASS - OT-Safe Enforcement Active (No side-effects performed)",
        message=f"Dry-run simulation for '{payload.action_type}' on '{payload.target_identifier}' succeeded safely.",
    )
