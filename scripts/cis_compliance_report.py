"""CIS Benchmark Compliance Assessment Engine for DCIM Core Platform (SI-06).

Parses Security Configuration Assessment (SCA) findings from Wazuh SIEM
and generates CIS benchmark compliance scores, evidence receipts, and audit summaries.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import ClassVar, Final


class CISBenchmarkLevel(str):
    LEVEL_1 = "Level 1"
    LEVEL_2 = "Level 2"


class CISCheckStatus(str):
    PASS = "PASS"
    FAIL = "FAIL"
    MANUAL = "MANUAL"
    NOT_APPLICABLE = "N/A"


@dataclass(frozen=True)
class CISRuleCheck:
    """Individual CIS Benchmark rule assessment."""

    rule_id: str
    title: str
    description: str
    rationale: str
    level: str
    status: str
    remediation: str


@dataclass
class CISComplianceReport:
    """Aggregated CIS Benchmark Compliance Report for a monitored host/asset."""

    agent_id: str
    agent_name: str
    os_platform: str
    benchmark_title: str
    evaluated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    checks: list[CISRuleCheck] = field(default_factory=list)

    @property
    def total_checks(self) -> int:
        return len(self.checks)

    @property
    def passed_checks(self) -> int:
        return sum(1 for c in self.checks if c.status == CISCheckStatus.PASS)

    @property
    def failed_checks(self) -> int:
        return sum(1 for c in self.checks if c.status == CISCheckStatus.FAIL)

    @property
    def compliance_score(self) -> float:
        """Calculate overall CIS compliance score percentage."""
        scannable = [c for c in self.checks if c.status in (CISCheckStatus.PASS, CISCheckStatus.FAIL)]
        if not scannable:
            return 0.0
        passed = sum(1 for c in scannable if c.status == CISCheckStatus.PASS)
        return round((passed / len(scannable)) * 100.0, 2)

    def summary(self) -> dict[str, str | int | float]:
        return {
            "agent_id": self.agent_id,
            "agent_name": self.agent_name,
            "benchmark_title": self.benchmark_title,
            "compliance_score_percent": self.compliance_score,
            "total_checks": self.total_checks,
            "passed": self.passed_checks,
            "failed": self.failed_checks,
            "evaluated_at": self.evaluated_at,
        }


def evaluate_wazuh_sca_payload(sca_event: dict) -> CISComplianceReport:
    """Parse raw Wazuh Security Configuration Assessment (SCA) event into CISComplianceReport."""
    sca_data = sca_event.get("sca", sca_event)
    agent_info = sca_event.get("agent", {})

    report = CISComplianceReport(
        agent_id=str(agent_info.get("id", "000")),
        agent_name=str(agent_info.get("name", "unknown-agent")),
        os_platform=str(sca_data.get("name", "Linux CIS Benchmark")),
        benchmark_title=str(sca_data.get("policy", "CIS Benchmark for Linux")),
    )

    raw_checks = sca_data.get("checks", sca_data.get("check", []))
    if isinstance(raw_checks, dict):
        raw_checks = [raw_checks]

    for item in raw_checks:
        status_raw = str(item.get("result", item.get("status", "FAIL"))).upper()
        if status_raw in ("PASSED", "PASS"):
            status = CISCheckStatus.PASS
        elif status_raw in ("FAILED", "FAIL"):
            status = CISCheckStatus.FAIL
        else:
            status = CISCheckStatus.MANUAL

        report.checks.append(
            CISRuleCheck(
                rule_id=str(item.get("id", "0.0")),
                title=str(item.get("title", "Untitled Check")),
                description=str(item.get("description", "")),
                rationale=str(item.get("rationale", "")),
                level=str(item.get("compliance", {}).get("cis", ["Level 1"])[0] if isinstance(item.get("compliance"), dict) else "Level 1"),
                status=status,
                remediation=str(item.get("remediation", "")),
            )
        )

    return report
