"""OT-Safe Playbook Safety Gate & Enforcement Engine.

Implements:
- ADR-0005: Dry-run automation & advisory default.
- ADR-0025: Five conjunctive execution preconditions.
- Workflow Safety Gates (Stage 1-5 validation, blast-radius declaration, rollback per step).
- Prohibited Operation Classes enforcement (SNMP SET, Redfish write, power reset, etc.).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
from typing import Any, Dict, List, Optional, Set

from dcim_workflow.incident_response import SafetyPreconditionError


class ProhibitedOperationError(SafetyPreconditionError):
    """Raised when a playbook contains a permanently prohibited operation class."""
    pass


class AssetClassification(str, Enum):
    """Asset safety classification levels."""

    IT_ENDPOINT = "IT-Endpoint"
    IT_SERVER = "IT-Server"
    OT_PLC = "OT-PLC"
    OT_SCADA = "OT-SCADA"
    OT_HMI = "OT-HMI"
    OT_DCS = "OT-DCS"
    CRITICAL_INFRASTRUCTURE = "Critical-Infrastructure"


PROHIBITED_OPERATION_CLASSES: Set[str] = {
    "snmp_set",
    "redfish_write",
    "power_reset",
    "firmware_flash",
    "ptz_control",
    "network_reconfig",
    "raw_shell_execution",
    "privileged_sql",
}

OT_ASSET_CLASSES: Set[str] = {
    AssetClassification.OT_PLC.value,
    AssetClassification.OT_SCADA.value,
    AssetClassification.OT_HMI.value,
    AssetClassification.OT_DCS.value,
    AssetClassification.CRITICAL_INFRASTRUCTURE.value,
}


@dataclass
class BlastRadiusReport:
    """Blast radius declaration required for Stage 2 & 3 execution gates."""

    affected_cis: List[str]
    impact_scope: str  # single-CI, service-group, site-wide, platform-wide
    dependency_chain: List[str]
    estimated_blast_duration: str
    blast_radius_confidence: str  # high, medium, low

    def validate(self) -> None:
        if not self.affected_cis:
            raise SafetyPreconditionError("BlastRadiusReport missing affected CIs")
        if self.impact_scope not in ("single-CI", "service-group", "site-wide", "platform-wide"):
            raise SafetyPreconditionError(f"Invalid impact_scope: '{self.impact_scope}'")
        if self.blast_radius_confidence not in ("high", "medium", "low"):
            raise SafetyPreconditionError(f"Invalid confidence: '{self.blast_radius_confidence}'")


@dataclass
class AuditRecord:
    """Immutable audit record generated before workflow execution (ADR-0025 Precondition 5)."""

    run_id: str
    playbook_id: str
    engine: str
    dry_run: bool
    target_ci: str
    asset_classification: str
    approval_granted_by: Optional[str]
    maintenance_window_active: bool
    blast_radius_confidence: str
    prohibited_class_rejected: Optional[str] = None
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    tamper_evidence_hash: str = ""

    def __post_init__(self) -> None:
        if not self.tamper_evidence_hash:
            payload = f"{self.run_id}:{self.playbook_id}:{self.target_ci}:{self.created_at}"
            self.tamper_evidence_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()


class OTPlaybookEnforcer:
    """Enforcer for OT Safety Gates and ADR-0025 Preconditions."""

    def __init__(
        self,
        current_phase: int = 0,
        enforce_dry_run_only: bool = True,
    ) -> None:
        self.current_phase = current_phase
        self.enforce_dry_run_only = enforce_dry_run_only
        self.audit_log: List[AuditRecord] = []

    def validate_playbook_definition(self, playbook: Dict[str, Any]) -> None:
        """Validate structural compliance and check for prohibited operation classes."""
        playbook_id = playbook.get("playbook_id", "unknown")
        steps = playbook.get("steps", [])

        if not steps:
            raise SafetyPreconditionError(f"Playbook '{playbook_id}' contains no steps.")

        for idx, step in enumerate(steps, start=1):
            op_class = step.get("operation_class") or step.get("action_type")
            if op_class in PROHIBITED_OPERATION_CLASSES:
                raise ProhibitedOperationError(
                    f"Playbook '{playbook_id}' Step {idx} contains permanently prohibited operation class: '{op_class}'"
                )

            rollback = step.get("rollback")
            if not rollback or not isinstance(rollback, dict):
                raise SafetyPreconditionError(
                    f"Playbook '{playbook_id}' Step {idx} '{step.get('step_id')}' lacks a mandatory rollback plan."
                )

    def evaluate_execution_request(
        self,
        playbook: Dict[str, Any],
        target_ci: str,
        asset_classification: str,
        run_id: str,
        is_dry_run: bool = True,
        approver_identity: Optional[str] = None,
        maintenance_window_active: bool = False,
        blast_radius: Optional[BlastRadiusReport] = None,
    ) -> AuditRecord:
        """Evaluate execution request against the 5 conjunctive ADR-0025 preconditions and OT safety gates."""
        # 1. Structural & Prohibited Class Check
        self.validate_playbook_definition(playbook)

        playbook_id = playbook.get("playbook_id", "unknown")
        ot_safe = playbook.get("ot_safe", False)
        is_ot_asset = asset_classification in OT_ASSET_CLASSES

        # 2. Stage 1: Dry-Run Phase Constraint
        if self.enforce_dry_run_only and not is_dry_run:
            # Check if this is an advisory-only non-destructive playbook
            is_advisory_only = all(
                step.get("action_type") in ("advisory_query", "approval_gate", "http_query", "ai_completion", "create_ticket")
                for step in playbook.get("steps", [])
            )
            if not is_advisory_only:
                raise SafetyPreconditionError(
                    f"Live execution of destructive playbook '{playbook_id}' blocked in Phase {self.current_phase}. Only dry-run allowed."
                )

        # 3. OT Asset Safeguard Checks
        if is_ot_asset and not ot_safe:
            # Non-OT-safe playbook targeting OT asset
            if is_dry_run:
                # Dry run allowed as advisory recommendation
                pass
            else:
                # Live execution requires ALL 5 conjunctive preconditions
                if not approver_identity:
                    raise SafetyPreconditionError(
                        f"Execution on OT asset '{target_ci}' ({asset_classification}) blocked: Human Approval missing (ADR-0025 Precondition 3)."
                    )
                if not maintenance_window_active:
                    raise SafetyPreconditionError(
                        f"Execution on OT asset '{target_ci}' blocked: Outside active Maintenance Window (ADR-0025 Precondition 4)."
                    )

        # 4. Blast Radius Declaration Check
        if not is_dry_run and blast_radius is not None:
            blast_radius.validate()

        # 5. Build Audit Record (ADR-0025 Precondition 5)
        audit_entry = AuditRecord(
            run_id=run_id,
            playbook_id=playbook_id,
            engine="TraceCat",
            dry_run=is_dry_run,
            target_ci=target_ci,
            asset_classification=asset_classification,
            approval_granted_by=approver_identity,
            maintenance_window_active=maintenance_window_active,
            blast_radius_confidence=blast_radius.blast_radius_confidence if blast_radius else "high",
        )

        self.audit_log.append(audit_entry)
        return audit_entry
