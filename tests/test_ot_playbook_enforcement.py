"""Tests for OT-Safe Playbook Enforcement Engine (SO-03)."""

from pathlib import Path
import unittest
import yaml

from dcim_workflow.ot_safety import (
    AssetClassification,
    AuditRecord,
    BlastRadiusReport,
    OTPlaybookEnforcer,
    ProhibitedOperationError,
    PROHIBITED_OPERATION_CLASSES,
)
from dcim_workflow.incident_response import SafetyPreconditionError

PLAYBOOK_DIR = Path("/home/infra/SOAR/playbooks")


class TestOTPlaybookEnforcement(unittest.TestCase):
    """Unit test suite for OT-Safe Playbook Enforcement Engine and ADR-0025 Preconditions."""

    def setUp(self) -> None:
        self.enforcer = OTPlaybookEnforcer(current_phase=0, enforce_dry_run_only=True)

    def test_load_all_playbook_yaml_fixtures(self) -> None:
        yaml_files = sorted(PLAYBOOK_DIR.glob("*.yaml"))
        self.assertGreaterEqual(len(yaml_files), 4, "Should have at least 4 playbook YAML templates")

        for filepath in yaml_files:
            content = yaml.safe_load(filepath.read_text(encoding="utf-8"))
            self.assertIn("playbook_id", content)
            self.assertIn("steps", content)
            self.assertIn("ot_safe", content)

    def test_advisory_playbook_passes_dry_run(self) -> None:
        playbook_path = PLAYBOOK_DIR / "escalation_soc_incident.yaml"
        playbook = yaml.safe_load(playbook_path.read_text(encoding="utf-8"))

        audit = self.enforcer.evaluate_execution_request(
            playbook=playbook,
            target_ci="srv-web-01",
            asset_classification=AssetClassification.IT_SERVER.value,
            run_id="run-advisory-001",
            is_dry_run=True,
        )

        self.assertEqual(audit.playbook_id, "pb-escalation-soc-incident")
        self.assertTrue(audit.dry_run)
        self.assertTrue(audit.tamper_evidence_hash)

    def test_ot_asset_without_approval_blocks_execution(self) -> None:
        playbook_path = PLAYBOOK_DIR / "containment_host_isolation.yaml"
        playbook = yaml.safe_load(playbook_path.read_text(encoding="utf-8"))

        enforcer = OTPlaybookEnforcer(current_phase=6, enforce_dry_run_only=False)
        with self.assertRaises(SafetyPreconditionError) as ctx:
            enforcer.evaluate_execution_request(
                playbook=playbook,
                target_ci="plc-water-pump-01",
                asset_classification=AssetClassification.OT_PLC.value,
                run_id="run-ot-block-001",
                is_dry_run=False,
                approver_identity=None,  # Missing human approval
                maintenance_window_active=True,
            )
        self.assertIn("Human Approval missing", str(ctx.exception))

    def test_outside_maintenance_window_blocks_execution(self) -> None:
        playbook_path = PLAYBOOK_DIR / "containment_host_isolation.yaml"
        playbook = yaml.safe_load(playbook_path.read_text(encoding="utf-8"))

        enforcer = OTPlaybookEnforcer(current_phase=6, enforce_dry_run_only=False)
        with self.assertRaises(SafetyPreconditionError) as ctx:
            enforcer.evaluate_execution_request(
                playbook=playbook,
                target_ci="plc-water-pump-01",
                asset_classification=AssetClassification.OT_PLC.value,
                run_id="run-ot-maint-001",
                is_dry_run=False,
                approver_identity="analyst-falah",
                maintenance_window_active=False,  # Outside maintenance window
            )
        self.assertIn("Outside active Maintenance Window", str(ctx.exception))

    def test_phase0_dry_run_only_enforcement(self) -> None:
        playbook_path = PLAYBOOK_DIR / "containment_host_isolation.yaml"
        playbook = yaml.safe_load(playbook_path.read_text(encoding="utf-8"))

        enforcer = OTPlaybookEnforcer(current_phase=0, enforce_dry_run_only=True)
        with self.assertRaises(SafetyPreconditionError) as ctx:
            enforcer.evaluate_execution_request(
                playbook=playbook,
                target_ci="srv-web-01",
                asset_classification=AssetClassification.IT_SERVER.value,
                run_id="run-phase0-block-001",
                is_dry_run=False,  # Attempt live execution in Phase 0
            )
        self.assertIn("Only dry-run allowed", str(ctx.exception))

    def test_prohibited_operation_class_permanently_blocked(self) -> None:
        playbook_path = PLAYBOOK_DIR / "ot_critical_safety_block.yaml"
        playbook = yaml.safe_load(playbook_path.read_text(encoding="utf-8"))

        # Even with approval and active maintenance window, prohibited operation class MUST fail!
        with self.assertRaises(ProhibitedOperationError) as ctx:
            self.enforcer.evaluate_execution_request(
                playbook=playbook,
                target_ci="scada-rtu-01",
                asset_classification=AssetClassification.OT_SCADA.value,
                run_id="run-prohibited-001",
                is_dry_run=True,
                approver_identity="admin-root",
                maintenance_window_active=True,
            )
        self.assertIn("permanently prohibited operation class: 'power_reset'", str(ctx.exception))

    def test_missing_step_rollback_plan_rejection(self) -> None:
        bad_playbook = {
            "playbook_id": "pb-bad-no-rollback",
            "ot_safe": False,
            "steps": [
                {
                    "step_id": "step-01",
                    "action_type": "network_quarantine",
                    # Rollback key missing!
                }
            ],
        }
        with self.assertRaises(SafetyPreconditionError) as ctx:
            self.enforcer.validate_playbook_definition(bad_playbook)
        self.assertIn("lacks a mandatory rollback plan", str(ctx.exception))

    def test_blast_radius_validation(self) -> None:
        valid_report = BlastRadiusReport(
            affected_cis=["ci-01", "ci-02"],
            impact_scope="service-group",
            dependency_chain=["ci-db-01"],
            estimated_blast_duration="15m",
            blast_radius_confidence="high",
        )
        valid_report.validate()

        invalid_report = BlastRadiusReport(
            affected_cis=[],  # Empty
            impact_scope="invalid-scope",
            dependency_chain=[],
            estimated_blast_duration="5m",
            blast_radius_confidence="low",
        )
        with self.assertRaises(SafetyPreconditionError):
            invalid_report.validate()

    def test_audit_record_pre_execution_write(self) -> None:
        playbook_path = PLAYBOOK_DIR / "containment_account_disable.yaml"
        playbook = yaml.safe_load(playbook_path.read_text(encoding="utf-8"))

        audit = self.enforcer.evaluate_execution_request(
            playbook=playbook,
            target_ci="user-johndoe",
            asset_classification=AssetClassification.IT_ENDPOINT.value,
            run_id="run-audit-001",
            is_dry_run=True,
        )

        self.assertEqual(len(self.enforcer.audit_log), 1)
        self.assertEqual(self.enforcer.audit_log[0].run_id, "run-audit-001")
        self.assertTrue(audit.tamper_evidence_hash)


if __name__ == "__main__":
    unittest.main()
