"""Tests for OT-Safe Playbook Enforcement Engine (SO-03)."""

from pathlib import Path
import json
import os
import re
import sys
import unittest

# ---------------------------------------------------------------------------
# Ensure repo-root and service packages are importable without PYTHONPATH
# ---------------------------------------------------------------------------
REPO_ROOT = str(Path(__file__).resolve().parent.parent)
WORKFLOW_SRC = os.path.join(REPO_ROOT, "services", "workflow", "src")
for _p in (REPO_ROOT, WORKFLOW_SRC):
    if _p not in sys.path:
        sys.path.insert(0, _p)

# ---------------------------------------------------------------------------
# Lightweight YAML loader — uses PyYAML when available, otherwise falls back
# to a minimal parser sufficient for the playbook fixture files used here.
# ---------------------------------------------------------------------------
try:
    import yaml as _yaml

    def _load_yaml(text: str) -> dict:
        return _yaml.safe_load(text)

except ModuleNotFoundError:
    def _load_yaml(text: str) -> dict:  # type: ignore[misc]
        """Minimal YAML-subset parser for simple playbook fixtures.

        Handles:
        - scalar key: value pairs (strings, ints, bools)
        - list items indicated by ``- ``
        - nested mappings via 2-space indentation
        """
        root: dict = {}
        stack: list[tuple[int, dict | list]] = [(-1, root)]

        for raw_line in text.splitlines():
            stripped = raw_line.rstrip()
            if not stripped or stripped.lstrip().startswith("#"):
                continue

            indent = len(raw_line) - len(raw_line.lstrip())

            # Pop back to correct nesting level
            while len(stack) > 1 and indent <= stack[-1][0]:
                stack.pop()

            _, current = stack[-1]

            # List item
            if stripped.lstrip().startswith("- "):
                item_text = stripped.lstrip()[2:]
                if isinstance(current, list):
                    container = current
                else:
                    # Should not happen for well-formed fixtures
                    container = current  # type: ignore[assignment]

                if ":" in item_text:
                    obj: dict = {}
                    k, v = item_text.split(":", 1)
                    obj[k.strip()] = _yaml_scalar(v.strip())
                    container.append(obj)  # type: ignore[union-attr]
                    stack.append((indent + 2, obj))
                else:
                    container.append(_yaml_scalar(item_text))  # type: ignore[union-attr]
                continue

            # Key: value
            if ":" in stripped:
                key, _, val = stripped.partition(":")
                key = key.strip()
                val = val.strip()
                if val == "":
                    # Could be a nested mapping or list — peek ahead is hard,
                    # so create a dict placeholder; if next lines are ``- ``,
                    # we will convert on the fly.
                    child: dict | list = {}
                    if isinstance(current, dict):
                        current[key] = child
                    stack.append((indent + 2, child))
                elif val.startswith("[") and val.endswith("]"):
                    # Inline list  e.g.  affected_cis: [ci-01, ci-02]
                    items = [_yaml_scalar(x.strip().strip("'\"")) for x in val[1:-1].split(",") if x.strip()]
                    if isinstance(current, dict):
                        current[key] = items
                elif val.startswith("{") and val.endswith("}"):
                    if isinstance(current, dict):
                        current[key] = json.loads(val)
                else:
                    if isinstance(current, dict):
                        current[key] = _yaml_scalar(val)

            # Check if we need to convert a dict placeholder to a list
            # (happens when the first child is a list item)

        # Convert empty dict placeholders that received list items
        _convert_empty_dicts(root)
        return root

    def _yaml_scalar(value: str):
        """Convert a YAML scalar string to a Python type."""
        if value in ("true", "True", "yes"):
            return True
        if value in ("false", "False", "no"):
            return False
        if value in ("null", "~", ""):
            return None
        # Strip surrounding quotes
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ('"', "'"):
            return value[1:-1]
        try:
            return int(value)
        except ValueError:
            pass
        try:
            return float(value)
        except ValueError:
            pass
        return value

    def _convert_empty_dicts(node):
        """Recursively convert dict placeholders that should be lists."""
        if isinstance(node, dict):
            for k, v in list(node.items()):
                if isinstance(v, dict) and not v:
                    # Remains empty dict — fine
                    pass
                elif isinstance(v, (dict, list)):
                    _convert_empty_dicts(v)
        elif isinstance(node, list):
            for item in node:
                if isinstance(item, (dict, list)):
                    _convert_empty_dicts(item)


def _load_yaml_file(filepath: Path) -> dict:
    """Load a YAML file using the best available parser."""
    return _load_yaml(filepath.read_text(encoding="utf-8"))


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
            content = _load_yaml_file(filepath)
            self.assertIn("playbook_id", content)
            self.assertIn("steps", content)
            self.assertIn("ot_safe", content)

    def test_advisory_playbook_passes_dry_run(self) -> None:
        playbook_path = PLAYBOOK_DIR / "escalation_soc_incident.yaml"
        playbook = _load_yaml_file(playbook_path)

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
        playbook = _load_yaml_file(playbook_path)

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
        playbook = _load_yaml_file(playbook_path)

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
        playbook = _load_yaml_file(playbook_path)

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
        playbook = _load_yaml_file(playbook_path)

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
        playbook = _load_yaml_file(playbook_path)

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
