"""Tests for the 6-state Incident Response workflow state machine."""

import os
import sys
import unittest
from datetime import datetime, timezone

# Ensure repo root and service package paths are in sys.path for unittest discovery
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

WORKFLOW_SRC = os.path.join(REPO_ROOT, "services/workflow/src")
if WORKFLOW_SRC not in sys.path:
    sys.path.insert(0, WORKFLOW_SRC)

from dcim_workflow.incident_response import (
    IncidentCase,
    IncidentState,
    InvalidStateTransitionError,
    SafetyPreconditionError,
    SeverityLevel,
)


class TestIncidentResponseWorkflow(unittest.TestCase):
    def test_full_6_state_lifecycle_happy_path(self) -> None:
        case = IncidentCase(
            case_id="INC-2026-0001",
            title="SSH Brute Force Attack Detected",
            severity=SeverityLevel.HIGH,
            source_event_id="wazuh-event-100600",
            assignee="soc-analyst-1",
        )

        # 1. State: NEW
        self.assertEqual(case.current_state, IncidentState.NEW)

        # 2. Transition: NEW -> TRIAGED
        case.transition_to(
            IncidentState.TRIAGED,
            actor="soc-analyst-1",
            reason="Confirmed 15 failed SSH logins from IP 203.0.113.45",
        )
        self.assertEqual(case.current_state, IncidentState.TRIAGED)

        # 3. Transition: TRIAGED -> CONTAINED
        case.transition_to(
            IncidentState.CONTAINED,
            actor="soar-bot",
            reason="Blocked source IP on firewall boundary (Dry-run mode)",
            dry_run=True,
        )
        self.assertEqual(case.current_state, IncidentState.CONTAINED)

        # 4. Transition: CONTAINED -> ERADICATED
        case.transition_to(
            IncidentState.ERADICATED,
            actor="soc-analyst-1",
            reason="Invalidated targeted user sessions and locked SSH port",
        )
        self.assertEqual(case.current_state, IncidentState.ERADICATED)

        # 5. Transition: ERADICATED -> RECOVERED
        case.transition_to(
            IncidentState.RECOVERED,
            actor="sysadmin",
            reason="Verified service health and restored normal access",
        )
        self.assertEqual(case.current_state, IncidentState.RECOVERED)

        # 6. Transition: RECOVERED -> CLOSED
        case.transition_to(
            IncidentState.CLOSED,
            actor="soc-lead",
            reason="Post-incident review complete. DFIR IRIS Ticket #884 closed.",
        )
        self.assertEqual(case.current_state, IncidentState.CLOSED)
        self.assertEqual(len(case.history), 5)

    def test_false_positive_triage_to_closed(self) -> None:
        case = IncidentCase(
            case_id="INC-2026-0002",
            title="Potential FIM Checksum Change /etc/hosts",
            severity=SeverityLevel.LOW,
            source_event_id="wazuh-event-100608",
        )

        # NEW -> TRIAGED -> CLOSED (False Positive)
        case.transition_to(
            IncidentState.TRIAGED,
            actor="soc-analyst-2",
            reason="Inspected checksum difference",
        )
        case.transition_to(
            IncidentState.CLOSED,
            actor="soc-analyst-2",
            reason="Scheduled automated Ansible maintenance update",
            false_positive=True,
        )

        self.assertEqual(case.current_state, IncidentState.CLOSED)
        self.assertTrue(case.is_false_positive)

    def test_invalid_state_transition_raises_error(self) -> None:
        case = IncidentCase(
            case_id="INC-2026-0003",
            title="Unauthorized Root Sudo",
            severity=SeverityLevel.MEDIUM,
            source_event_id="wazuh-event-100602",
        )

        # Direct transition NEW -> ERADICATED should fail
        with self.assertRaises(InvalidStateTransitionError):
            case.transition_to(
                IncidentState.ERADICATED,
                actor="soc-analyst-1",
                reason="Invalid direct jump",
            )

    def test_critical_unassigned_containment_safety_precondition(self) -> None:
        case = IncidentCase(
            case_id="INC-2026-0004",
            title="Ransomware Hash Detection",
            severity=SeverityLevel.CRITICAL,
            source_event_id="wazuh-event-100604",
            assignee=None,  # No assignee
        )

        case.transition_to(
            IncidentState.TRIAGED,
            actor="auto-triage",
            reason="Automated triage",
        )

        with self.assertRaises(SafetyPreconditionError):
            case.transition_to(
                IncidentState.CONTAINED,
                actor="auto-triage",
                reason="Attempting active containment without assignee",
                dry_run=False,
            )


if __name__ == "__main__":
    unittest.main()
