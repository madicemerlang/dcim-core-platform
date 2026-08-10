"""6-State Incident Response State Machine for SIEM/SOC (NIST SP 800-61 / ISO 27035).

Governed by ADR-0004 (Read-Only Integration), ADR-0005 (Dry-Run Automation),
and ADR-0025 (Execution Preconditions).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import ClassVar, Final


class IncidentState(str, Enum):
    """The 6 formal states of the Incident Response Lifecycle."""

    NEW = "NEW"
    TRIAGED = "TRIAGED"
    CONTAINED = "CONTAINED"
    ERADICATED = "ERADICATED"
    RECOVERED = "RECOVERED"
    CLOSED = "CLOSED"


class SeverityLevel(str, Enum):
    """Incident severity classification."""

    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class InvalidStateTransitionError(ValueError):
    """Raised when an invalid state transition is attempted."""

    pass


class SafetyPreconditionError(RuntimeError):
    """Raised when an action violates safety guards or ADR-0005/ADR-0025 preconditions."""

    pass


# Valid state transition graph
VALID_TRANSITIONS: Final[dict[IncidentState, set[IncidentState]]] = {
    IncidentState.NEW: {IncidentState.TRIAGED, IncidentState.CLOSED},
    IncidentState.TRIAGED: {IncidentState.CONTAINED, IncidentState.CLOSED},  # CLOSED if False Positive
    IncidentState.CONTAINED: {IncidentState.ERADICATED},
    IncidentState.ERADICATED: {IncidentState.RECOVERED},
    IncidentState.RECOVERED: {IncidentState.CLOSED},
    IncidentState.CLOSED: set(),  # Terminal state
}


@dataclass
class IncidentStateHistory:
    """Audit log entry for an incident state transition."""

    from_state: IncidentState
    to_state: IncidentState
    timestamp: str
    actor: str
    reason: str


@dataclass
class IncidentCase:
    """Incident Response Case tracking a security event through its 6-state lifecycle."""

    case_id: str
    title: str
    severity: SeverityLevel
    source_event_id: str
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    current_state: IncidentState = IncidentState.NEW
    assignee: str | None = None
    is_false_positive: bool = False
    iris_ticket_id: str | None = None
    history: list[IncidentStateHistory] = field(default_factory=list)

    def transition_to(
        self,
        new_state: IncidentState,
        actor: str,
        reason: str,
        *,
        dry_run: bool = True,
        false_positive: bool = False,
    ) -> None:
        """Execute a state transition conforming to the 6-state state machine and safety guards."""
        if new_state not in VALID_TRANSITIONS[self.current_state]:
            raise InvalidStateTransitionError(
                f"Cannot transition incident '{self.case_id}' from {self.current_state.value} to {new_state.value}. "
                f"Allowed target states: {[s.value for s in VALID_TRANSITIONS[self.current_state]]}"
            )

        # Enforce ADR-0005 / ADR-0025 Safety Preconditions for Containment & Eradication
        if new_state in (IncidentState.CONTAINED, IncidentState.ERADICATED) and not dry_run:
            if self.severity == SeverityLevel.CRITICAL and not self.assignee:
                raise SafetyPreconditionError(
                    "ADR-0025 Precondition Violation: Critical incident active containment requires an assigned analyst."
                )

        now = datetime.now(timezone.utc).isoformat()
        old_state = self.current_state

        if false_positive:
            self.is_false_positive = True

        self.current_state = new_state
        self.history.append(
            IncidentStateHistory(
                from_state=old_state,
                to_state=new_state,
                timestamp=now,
                actor=actor,
                reason=reason,
            )
        )
