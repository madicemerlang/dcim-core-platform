"""Email / SMTP Notification Connector."""

from typing import Any, Dict, List, Optional
from connectors.soar_registry import BaseSOARConnector, ConnectorValidationError


class EmailConnector(BaseSOARConnector):
    connector_id = "email"
    name = "SMTP Email Notification System"
    category = "notification"
    supported_actions = ["send_incident_digest", "send_approval_notification"]

    def validate_params(self, action: str, params: Dict[str, Any]) -> None:
        super().validate_params(action, params)
        if "recipient" not in params:
            raise ConnectorValidationError("Email connector requires 'recipient' parameter")
        if action == "send_incident_digest" and "incident_id" not in params:
            raise ConnectorValidationError("Email 'send_incident_digest' requires 'incident_id'")
        elif action == "send_approval_notification" and "approval_token" not in params:
            raise ConnectorValidationError("Email 'send_approval_notification' requires 'approval_token'")

    def execute(self, action: str, params: Dict[str, Any], dry_run: bool = True) -> Dict[str, Any]:
        self.validate_params(action, params)
        if dry_run:
            return {
                "status": "success",
                "dry_run": True,
                "connector": self.connector_id,
                "action": action,
                "mock_response": {
                    "recipient": params.get("recipient"),
                    "subject": f"[DRY-RUN] Incident Notification: {params.get('incident_id', 'INC-001')}",
                    "sent": True,
                },
            }
        return {
            "status": "success",
            "dry_run": False,
            "connector": self.connector_id,
            "action": action,
            "data": {"recipient": params.get("recipient"), "status": "sent"},
        }
