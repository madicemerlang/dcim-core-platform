"""Slack / Teams Notification Connector."""

from typing import Any, Dict, List, Optional
from connectors.soar_registry import BaseSOARConnector, ConnectorValidationError


class SlackConnector(BaseSOARConnector):
    connector_id = "slack"
    name = "Slack / Teams Incident Messenger"
    category = "notification"
    supported_actions = ["send_alert_notification", "send_approval_request"]

    def validate_params(self, action: str, params: Dict[str, Any]) -> None:
        super().validate_params(action, params)
        if action == "send_alert_notification" and ("channel" not in params or "message" not in params):
            raise ConnectorValidationError("Slack 'send_alert_notification' requires 'channel' and 'message'")
        elif action == "send_approval_request" and ("channel" not in params or "playbook_id" not in params):
            raise ConnectorValidationError("Slack 'send_approval_request' requires 'channel' and 'playbook_id'")

    def execute(self, action: str, params: Dict[str, Any], dry_run: bool = True) -> Dict[str, Any]:
        self.validate_params(action, params)
        if dry_run:
            return {
                "status": "success",
                "dry_run": True,
                "connector": self.connector_id,
                "action": action,
                "mock_response": {
                    "channel": params.get("channel"),
                    "message_sent": True,
                    "ts": "1698765432.000100",
                },
            }
        return {
            "status": "success",
            "dry_run": False,
            "connector": self.connector_id,
            "action": action,
            "data": {"channel": params.get("channel"), "status": "delivered"},
        }
