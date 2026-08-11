"""EDR Endpoint Isolation Connector."""

from typing import Any, Dict, List, Optional
from connectors.soar_registry import BaseSOARConnector, ConnectorValidationError


class EDRConnector(BaseSOARConnector):
    connector_id = "edr"
    name = "EDR Endpoint Isolation & Defense Connector"
    category = "endpoint_defense"
    supported_actions = ["isolate_host", "unisolate_host", "get_host_status"]

    def validate_params(self, action: str, params: Dict[str, Any]) -> None:
        super().validate_params(action, params)
        if "agent_id" not in params and "hostname" not in params:
            raise ConnectorValidationError(f"EDR '{action}' requires 'agent_id' or 'hostname'")

    def execute(self, action: str, params: Dict[str, Any], dry_run: bool = True) -> Dict[str, Any]:
        self.validate_params(action, params)
        target = params.get("agent_id") or params.get("hostname")
        if dry_run:
            return {
                "status": "success",
                "dry_run": True,
                "connector": self.connector_id,
                "action": action,
                "mock_response": {
                    "target": target,
                    "isolation_status": "PENDING_DRY_RUN",
                    "reason": "DRY_RUN_DEFAULT (ADR-0005)",
                },
            }
        return {
            "status": "success",
            "dry_run": False,
            "connector": self.connector_id,
            "action": action,
            "data": {"target": target, "isolation_status": "ISOLATED" if action == "isolate_host" else "ACTIVE"},
        }
