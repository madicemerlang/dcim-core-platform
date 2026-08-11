"""DFIR IRIS Case Management Modular Connector."""

from typing import Any, Dict, Optional
from connectors.soar_registry import BaseSOARConnector, ConnectorValidationError
from dcim_workflow.iris_sync import (
    IRISSyncBridge,
    map_rule_level_to_iris_severity,
    map_incident_state_to_iris_status,
)


class IRISConnector(BaseSOARConnector):
    connector_id = "iris"
    name = "DFIR IRIS Case Management"
    category = "incident_mgmt"
    supported_actions = ["create_case", "update_case_status", "sync_incident_case"]

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(config)
        self.bridge = IRISSyncBridge()

    def validate_params(self, action: str, params: Dict[str, Any]) -> None:
        super().validate_params(action, params)
        if action == "create_case" and "case_name" not in params:
            raise ConnectorValidationError("IRIS 'create_case' requires 'case_name'")
        elif action == "update_case_status" and ("iris_ticket_id" not in params or "state" not in params):
            raise ConnectorValidationError("IRIS 'update_case_status' requires 'iris_ticket_id' and 'state'")

    def execute(self, action: str, params: Dict[str, Any], dry_run: bool = True) -> Dict[str, Any]:
        self.validate_params(action, params)
        if action == "create_case":
            return self.bridge.create_case(
                case_name=params["case_name"],
                description=params.get("description", "SOAR Incident Case"),
                rule_level=params.get("rule_level", 8),
                soc_id=params.get("soc_id", "SOC-AUTO-ANALYST"),
                dry_run=dry_run,
            )
        elif action == "update_case_status":
            return self.bridge.update_case_status(
                iris_ticket_id=params["iris_ticket_id"],
                state=params["state"],
                note=params.get("note", ""),
                dry_run=dry_run,
            )
        elif action == "sync_incident_case":
            case = params.get("incident_case")
            if not case:
                raise ConnectorValidationError("IRIS 'sync_incident_case' requires 'incident_case' object")
            return self.bridge.sync_incident_case(case, rule_level=params.get("rule_level", 10), dry_run=dry_run)

        return {"status": "error", "message": f"Action '{action}' not implemented"}
