"""TheHive & Cortex Incident Response Connector."""

from typing import Any, Dict, List, Optional
from connectors.soar_registry import BaseSOARConnector, ConnectorValidationError


class TheHiveConnector(BaseSOARConnector):
    connector_id = "thehive"
    name = "TheHive & Cortex IR Platform"
    category = "incident_mgmt"
    supported_actions = ["create_case", "add_observable", "run_analyzer"]

    def validate_params(self, action: str, params: Dict[str, Any]) -> None:
        super().validate_params(action, params)
        if action == "create_case" and "title" not in params:
            raise ConnectorValidationError("TheHive 'create_case' requires 'title'")
        elif action == "add_observable" and ("case_id" not in params or "data" not in params):
            raise ConnectorValidationError("TheHive 'add_observable' requires 'case_id' and 'data'")
        elif action == "run_analyzer" and ("cortex_id" not in params or "analyzer_name" not in params):
            raise ConnectorValidationError("TheHive 'run_analyzer' requires 'cortex_id' and 'analyzer_name'")

    def execute(self, action: str, params: Dict[str, Any], dry_run: bool = True) -> Dict[str, Any]:
        self.validate_params(action, params)
        if dry_run:
            return {
                "status": "success",
                "dry_run": True,
                "connector": self.connector_id,
                "action": action,
                "mock_response": {
                    "case_id": params.get("case_id", "hive-case-104"),
                    "title": params.get("title", "Dry-run TheHive Incident"),
                    "severity": params.get("severity", 2),
                },
            }
        return {
            "status": "success",
            "dry_run": False,
            "connector": self.connector_id,
            "action": action,
            "data": {"case_id": "hive-case-104", "result": "ok"},
        }
