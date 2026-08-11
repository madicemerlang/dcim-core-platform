"""Firewall / Network Defense Connector."""

from typing import Any, Dict, List, Optional
from connectors.soar_registry import BaseSOARConnector, ConnectorValidationError


class FirewallConnector(BaseSOARConnector):
    connector_id = "firewall"
    name = "Network ACL & Firewall Remediation Connector"
    category = "network_defense"
    supported_actions = ["block_ip", "unblock_ip", "get_blocked_list"]

    def validate_params(self, action: str, params: Dict[str, Any]) -> None:
        super().validate_params(action, params)
        if action in ("block_ip", "unblock_ip") and "ip" not in params:
            raise ConnectorValidationError(f"Firewall '{action}' requires 'ip' parameter")

    def execute(self, action: str, params: Dict[str, Any], dry_run: bool = True) -> Dict[str, Any]:
        self.validate_params(action, params)
        ip = params.get("ip", "")
        if dry_run:
            return {
                "status": "success",
                "dry_run": True,
                "connector": self.connector_id,
                "action": action,
                "mock_response": {
                    "ip": ip,
                    "rule_id": f"fw-rule-{hash(ip) & 0xffff}",
                    "applied": False,
                    "reason": "DRY_RUN_DEFAULT (ADR-0005)",
                },
            }
        return {
            "status": "success",
            "dry_run": False,
            "connector": self.connector_id,
            "action": action,
            "data": {"ip": ip, "status": "active_rule_applied"},
        }
