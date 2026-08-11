"""SOAR Modular Connector Registry and Interface.

Provides a unified, extensible plugin architecture for SOAR integration connectors.
Supports dry-run execution (ADR-0005), schema validation, and dynamic registration.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Type

from scripts.phase2.errors import Phase2Error


class ConnectorValidationError(Phase2Error):
    """Raised when connector parameter validation fails."""
    pass


class ConnectorExecutionError(Phase2Error):
    """Raised when connector execution fails."""
    pass


class BaseSOARConnector(ABC):
    """Abstract base class for all SOAR integration connectors."""

    connector_id: str
    name: str
    category: str  # threat_intel, incident_mgmt, notification, network_defense, endpoint_defense
    supported_actions: List[str]

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        self.config = config or {}

    @abstractmethod
    def validate_params(self, action: str, params: Dict[str, Any]) -> None:
        """Validate input parameters for a given action."""
        if action not in self.supported_actions:
            raise ConnectorValidationError(
                f"Connector '{self.connector_id}' does not support action '{action}'. Supported: {self.supported_actions}"
            )

    @abstractmethod
    def execute(
        self,
        action: str,
        params: Dict[str, Any],
        dry_run: bool = True,
    ) -> Dict[str, Any]:
        """Execute connector action with mandatory dry_run support."""
        pass


class SOARConnectorRegistry:
    """Central registry for discovering and executing SOAR connectors."""

    def __init__(self) -> None:
        self._connectors: Dict[str, BaseSOARConnector] = {}

    def register(self, connector: BaseSOARConnector) -> None:
        """Register a connector instance."""
        self._connectors[connector.connector_id] = connector

    def get(self, connector_id: str) -> Optional[BaseSOARConnector]:
        """Retrieve a registered connector by ID."""
        return self._connectors.get(connector_id)

    def list_connectors(self) -> List[Dict[str, Any]]:
        """List all registered connectors and their metadata."""
        return [
            {
                "connector_id": conn.connector_id,
                "name": conn.name,
                "category": conn.category,
                "supported_actions": conn.supported_actions,
            }
            for conn in self._connectors.values()
        ]

    def execute_action(
        self,
        connector_id: str,
        action: str,
        params: Dict[str, Any],
        dry_run: bool = True,
    ) -> Dict[str, Any]:
        """Execute an action on a specific registered connector."""
        connector = self.get(connector_id)
        if not connector:
            raise ConnectorExecutionError(f"Connector '{connector_id}' is not registered.")
        connector.validate_params(action, params)
        return connector.execute(action, params, dry_run=dry_run)
