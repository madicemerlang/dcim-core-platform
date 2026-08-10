"""Replay synthetic Wazuh SIEM fixtures and parse Avro/JSON events without network or write capabilities."""

from __future__ import annotations

from collections.abc import Callable, Iterator
import json
from pathlib import Path
from typing import ClassVar, Final, Protocol, final

try:
    from typing import TypeAlias, override
except ImportError:
    try:
        from typing_extensions import TypeAlias, override
    except ImportError:
        TypeAlias = object
        def override(method):
            return method

from scripts.phase2.errors import (
    ConnectorCeilingError,
    KillSwitchEngaged,
    Phase2Error,
)

JsonValue: TypeAlias = (
    None
    | bool
    | int
    | float
    | str
    | list["JsonValue"]
    | dict[str, "JsonValue"]
)
CanonicalEnvelope: TypeAlias = dict[str, JsonValue]


class _JsonLoader(Protocol):
    def __call__(self, s: str) -> JsonValue: ...


_JSON_LOADS: _JsonLoader = json.loads
WAZUH_MIN_POLL_INTERVAL_SECONDS: Final = 30
WAZUH_MAX_READ_TIMEOUT_SECONDS: Final = 10


class WazuhFixtureError(Phase2Error):
    """Raised when parsing or validating a Wazuh SIEM event or fixture fails."""

    pass


def parse_wazuh_event(
    raw_payload: str | bytes | dict[str, JsonValue],
    observed_at: str,
    default_instance: str = "wazuh-manager-01",
) -> CanonicalEnvelope:
    """Parse raw JSON/dict event emitted by Wazuh SIEM into a DCIM CanonicalEnvelope.

    Enforces ADR-0004 inbound read-only normalization and validates required fields.
    """
    if isinstance(raw_payload, (str, bytes)):
        try:
            payload = _JSON_LOADS(
                raw_payload if isinstance(raw_payload, str) else raw_payload.decode("utf-8")
            )
        except Exception as exc:
            raise WazuhFixtureError(f"Failed to parse Wazuh event payload as JSON: {exc}") from exc
    else:
        payload = raw_payload

    if not isinstance(payload, dict):
        raise WazuhFixtureError("Wazuh event payload must be a JSON object")

    # Handle both direct Wazuh alert JSON and wrapped DCIM envelope format
    if "wazuh" in payload and isinstance(payload["wazuh"], dict):
        wazuh_data = payload["wazuh"]
        source_info = payload.get("source", {})
        if not isinstance(source_info, dict):
            source_info = {}
    else:
        wazuh_data = payload
        source_info = {}

    rule_info = wazuh_data.get("rule", {})
    if isinstance(rule_info, dict):
        native_event_id = str(rule_info.get("id", source_info.get("native_event_id", "unknown")))
    else:
        native_event_id = str(source_info.get("native_event_id", "unknown"))

    instance = str(source_info.get("instance", default_instance))

    envelope: CanonicalEnvelope = {
        "event_id": payload.get("event_id") or f"wazuh-event-{native_event_id}",
        "timestamp": payload.get("timestamp") or wazuh_data.get("timestamp") or observed_at,
        "observed_at": observed_at,
        "source": {
            "system": "wazuh-siem",
            "instance": instance,
            "connector": "wazuh-fixture-adapter",
            "transport": str(source_info.get("transport", "syslog-json")),
            "native_event_id": native_event_id,
        },
        "wazuh": wazuh_data,
    }

    return envelope


class WazuhFixtureAdapter:
    """Replay synthetic Wazuh SIEM envelopes with ADR-0023 contract ceilings.

    Ceiling arguments are contract dummies for this replay adapter; no live
    Wazuh poll or source request is performed.
    """

    __slots__: ClassVar[tuple[str, ...]] = (
        "_clock",
        "_enabled",
        "_fixture_paths",
        "_kill_flag",
        "_poll_interval_seconds",
        "_read_timeout_seconds",
        "_stop_file",
    )
    _clock: str
    _enabled: bool
    _fixture_paths: tuple[Path, ...]
    _kill_flag: Callable[[], bool]
    _poll_interval_seconds: int
    _read_timeout_seconds: int
    _stop_file: Path | None

    def __init__(
        self,
        fixture_paths: list[Path],
        clock: str,
        kill_flag: Callable[[], bool],
        stop_file: Path | None,
        poll_interval_seconds: int = 30,
        read_timeout_seconds: int = 10,
        enabled: bool = True,
    ) -> None:
        if poll_interval_seconds < WAZUH_MIN_POLL_INTERVAL_SECONDS:
            raise ConnectorCeilingError(
                connector="wazuh",
                parameter="poll_interval_seconds",
                value=poll_interval_seconds,
                bound="at least",
                limit=WAZUH_MIN_POLL_INTERVAL_SECONDS,
            )
        if read_timeout_seconds > WAZUH_MAX_READ_TIMEOUT_SECONDS:
            raise ConnectorCeilingError(
                connector="wazuh",
                parameter="read_timeout_seconds",
                value=read_timeout_seconds,
                bound="at most",
                limit=WAZUH_MAX_READ_TIMEOUT_SECONDS,
            )
        self._fixture_paths = tuple(fixture_paths)
        self._clock = clock
        self._kill_flag = kill_flag
        self._stop_file = stop_file
        self._poll_interval_seconds = poll_interval_seconds
        self._read_timeout_seconds = read_timeout_seconds
        self._enabled = enabled

    def __iter__(self) -> Iterator[CanonicalEnvelope]:
        return _WazuhFixtureIterator(
            fixture_paths=self._fixture_paths,
            enabled=self._enabled,
            raise_if_stopped=self._raise_if_stopped,
            load_fixture=self._load_fixture,
        )

    @property
    def poll_interval_seconds(self) -> int:
        return self._poll_interval_seconds

    @property
    def read_timeout_seconds(self) -> int:
        return self._read_timeout_seconds

    @property
    def enabled(self) -> bool:
        return self._enabled

    def _raise_if_stopped(self) -> None:
        if self._kill_flag() or (
            self._stop_file is not None and self._stop_file.exists()
        ):
            raise KillSwitchEngaged(
                "Wazuh fixture adapter kill switch is engaged"
            )

    def _load_fixture(self, fixture_path: Path) -> CanonicalEnvelope:
        content = fixture_path.read_text(encoding="utf-8")
        envelope = parse_wazuh_event(
            raw_payload=content,
            observed_at=self._clock,
        )
        return envelope


@final
class _WazuhFixtureIterator(Iterator[CanonicalEnvelope]):
    __slots__: ClassVar[tuple[str, ...]] = (
        "_enabled",
        "_fixture_paths",
        "_index",
        "_load_fixture",
        "_raise_if_stopped",
    )
    _enabled: bool
    _fixture_paths: tuple[Path, ...]
    _index: int
    _load_fixture: Callable[[Path], CanonicalEnvelope]
    _raise_if_stopped: Callable[[], None]

    def __init__(
        self,
        *,
        fixture_paths: tuple[Path, ...],
        enabled: bool,
        raise_if_stopped: Callable[[], None],
        load_fixture: Callable[[Path], CanonicalEnvelope],
    ) -> None:
        self._fixture_paths = fixture_paths
        self._enabled = enabled
        self._index = 0
        self._raise_if_stopped = raise_if_stopped
        self._load_fixture = load_fixture

    @override
    def __iter__(self) -> _WazuhFixtureIterator:
        return self

    @override
    def __next__(self) -> CanonicalEnvelope:
        if not self._enabled or self._index >= len(self._fixture_paths):
            raise StopIteration
        self._raise_if_stopped()
        fixture_path = self._fixture_paths[self._index]
        self._index += 1
        return self._load_fixture(fixture_path)
