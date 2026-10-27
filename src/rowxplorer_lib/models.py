"""Data models for rowxplorer-lib.

These mirror the JSON the robot/cloud returns. Known fields are typed;
unknown fields are preserved in ``raw``.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class CleaningMode(str, Enum):
    """Cleaning modes."""

    CLEAN_ALL = "clean_all"
    CLEAN_SPOT = "clean_spot"
    CLEAN_MAP = "clean_map"
    CLEAN_AREA = "clean_area"
    CLEAN_START_OR_CONTINUE = "clean_start_or_continue"
    CLEAN_CONTINUE = "clean_continue"


@dataclass
class RobotStatus:
    """Parsed ``GET /status`` payload.

    The exact schema varies by firmware; known fields are typed, everything
    else is kept in :attr:`raw`.
    """

    raw: dict[str, Any] = field(default_factory=dict)

    # Common fields (best-effort; adjust as real payloads are captured).
    battery_level: int | None = None
    battery_state: str | None = None
    execution_state: str | None = None
    cleaning_state: str | None = None
    robot_state: str | None = None
    error: str | None = None

    # SEB cloud (MQTT) fields.
    method: str | None = None
    power: str | None = None
    error_code: str | None = None
    cleaning_area: int | None = None
    cleaning_time: int | None = None
    total_cleaning_time: int | None = None
    map_id: str | None = None
    start_timestamp: int | None = None
    current_timestamp: int | None = None
    end_timestamp: int | None = None
    accessories: list[dict[str, Any]] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "RobotStatus":
        def pick(*keys: str) -> Any:
            for k in keys:
                if k in data and data[k] is not None:
                    return data[k]
            return None

        return cls(
            raw=dict(data),
            battery_level=_as_int(pick("battery_level", "battery", "batteryLevel")),
            battery_state=_as_str(pick("battery_state", "batteryState")),
            execution_state=_as_str(
                pick("execution_state", "executionState", "state", "status")
            ),
            cleaning_state=_as_str(pick("cleaning_state", "cleaningState")),
            robot_state=_as_str(pick("robot_state", "robotState")),
            error=_as_str(pick("error", "error_message", "errorMessage")),
            method=_as_str(pick("method")),
            power=_as_str(pick("power")),
            error_code=_as_str(pick("errorCode", "error_code")),
            cleaning_area=_as_int(pick("cleaningArea", "cleaning_area")),
            cleaning_time=_as_int(pick("cleaningTime", "cleaning_time")),
            total_cleaning_time=_as_int(pick("totalCleaningTime", "total_cleaning_time")),
            map_id=_as_str(pick("mapId", "map_id")),
            start_timestamp=_as_int(pick("startTimestamp", "start_timestamp")),
            current_timestamp=_as_int(pick("currentTimestamp", "current_timestamp")),
            end_timestamp=_as_int(pick("endTimestamp", "end_timestamp")),
            accessories=list(data.get("accessories") or []),
        )

    @property
    def is_cleaning(self) -> bool:
        s = (self.execution_state or self.cleaning_state or "").lower()
        return any(t in s for t in ("clean", "running", "working", "active"))

    def __str__(self) -> str:  # pragma: no cover - convenience
        return (
            f"RobotStatus(battery={self.battery_level}%, "
            f"state={self.execution_state or self.cleaning_state}, "
            f"error={self.error})"
        )


@dataclass
class DiscoveredRobot:
    """A robot found on the network (mDNS) or by config."""

    name: str
    ip: str
    port: int
    service_type: str = "_aicu-http._tcp.local."
    txt: dict[str, str] = field(default_factory=dict)

    @property
    def base_url(self) -> str:
        return f"http://{self.ip}:{self.port}"


@dataclass
class Device:
    """A robot (device) registered in the SEB account.

    Returned by :meth:`rowxplorer_lib.seb_profile.list_devices`. The
    ``uuid`` is the value used as ``robot_id`` in MQTT topics
    (``VAC001/<uuid>/...``).
    """

    name: str
    uuid: str
    appliance: str | None = None
    thing_type: str | None = None
    source: str | None = None
    rcu_asset_id: str | None = None
    raw: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Device":
        iot = data.get("iot") or {}
        return cls(
            name=str(data.get("name") or data.get("nickname") or ""),
            uuid=str(iot.get("functionalId") or iot.get("functional_id") or ""),
            appliance=data.get("appliance"),
            thing_type=iot.get("thingType") or iot.get("thing_type"),
            source=iot.get("source"),
            rcu_asset_id=data.get("rcuAssetId") or data.get("rcu_asset_id"),
            raw=dict(data),
        )

    def __str__(self) -> str:  # pragma: no cover - convenience
        return f"Device(name={self.name!r}, uuid={self.uuid!r}, thing_type={self.thing_type!r})"


def _as_int(v: Any) -> int | None:
    if v is None:
        return None
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _as_str(v: Any) -> str | None:
    return None if v is None else str(v)
