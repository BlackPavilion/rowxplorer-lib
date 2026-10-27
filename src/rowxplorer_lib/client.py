"""High-level client facade.

The **SEB cloud transport** (OAuth + Cognito + MQTT over WSS) is the only
transport: it is the path verified live against the robot.

Usage::

    from . import RowxplorerClient
    client = RowxplorerClient.seb()          # reads IOT_* env vars
    print(client.status())
    client.clean_all()
    client.stop()
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any

from .models import Device, RobotStatus

if TYPE_CHECKING:
    from .seb_auth import SebAuthConfig
    from .seb_mqtt import SebMqttClient, SebMqttConfig


class RowxplorerClient:
    """Facade over :class:`SebMqttClient` (the only enabled transport)."""

    def __init__(self, transport: "SebMqttClient"):
        self._t = transport

    # -- constructors ------------------------------------------------------
    @classmethod
    def seb(
        cls,
        auth_config: "SebAuthConfig | None" = None,
        mqtt_config: "SebMqttConfig | None" = None,
        auth: Any = None,
        robot_id: str | None = None,
        device: str | None = None,
        **kw: Any,
    ) -> "RowxplorerClient":
        """SEB cloud transport (OAuth + Cognito + MQTT over WSS).

        Without arguments both configs are read from the environment
        (``IOT_REFRESH_TOKEN``, ``IOT_MQTT_ENDPOINT``, ``ROBOT_ID``,
        ``PRODUCT_ID``, ``IOT_REGION``, ...). Pass ``auth`` (a
        :class:`SebAuth` or compatible) to skip building one. ``**kw`` is
        passed to :class:`SebMqttClient` (e.g. ``client_factory`` for tests).

        Multi-robot accounts: pass ``robot_id`` to target a specific robot
        UUID, or ``device`` (a robot name or UUID) to pick one of the
        account's robots via :meth:`list_devices` — this also sets the
        matching ``product_id`` (thing type). ``device`` takes precedence
        over ``robot_id``.
        """
        from .seb_auth import SebAuth, SebAuthConfig
        from .seb_mqtt import SebMqttClient, SebMqttConfig

        if auth is None:
            auth_config = auth_config or SebAuthConfig.from_env()
            auth = SebAuth(auth_config)
        mqtt_config = mqtt_config or SebMqttConfig.from_env()

        if device is not None:
            dev = _resolve_device(auth, device)
            mqtt_config.robot_id = dev.uuid
            if dev.thing_type:
                mqtt_config.product_id = dev.thing_type
        elif robot_id is not None:
            mqtt_config.robot_id = robot_id

        return cls(SebMqttClient(mqtt_config, auth, **kw))

    # -- devices -----------------------------------------------------------
    def list_devices(self, **kw: Any) -> list[Device]:
        """List the robots registered in the SEB account.

        Wraps :func:`rowxplorer_lib.seb_profile.list_devices`. Accepts the
        same keyword arguments (``dcp_context``, ``brand_api_key``, ...).
        """
        from .seb_profile import list_devices as _list_devices

        return _list_devices(self._t.auth, **kw)

    # -- status ------------------------------------------------------------
    def status(self) -> RobotStatus:
        data = self._t.status()
        inner = data.get("data", data)
        return RobotStatus.from_dict(inner if isinstance(inner, dict) else {"raw": str(inner)})

    # -- commands ----------------------------------------------------------
    def clean_all(self) -> dict[str, Any]:
        return self._t.clean_all()

    def clean_spot(self, **kw: Any) -> dict[str, Any]:
        return self._t.clean_spot(**kw)

    def clean_map(self, map_id: int, area_ids: list[int] | None = None) -> dict[str, Any]:
        return self._t.clean_map(map_id, area_ids)

    def stop(self) -> dict[str, Any]:
        return self._t.stop()

    def abort(self) -> dict[str, Any]:
        return self._t.abort()

    def go_home(self) -> dict[str, Any]:
        return self._t.go_home()

    def explore(self) -> dict[str, Any]:
        return self._t.explore()

    def continue_cleaning(self) -> dict[str, Any]:
        return self._t.continue_cleaning()

    # -- extra actions -----------------------------------------------------
    def localize(self) -> dict[str, Any]:
        """Beep the robot (SEB MQTT path only)."""
        return self._t.localize()

    def set_power(self, power: str) -> dict[str, Any]:
        """Change suction power while cleaning (SEB MQTT path only)."""
        return self._t.set_power(power)

    def set_method(self, method: str) -> dict[str, Any]:
        """Change cleaning method while cleaning (SEB MQTT path only)."""
        return self._t.set_method(method)

    # -- raw passthrough ---------------------------------------------------
    def get(self, endpoint: str, **params: Any) -> dict[str, Any]:
        return self._t.get(endpoint, **params)

    def post(self, endpoint: str, **params: Any) -> dict[str, Any]:
        return self._t.post(endpoint, **params)

    @property
    def transport(self) -> "SebMqttClient":
        return self._t


def _resolve_device(auth: Any, name_or_uuid: str) -> Device:
    """Resolve a robot by name or UUID from the account's device list.

    Matching order: exact UUID, exact name (case-insensitive), then a
    unique case-insensitive substring of the name. Raises
    :class:`RobotNotFoundError` when nothing matches or the name is
    ambiguous.
    """
    from .exceptions import RobotNotFoundError
    from .seb_profile import list_devices

    devices = list_devices(auth)
    target = name_or_uuid.strip()
    for d in devices:
        if d.uuid and d.uuid == target:
            return d
    for d in devices:
        if d.name and d.name.lower() == target.lower():
            return d
    matches = [d for d in devices if d.name and target.lower() in d.name.lower()]
    if len(matches) == 1:
        return matches[0]
    if not matches:
        available = ", ".join(d.name or d.uuid for d in devices) or "(none)"
        raise RobotNotFoundError(
            f"no device matching {name_or_uuid!r} (available: {available})"
        )
    names = ", ".join(d.name for d in matches)
    raise RobotNotFoundError(f"ambiguous device {name_or_uuid!r}: {names}")
