"""MQTT client for the SEB IoT cloud (AWS IoT over WebSocket).

The client connects to AWS IoT **over WebSocket (WSS, port 443)** — not raw
MQTT/TCP on 8883 — and signs the WebSocket upgrade request with SigV4
(service ``iotdata``) using the temporary IAM credentials from
:class:`rowxplorer_lib.seb_auth.SebAuth`.

Wire protocol:

- canonical request: ``GET /mqtt`` with the signed query string, ``host``
  header **without port**, empty payload
- the WebSocket handshake requires ``Sec-WebSocket-Protocol: mqtt``
- topics: ``<product_id>/<robot_id>/<topicName>``
- request/response: publish ``{}`` (QoS 0) to the *publication* topic and
  wait for the payload on the matching *subscription* topic
- commands: publish a JSON payload to the ``command`` topic (fire & forget);
  the robot then pushes status updates on the ``status`` topic
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import ssl
import threading
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable
from urllib.parse import quote

from .exceptions import ConnectionError as RowxplorerConnectionError
from .seb_auth import IamCredentials, _env

_LOGGER = logging.getLogger(__name__)

# publication topic -> subscription topic
TOPIC_PAIRS: dict[str, tuple[str, str]] = {
    "status": ("getStatus", "status"),
    "history": ("getHistory", "history"),
    "client_listening": ("clientListening", "clientListeningSub"),
}

DEFAULT_REGION = "eu-west-1"
DEFAULT_PRODUCT_ID = "VAC001"
SERVICE = "iotdata"
WS_PATH = "/mqtt"


def sign_websocket_url(
    creds: IamCredentials,
    *,
    region: str,
    host: str,
    service: str = SERVICE,
    now: datetime | None = None,
) -> str:
    """Build the SigV4-signed query string for ``wss://<host>:443/mqtt?<query>``.

    Implements the AWS IoT WebSocket URL signing (SigV4). The canonical
    request uses the host **without port** and an empty payload; the session
    token is appended *after* signing.
    """
    now = now or datetime.now(timezone.utc)
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    date_stamp = now.strftime("%Y%m%d")
    scope = f"{date_stamp}/{region}/{service}/aws4_request"
    qs = (
        "X-Amz-Algorithm=AWS4-HMAC-SHA256"
        "&X-Amz-Credential=" + quote(f"{creds.access_key_id}/{scope}", safe="")
        + "&X-Amz-Date=" + amz_date
        + "&X-Amz-SignedHeaders=host"
    )
    canonical_request = (
        "GET\n"
        f"{WS_PATH}\n"
        f"{qs}\n"
        f"host:{host}\n"
        "\n"
        "host\n"
        + hashlib.sha256(b"").hexdigest()
    )
    string_to_sign = (
        "AWS4-HMAC-SHA256\n"
        f"{amz_date}\n"
        f"{scope}\n"
        + hashlib.sha256(canonical_request.encode("utf-8")).hexdigest()
    )

    def _hmac(key: bytes, msg: str) -> bytes:
        return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()

    key = _hmac(("AWS4" + creds.secret_key).encode("utf-8"), date_stamp)
    key = _hmac(key, region)
    key = _hmac(key, service)
    key = _hmac(key, "aws4_request")
    signature = hmac.new(key, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()
    full = f"{qs}&X-Amz-Signature={signature}"
    if creds.session_token:
        full += "&X-Amz-Security-Token=" + quote(creds.session_token, safe="")
    return full


@dataclass
class SebMqttConfig:
    """Configuration for :class:`SebMqttClient`.

    Attributes:
        mqtt_endpoint: IoT MQTT host (e.g. ``prod-new.iot.mqtt.groupe-seb.com``).
        region: AWS region (``eu-west-1``).
        product_id: thing type (``VAC001``).
        robot_id: appliance asset id (the robot UUID).
        client_id: MQTT client id (default: ``#python-<uuid>``).
        keepalive: MQTT keepalive in seconds.
        timeout: request/response timeout in seconds.
        connect_timeout: CONNACK timeout in seconds.
    """

    mqtt_endpoint: str = ""
    region: str = DEFAULT_REGION
    product_id: str = DEFAULT_PRODUCT_ID
    robot_id: str = ""
    client_id: str = ""
    keepalive: int = 120
    timeout: float = 15.0
    connect_timeout: float = 20.0

    @classmethod
    def from_env(cls) -> SebMqttConfig:
        """Build the config from environment variables (``.env`` values)."""
        return cls(
            mqtt_endpoint=_env("IOT_MQTT_ENDPOINT"),
            region=_env("IOT_REGION", DEFAULT_REGION),
            product_id=_env("PRODUCT_ID", DEFAULT_PRODUCT_ID),
            robot_id=_env("ROBOT_ID"),
        )

    def topic(self, name: str) -> str:
        return f"{self.product_id}/{self.robot_id}/{name}"


class SebMqttClient:
    """MQTT client for the SEB IoT cloud (WSS + SigV4).

    Usage::

        auth = SebAuth(SebAuthConfig(refresh_token="..."))
        client = SebMqttClient(
            SebMqttConfig(mqtt_endpoint="prod-new.iot.mqtt.groupe-seb.com",
                          robot_id="01234567-..."),
            auth,
        )
        with client:
            print(client.status())
            client.clean_all()
            client.go_home()

    The client connects lazily on the first request (or explicitly via
    :meth:`connect`). ``client_factory`` can be injected for testing.

    Note: the signed URL is valid for ~15 min; long-lived sessions should
    reconnect (``disconnect()`` + ``connect()``) before it expires.
    """

    def __init__(
        self,
        config: SebMqttConfig,
        auth: Any,
        client_factory: Callable[[str], Any] | None = None,
        status_callback: Callable[[dict[str, Any]], None] | None = None,
    ):
        self.config = config
        self.auth = auth
        self._factory = client_factory or self._default_factory
        self._client: Any | None = None
        self._connected = False
        self._connect_error: str | None = None
        self._connected_event = threading.Event()
        self._lock = threading.Lock()
        self._waiters: dict[str, list[tuple[threading.Event, dict[str, Any]]]] = {}
        self._subscribed: set[str] = set()
        # Called from the paho network thread with every status payload that
        # the robot pushes (not a response to our own getStatus request).
        self.status_callback = status_callback

    # -- lifecycle -----------------------------------------------------------
    def _default_factory(self, client_id: str) -> Any:
        import paho.mqtt.client as mqtt  # lazy: only needed for the SEB path

        try:
            return mqtt.Client(
                mqtt.CallbackAPIVersion.VERSION2,
                client_id=client_id,
                protocol=mqtt.MQTTv311,
                transport="websockets",
            )
        except (AttributeError, TypeError):  # paho < 2
            return mqtt.Client(
                client_id=client_id, protocol=mqtt.MQTTv311, transport="websockets"
            )

    def connect(self) -> None:
        """Authenticate (Cognito), sign the WSS URL and connect."""
        if self._connected:
            return
        if not self.config.mqtt_endpoint:
            raise RowxplorerConnectionError("mqtt_endpoint is not configured")
        creds = self.auth.cognito_credentials()
        query = sign_websocket_url(
            creds, region=self.config.region, host=self.config.mqtt_endpoint
        )
        client_id = self.config.client_id or f"#python-{uuid.uuid4()}"
        client = self._factory(client_id)
        client.ws_set_options(
            path=f"{WS_PATH}?{query}", headers={"Sec-WebSocket-Protocol": "mqtt"}
        )
        client.tls_set(cert_reqs=ssl.CERT_REQUIRED, tls_version=ssl.PROTOCOL_TLS_CLIENT)
        client.on_connect = self._on_connect
        client.on_message = self._on_message
        client.on_disconnect = self._on_disconnect
        self._client = client
        self._connect_error = None
        self._connected_event.clear()
        try:
            client.connect(self.config.mqtt_endpoint, 443, keepalive=self.config.keepalive)
        except Exception as exc:
            self._client = None
            raise RowxplorerConnectionError(
                f"MQTT connect to {self.config.mqtt_endpoint} failed: {exc}"
            ) from exc
        client.loop_start()
        if not self._connected_event.wait(self.config.connect_timeout):
            self.disconnect()
            raise RowxplorerConnectionError(
                f"MQTT: no CONNACK from {self.config.mqtt_endpoint} "
                f"within {self.config.connect_timeout}s"
            )
        if self._connect_error:
            self.disconnect()
            raise RowxplorerConnectionError(f"MQTT: connection refused: {self._connect_error}")
        self._connected = True
        if self.status_callback is not None:
            self._subscribe(self.config.topic("status"))

    def disconnect(self) -> None:
        client, self._client = self._client, None
        self._connected = False
        with self._lock:
            self._subscribed.clear()
        if client is None:
            return
        try:
            client.loop_stop()
            client.disconnect()
        except Exception:  # noqa: BLE001, S110 - best-effort cleanup
            pass

    def __enter__(self) -> SebMqttClient:  # noqa: PYI034 - Self needs py3.11
        self.connect()
        return self

    def __exit__(self, *exc: object) -> None:
        self.disconnect()

    # -- low-level -------------------------------------------------------------
    def _ensure_connected(self) -> None:
        if not self._connected:
            self.connect()

    def subscribe_status(self) -> None:
        """Subscribe to the robot's ``status`` topic for push updates."""
        self._ensure_connected()
        self._subscribe(self.config.topic("status"))

    def _subscribe(self, topic: str) -> None:
        with self._lock:
            if topic in self._subscribed:
                return
            self._subscribed.add(topic)
        self._client.subscribe(topic, qos=0)

    def request(
        self,
        pub_name: str,
        sub_name: str,
        payload: str | bytes = b"{}",
        timeout: float | None = None,
    ) -> dict[str, Any]:
        """Publish to ``<product>/<robot>/<pub_name>`` and wait for a payload
        on ``<product>/<robot>/<sub_name>`` (request/response mechanic,
        QoS 0)."""
        self._ensure_connected()
        timeout = self.config.timeout if timeout is None else timeout
        pub_topic = self.config.topic(pub_name)
        sub_topic = self.config.topic(sub_name)
        if isinstance(payload, str):
            payload = payload.encode("utf-8")
        ev = threading.Event()
        slot: dict[str, Any] = {}
        with self._lock:
            self._waiters.setdefault(sub_topic, []).append((ev, slot))
        self._subscribe(sub_topic)
        info = self._client.publish(pub_topic, payload, qos=0)
        if getattr(info, "rc", 0) != 0:
            self._drop_waiter(sub_topic, ev)
            raise RowxplorerConnectionError(f"publish to {pub_topic} failed (rc={info.rc})")
        if not ev.wait(timeout):
            self._drop_waiter(sub_topic, ev)
            raise RowxplorerConnectionError(f"no response on {sub_topic} within {timeout}s")
        data = slot.get("data")
        if data is None:
            raise RowxplorerConnectionError(f"connection lost while waiting on {sub_topic}")
        return data

    def _drop_waiter(self, topic: str, ev: threading.Event) -> None:
        with self._lock:
            lst = self._waiters.get(topic, [])
            for i, (e, _s) in enumerate(lst):
                if e is ev:
                    lst.pop(i)
                    break

    # -- callbacks (paho network thread) -----------------------------------------
    def _on_connect(
        self, client: Any, userdata: Any, flags: Any, rc: Any, properties: Any = None
    ) -> None:
        if not _connect_ok(rc):
            self._connect_error = str(getattr(rc, "name", rc))
        self._connected_event.set()

    def _on_message(self, client: Any, userdata: Any, msg: Any) -> None:
        try:
            data = json.loads(msg.payload.decode("utf-8", "replace"))
        except ValueError:
            data = {"raw": msg.payload.decode("utf-8", "replace")}
        if not isinstance(data, dict):
            data = {"data": data}
        ev: threading.Event | None = None
        with self._lock:
            waiters = self._waiters.get(msg.topic)
            if waiters:
                ev, slot = waiters.pop(0)
                slot["data"] = data
        if ev is not None:
            ev.set()
        elif (
            self.status_callback is not None
            and msg.topic == self.config.topic("status")
        ):
            try:
                self.status_callback(data)
            except Exception:  # noqa: BLE001 - never kill the paho thread
                _LOGGER.exception("status callback failed")

    def _on_disconnect(
        self, client: Any, userdata: Any, flags: Any, rc: Any, properties: Any = None
    ) -> None:
        self._connected = False
        with self._lock:
            for topic in list(self._waiters):
                for ev, _slot in self._waiters.pop(topic):
                    ev.set()

    # -- high-level: status / history ---------------------------------------------
    def status(self, timeout: float | None = None) -> dict[str, Any]:
        """Current robot status (``getStatus`` -> ``status``)."""
        return self.request("getStatus", "status", timeout=timeout)

    def history(self, timeout: float | None = None) -> dict[str, Any]:
        """Cleaning history (``getHistory`` -> ``history``)."""
        return self.request("getHistory", "history", timeout=timeout)

    # -- high-level: commands (fire & forget on the ``command`` topic) ------------
    def command(self, payload: dict[str, Any] | str) -> dict[str, Any]:
        """Publish a command to the ``command`` topic.

        The robot does not answer commands directly; it pushes the new state
        on the ``status`` topic (poll :meth:`status`).
        """
        self._ensure_connected()
        topic = self.config.topic("command")
        data = payload if isinstance(payload, str) else json.dumps(payload)
        info = self._client.publish(topic, data, qos=0)
        if getattr(info, "rc", 0) != 0:
            raise RowxplorerConnectionError(f"publish to {topic} failed (rc={info.rc})")
        return {"published": True, "topic": topic, "mid": getattr(info, "mid", None)}

    def clean_all(self, method: str = "AUTO_CLEANING", power: str = "NORMAL") -> dict[str, Any]:
        """Start a full clean (``{"method": ..., "power": ...}``)."""
        return self.command({"method": method, "power": power})

    def clean_spot(self, power: str = "STRONG", **_kw: Any) -> dict[str, Any]:
        """Spot clean (``{"method": "SPIRAL", ...}``)."""
        return self.command({"method": "SPIRAL", "power": power})

    def clean_map(self, map_id: int, area_ids: list[int] | None = None) -> dict[str, Any]:
        raise NotImplementedError(
            "the SEB MQTT path has no map-specific clean; use clean_all()"
        )

    def stop(self) -> dict[str, Any]:
        """Stop/pause (``{"method": "PAUSE"}``)."""
        return self.command({"method": "PAUSE"})

    def abort(self) -> dict[str, Any]:
        return self.stop()

    def go_home(self) -> dict[str, Any]:
        """Go back to the dock (``{"method": "BACK_TO_DOCK"}``)."""
        return self.command({"method": "BACK_TO_DOCK"})

    def explore(self) -> dict[str, Any]:
        raise NotImplementedError("explore is not available on the SEB MQTT path")

    def continue_cleaning(self) -> dict[str, Any]:
        return self.clean_all()

    def localize(self) -> dict[str, Any]:
        """Beep (``{"beep": "ON"}``) — SEB-only action."""
        return self.command({"beep": "ON"})

    def set_power(self, power: str) -> dict[str, Any]:
        """Change suction power while cleaning (``{"power": ...}``)."""
        return self.command({"power": power})

    def set_method(self, method: str) -> dict[str, Any]:
        """Change cleaning method while cleaning (``{"method": ...}``)."""
        return self.command({"method": method})

    # -- raw passthrough (RowxplorerClient.get/post) -----------------------------------
    def get(self, name: str, **params: Any) -> dict[str, Any]:
        if name == "status":
            return self.status()
        if name == "history":
            return self.history()
        return self.request(name, name, payload=json.dumps(params) if params else b"{}")

    def post(self, name: str, **params: Any) -> dict[str, Any]:
        if name == "command":
            return self.command(params)
        self._ensure_connected()
        topic = self.config.topic(name)
        info = self._client.publish(topic, json.dumps(params) if params else "{}", qos=0)
        if getattr(info, "rc", 0) != 0:
            raise RowxplorerConnectionError(f"publish to {topic} failed (rc={info.rc})")
        return {"published": True, "topic": topic, "mid": getattr(info, "mid", None)}


def _connect_ok(rc: Any) -> bool:
    """True when a paho on_connect reason (int or ConnectReason) is success."""
    if isinstance(rc, int):
        return rc == 0
    return not bool(getattr(rc, "is_failure", True))
