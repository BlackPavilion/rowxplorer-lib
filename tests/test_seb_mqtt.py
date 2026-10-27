"""Unit tests for the SEB MQTT client (paho + HTTP mocked)."""
from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from rowxplorer_lib import RowxplorerConnectionError
from rowxplorer_lib.seb_auth import IamCredentials
from rowxplorer_lib.seb_mqtt import (
    SebMqttClient,
    SebMqttConfig,
    sign_websocket_url,
)

CREDS = IamCredentials(
    access_key_id="AKIDEXAMPLE",
    secret_key="wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
    session_token="SESSIONTOKEN123",
)
HOST = "prod-new.iot.mqtt.groupe-seb.com"
ROBOT_ID = "01234567-89ab-cdef-0123-456789abcdef"
FIXED_NOW = datetime(2026, 10, 27, 12, 0, 0, tzinfo=timezone.utc)


class StubAuth:
    """Duck-typed SebAuth: returns fixed IAM credentials, no HTTP."""

    def __init__(self, creds=CREDS):
        self._creds = creds

    def cognito_credentials(self):
        return self._creds


class FakeMessage:
    def __init__(self, topic: str, payload):
        self.topic = topic
        if isinstance(payload, (bytes, str)):
            self.payload = payload if isinstance(payload, bytes) else payload.encode()
        else:
            self.payload = json.dumps(payload).encode()


class FakeMqttClient:
    """Mimics the paho 2.x API surface used by SebMqttClient.

    ``respond_with`` maps a publication topic to ``(sub_topic, payload)``;
    when that topic is published, the fake delivers the payload to
    ``on_message`` synchronously (like the robot would).
    """

    def __init__(self, client_id: str, respond_with: dict | None = None):
        self.client_id = client_id
        self.ws_path = None
        self.ws_headers = None
        self.tls_kwargs = None
        self.host = None
        self.port = None
        self.connected = False
        self.subscriptions: list[str] = []
        self.published: list[dict] = []
        self.on_connect = None
        self.on_message = None
        self.on_disconnect = None
        self._respond_with = respond_with or {}

    def ws_set_options(self, path=None, headers=None):
        self.ws_path = path
        self.ws_headers = headers

    def tls_set(self, **kw):
        self.tls_kwargs = kw

    def connect(self, host, port=1883, keepalive=60, **kw):
        self.host = host
        self.port = port
        self.connected = True
        if self.on_connect:
            self.on_connect(self, None, None, 0)  # int rc == success
        return 0

    def loop_start(self):
        pass

    def loop_stop(self):
        pass

    def disconnect(self):
        self.connected = False

    def subscribe(self, topic, qos=0):
        self.subscriptions.append(topic)

    def publish(self, topic, payload, qos=0):
        self.published.append({"topic": topic, "payload": payload, "qos": qos})
        info = type("Info", (), {"rc": 0, "mid": len(self.published)})()
        if topic in self._respond_with:
            sub_topic, payload_out = self._respond_with[topic]
            if self.on_message:
                self.on_message(self, None, FakeMessage(sub_topic, payload_out))
        return info


def make_client(respond_with=None, **cfg_kw):
    cfg = SebMqttConfig(mqtt_endpoint=HOST, robot_id=ROBOT_ID, **cfg_kw)
    fake = FakeMqttClient(client_id="", respond_with=respond_with)

    def factory(cid):
        fake.client_id = cid
        return fake

    client = SebMqttClient(cfg, StubAuth(), client_factory=factory)
    return client, fake


# -- SigV4 signing ---------------------------------------------------------------------


def test_sign_websocket_url_known_vector():
    qs = sign_websocket_url(
        CREDS, region="eu-west-1", host=HOST, now=FIXED_NOW
    )
    assert (
        qs
        == "X-Amz-Algorithm=AWS4-HMAC-SHA256"
        "&X-Amz-Credential=AKIDEXAMPLE%2F20261027%2Feu-west-1%2Fiotdata%2Faws4_request"
        "&X-Amz-Date=20261027T120000Z"
        "&X-Amz-SignedHeaders=host"
        "&X-Amz-Signature=1beeb9e516e965a7db565a9b00d75b3160ee370865f52fb787dd538f774f71d5"
        "&X-Amz-Security-Token=SESSIONTOKEN123"
    )


def test_sign_websocket_url_without_session_token():
    creds = IamCredentials(access_key_id="AK", secret_key="SK", session_token="")
    qs = sign_websocket_url(creds, region="eu-west-1", host=HOST, now=FIXED_NOW)
    assert "X-Amz-Security-Token" not in qs
    assert "X-Amz-Signature=" in qs


# -- connect ----------------------------------------------------------------------------


def test_connect_signs_url_and_sets_ws_options():
    client, fake = make_client()
    client.connect()
    assert client._connected is True
    assert fake.host == HOST
    assert fake.port == 443
    assert fake.ws_path.startswith("/mqtt?X-Amz-Algorithm=AWS4-HMAC-SHA256")
    assert "X-Amz-Signature=" in fake.ws_path
    assert "X-Amz-Security-Token=SESSIONTOKEN123" in fake.ws_path
    # mandatory handshake header
    assert fake.ws_headers == {"Sec-WebSocket-Protocol": "mqtt"}
    assert fake.tls_kwargs["cert_reqs"] is not None
    assert fake.client_id.startswith("#python-")


def test_connect_without_endpoint_raises():
    cfg = SebMqttConfig(robot_id=ROBOT_ID)  # no endpoint
    client = SebMqttClient(cfg, StubAuth(), client_factory=lambda cid: FakeMqttClient(cid))
    with pytest.raises(RowxplorerConnectionError, match="mqtt_endpoint"):
        client.connect()


# -- request/response --------------------------------------------------------------------


STATUS_PAYLOAD = {
    "status": "CHARGING",
    "method": "PAUSE",
    "battery": 100,
    "errorCode": None,
    "cleaningArea": 0,
    "cleaningTime": 0,
    "totalCleaningTime": 2152,
    "mapId": None,
    "startTimestamp": 1793037797756,
    "currentTimestamp": 1793097362507,
    "endTimestamp": -1,
    "accessories": [
        {"current": 100, "limit": 100, "name": "SIDE-BRUSH", "alert": True},
        {"current": 0, "limit": 100, "name": "MAIN-BRUSH", "alert": False},
    ],
}


def test_status_request_response():
    client, fake = make_client(
        respond_with={
            f"VAC001/{ROBOT_ID}/getStatus": (f"VAC001/{ROBOT_ID}/status", STATUS_PAYLOAD)
        }
    )
    out = client.status()
    assert out["status"] == "CHARGING"
    assert out["battery"] == 100
    # published "{}" QoS0 to the publication topic
    pub = fake.published[0]
    assert pub["topic"] == f"VAC001/{ROBOT_ID}/getStatus"
    assert pub["payload"] == b"{}"
    assert pub["qos"] == 0
    # subscribed to the subscription topic
    assert fake.subscriptions == [f"VAC001/{ROBOT_ID}/status"]


def test_history_request_response():
    client, _fake = make_client(
        respond_with={
            f"VAC001/{ROBOT_ID}/getHistory": (
                f"VAC001/{ROBOT_ID}/history",
                {"totalNumberOfClean": 42},
            )
        }
    )
    assert client.history()["totalNumberOfClean"] == 42


def test_request_timeout_raises():
    client, _fake = make_client()  # no response configured
    with pytest.raises(RowxplorerConnectionError, match="no response"):
        client.status(timeout=0.2)


def test_non_json_payload_wrapped():
    client, _fake = make_client(
        respond_with={
            f"VAC001/{ROBOT_ID}/getStatus": (f"VAC001/{ROBOT_ID}/status", "not-json")
        }
    )
    assert client.status() == {"raw": "not-json"}


# -- commands ------------------------------------------------------------------------------


def _last_command(fake) -> dict:
    pub = fake.published[-1]
    assert pub["topic"] == f"VAC001/{ROBOT_ID}/command"
    return json.loads(pub["payload"])


def test_go_home_payload():
    client, fake = make_client()
    out = client.go_home()
    assert out["published"] is True
    assert _last_command(fake) == {"method": "BACK_TO_DOCK"}


def test_stop_payload():
    client, fake = make_client()
    client.stop()
    assert _last_command(fake) == {"method": "PAUSE"}
    client.abort()
    assert _last_command(fake) == {"method": "PAUSE"}


def test_clean_all_payload():
    client, fake = make_client()
    client.clean_all()
    assert _last_command(fake) == {"method": "AUTO_CLEANING", "power": "NORMAL"}
    client.clean_all(method="SMART_CLEANING", power="STRONG")
    assert _last_command(fake) == {"method": "SMART_CLEANING", "power": "STRONG"}


def test_clean_spot_payload():
    client, fake = make_client()
    client.clean_spot()
    assert _last_command(fake) == {"method": "SPIRAL", "power": "STRONG"}


def test_localize_payload():
    client, fake = make_client()
    client.localize()
    assert _last_command(fake) == {"beep": "ON"}


def test_set_power_and_method_payloads():
    client, fake = make_client()
    client.set_power("SILENT")
    assert _last_command(fake) == {"power": "SILENT"}
    client.set_method("WALL_FOLLOW")
    assert _last_command(fake) == {"method": "WALL_FOLLOW"}


def test_clean_map_and_explore_not_implemented():
    client, _fake = make_client()
    with pytest.raises(NotImplementedError):
        client.clean_map(1)
    with pytest.raises(NotImplementedError):
        client.explore()


# -- raw passthrough ------------------------------------------------------------------------


def test_get_status_alias():
    client, _fake = make_client(
        respond_with={
            f"VAC001/{ROBOT_ID}/getStatus": (f"VAC001/{ROBOT_ID}/status", STATUS_PAYLOAD)
        }
    )
    assert client.get("status")["battery"] == 100


def test_post_command_passthrough():
    client, fake = make_client()
    client.post("command", method="PAUSE")
    assert _last_command(fake) == {"method": "PAUSE"}


# -- lifecycle --------------------------------------------------------------------------------


def test_context_manager_connects_and_disconnects():
    client, fake = make_client()
    with client as c:
        assert c._connected is True
    assert client._connected is False
    assert fake.connected is False


def test_disconnect_fails_pending_waiters():
    client, fake = make_client()
    client.connect()
    # start a request that will never be answered, then drop the connection
    import threading
    import time

    result = {}

    def do_request():
        try:
            client.status(timeout=5)
        except RowxplorerConnectionError as exc:
            result["error"] = str(exc)

    t = threading.Thread(target=do_request)
    t.start()
    time.sleep(0.1)  # let the request register its waiter
    fake.on_disconnect(fake, None, None, 0)
    t.join(timeout=5)
    assert "connection lost" in result.get("error", "")


# -- facade (RowxplorerClient.seb) -------------------------------------------------------------


def test_facade_seb_status():
    from rowxplorer_lib import RowxplorerClient

    fake = FakeMqttClient(
        client_id="",
        respond_with={
            f"VAC001/{ROBOT_ID}/getStatus": (f"VAC001/{ROBOT_ID}/status", STATUS_PAYLOAD)
        },
    )

    def factory(cid):
        fake.client_id = cid
        return fake

    client = RowxplorerClient.seb(
        auth=StubAuth(),
        mqtt_config=SebMqttConfig(mqtt_endpoint=HOST, robot_id=ROBOT_ID),
        client_factory=factory,
    )
    status = client.status()
    assert status.battery_level == 100
    assert status.execution_state == "CHARGING"
    assert status.method == "PAUSE"
    assert status.total_cleaning_time == 2152
    assert status.accessories[0]["name"] == "SIDE-BRUSH"
    assert status.is_cleaning is False


# -- multi-robot (robot_id / device selection) ------------------------------------------


def test_facade_seb_robot_id_override():
    from rowxplorer_lib import RowxplorerClient
    from rowxplorer_lib.seb_mqtt import SebMqttConfig

    client = RowxplorerClient.seb(
        auth=StubAuth(),
        mqtt_config=SebMqttConfig(mqtt_endpoint=HOST, robot_id="ORIGINAL"),
        robot_id="OVERRIDDEN",
    )
    assert client.transport.config.robot_id == "OVERRIDDEN"


def _patch_devices(monkeypatch, devices):
    monkeypatch.setattr(
        "rowxplorer_lib.seb_profile.list_devices",
        lambda auth, **kw: devices,
    )


def test_facade_seb_device_by_name_sets_product_id(monkeypatch):
    from rowxplorer_lib import RowxplorerClient
    from rowxplorer_lib.models import Device
    from rowxplorer_lib.seb_mqtt import SebMqttConfig

    _patch_devices(
        monkeypatch,
        [
            Device(name="Alpha", uuid="UUID-1", thing_type="VAC001"),
            Device(name="Beta", uuid="UUID-2", thing_type="VAC002"),
        ],
    )
    client = RowxplorerClient.seb(
        auth=StubAuth(),
        mqtt_config=SebMqttConfig(mqtt_endpoint=HOST, robot_id="ORIGINAL"),
        device="Beta",
    )
    assert client.transport.config.robot_id == "UUID-2"
    assert client.transport.config.product_id == "VAC002"


def test_facade_seb_device_by_uuid(monkeypatch):
    from rowxplorer_lib import RowxplorerClient
    from rowxplorer_lib.models import Device
    from rowxplorer_lib.seb_mqtt import SebMqttConfig

    _patch_devices(
        monkeypatch,
        [Device(name="Alpha", uuid="UUID-1", thing_type="VAC001")],
    )
    client = RowxplorerClient.seb(
        auth=StubAuth(),
        mqtt_config=SebMqttConfig(mqtt_endpoint=HOST, robot_id="ORIGINAL"),
        device="UUID-1",
    )
    assert client.transport.config.robot_id == "UUID-1"
    assert client.transport.config.product_id == "VAC001"


def test_facade_seb_device_substring_unique(monkeypatch):
    from rowxplorer_lib import RowxplorerClient
    from rowxplorer_lib.models import Device
    from rowxplorer_lib.seb_mqtt import SebMqttConfig

    _patch_devices(
        monkeypatch,
        [
            Device(name="Alpha", uuid="UUID-1"),
            Device(name="Beta", uuid="UUID-2"),
        ],
    )
    client = RowxplorerClient.seb(
        auth=StubAuth(),
        mqtt_config=SebMqttConfig(mqtt_endpoint=HOST),
        device="alp",  # unique substring of "Alpha"
    )
    assert client.transport.config.robot_id == "UUID-1"


def test_facade_seb_device_not_found(monkeypatch):
    from rowxplorer_lib import RobotNotFoundError, RowxplorerClient
    from rowxplorer_lib.models import Device
    from rowxplorer_lib.seb_mqtt import SebMqttConfig

    _patch_devices(monkeypatch, [Device(name="Alpha", uuid="UUID-1")])
    with pytest.raises(RobotNotFoundError, match="no device matching"):
        RowxplorerClient.seb(
            auth=StubAuth(),
            mqtt_config=SebMqttConfig(mqtt_endpoint=HOST),
            device="Nonexistent",
        )


def test_facade_seb_device_ambiguous(monkeypatch):
    from rowxplorer_lib import RobotNotFoundError, RowxplorerClient
    from rowxplorer_lib.models import Device
    from rowxplorer_lib.seb_mqtt import SebMqttConfig

    _patch_devices(
        monkeypatch,
        [
            Device(name="Alpha Prime", uuid="UUID-1"),
            Device(name="Alpha Jr", uuid="UUID-2"),
        ],
    )
    with pytest.raises(RobotNotFoundError, match="ambiguous"):
        RowxplorerClient.seb(
            auth=StubAuth(),
            mqtt_config=SebMqttConfig(mqtt_endpoint=HOST),
            device="Alpha",  # substring matches both, no exact name match
        )


# -- push updates --------------------------------------------------------------------------

STATUS_TOPIC = f"VAC001/{ROBOT_ID}/status"


def make_push_client(callback):
    cfg = SebMqttConfig(mqtt_endpoint=HOST, robot_id=ROBOT_ID)
    fake = FakeMqttClient(client_id="")
    client = SebMqttClient(
        cfg,
        StubAuth(),
        client_factory=lambda cid: fake,
        status_callback=callback,
    )
    return client, fake


def test_status_callback_subscribes_on_connect():
    pushed = []
    client, fake = make_push_client(pushed.append)
    client.connect()
    assert fake.subscriptions == [STATUS_TOPIC]
    # subscribing twice does not duplicate the subscription
    client.subscribe_status()
    assert fake.subscriptions == [STATUS_TOPIC]


def test_status_callback_receives_unsolicited_message():
    pushed = []
    client, fake = make_push_client(pushed.append)
    client.connect()
    fake.on_message(fake, None, FakeMessage(STATUS_TOPIC, STATUS_PAYLOAD))
    assert pushed == [STATUS_PAYLOAD]
    assert pushed[0]["battery"] == 100


def test_status_callback_ignores_request_responses():
    pushed = []
    cfg = SebMqttConfig(mqtt_endpoint=HOST, robot_id=ROBOT_ID)
    fake = FakeMqttClient(
        client_id="",
        respond_with={f"VAC001/{ROBOT_ID}/getStatus": (STATUS_TOPIC, STATUS_PAYLOAD)},
    )
    client = SebMqttClient(
        cfg,
        StubAuth(),
        client_factory=lambda cid: fake,
        status_callback=pushed.append,
    )
    out = client.status()
    assert out["battery"] == 100
    # the reply to our own request is consumed by the waiter, not the callback
    assert pushed == []


def test_status_callback_errors_do_not_break_the_network_thread():
    def boom(_data):
        raise RuntimeError("callback exploded")

    client, fake = make_push_client(boom)
    client.connect()
    fake.on_message(fake, None, FakeMessage(STATUS_TOPIC, STATUS_PAYLOAD))
    # still connected and usable
    assert client._connected is True


def test_status_subscription_is_renewed_after_reconnect():
    pushed = []
    client, fake = make_push_client(pushed.append)
    client.connect()
    client.disconnect()
    client.connect()
    assert fake.subscriptions == [STATUS_TOPIC, STATUS_TOPIC]
