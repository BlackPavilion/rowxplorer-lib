"""SEB account profile / device discovery.

The list of robots paired with a SEB account is *not* exposed through the
MQTT topics. After login the app fetches the user's DCP profile from the
SEB platform, which contains the household's products; each product carries
an ``iot.functionalId`` that is the robot UUID used in MQTT topics
(``VAC001/<uuid>/...``).

This module replicates that fetch.
"""
from __future__ import annotations

from typing import Any

import requests

from .exceptions import AuthenticationError
from .exceptions import ConnectionError as RowxplorerConnectionError
from .models import Device
from .seb_auth import SebAuth

DEFAULT_BRAND_API_KEY = "19UfOfJmK6365857UYNzjn427R6q1XFA"
DEFAULT_DCP_CONTEXT = "ROWENTA_ES"
DEFAULT_APP_VERSION = "10.0.0"
PROFILE_URL = "https://sebplatform.api.groupe-seb.com/common-api/profiles/me"


def fetch_profile(
    auth: SebAuth,
    *,
    dcp_context: str = DEFAULT_DCP_CONTEXT,
    brand_api_key: str = DEFAULT_BRAND_API_KEY,
    app_version: str = DEFAULT_APP_VERSION,
    timeout: float = 30.0,
) -> dict[str, Any]:
    """Fetch the SEB DCP profile for the authenticated account.

    Returns the raw JSON dict (contains ``household.products`` with the
    robot UUIDs).
    """
    access_token = auth.access_token()
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "Gseb-App-Version": app_version,
        "ApiKey": brand_api_key,
        "Authorization": "Bearer " + access_token,
        "Grant-Type": "RCUToken",
        "DCP-Context": dcp_context,
    }
    try:
        resp = auth.session.get(PROFILE_URL, headers=headers, timeout=timeout)
    except requests.RequestException as exc:
        raise RowxplorerConnectionError(f"profile request failed: {exc}") from exc
    if resp.status_code != 200:
        raise AuthenticationError(
            f"profile fetch failed (HTTP {resp.status_code}): {resp.text[:200]}"
        )
    try:
        return resp.json()
    except ValueError as exc:
        raise AuthenticationError(
            f"profile returned non-JSON: {resp.text[:200]}"
        ) from exc


def list_devices(
    auth: SebAuth,
    *,
    dcp_context: str = DEFAULT_DCP_CONTEXT,
    brand_api_key: str = DEFAULT_BRAND_API_KEY,
    app_version: str = DEFAULT_APP_VERSION,
    timeout: float = 30.0,
) -> list[Device]:
    """Return the robots registered in the account.

    Each :class:`Device` exposes the robot ``uuid`` (the value used as
    ``robot_id`` in MQTT topics) plus its display name, thing type and
    appliance id.
    """
    profile = fetch_profile(
        auth,
        dcp_context=dcp_context,
        brand_api_key=brand_api_key,
        app_version=app_version,
        timeout=timeout,
    )
    household = profile.get("household") or {}
    products = household.get("products") or []
    devices: list[Device] = []
    for product in products:
        if not isinstance(product, dict):
            continue
        iot = product.get("iot")
        if not isinstance(iot, dict) or not iot.get("functionalId"):
            # Not an IoT robot (or no UUID) -> skip.
            continue
        devices.append(Device.from_dict(product))
    return devices