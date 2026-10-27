"""rowxplorer-lib — control Rowenta X-Plorer 45 robots from Python.

Works with Rowenta X-Plorer serie 45 robot vacuums (and other Groupe SEB
robots on the same platform). The robot is controlled over the SEB cloud
(OAuth + Cognito + MQTT over WSS).
"""
from .client import RowxplorerClient
from .exceptions import (
    AuthenticationError,
    CommandError,
    RobotNotFoundError,
    RowxplorerError,
)
from .exceptions import (
    ConnectionError as RowxplorerConnectionError,
)
from .models import CleaningMode, Device, RobotStatus
from .seb_profile import fetch_profile, list_devices
from .seb_auth import IamCredentials, SebAuth, SebAuthConfig, SebTokens
from .seb_mqtt import SebMqttClient, SebMqttConfig

__version__ = "0.1.0"

__all__ = [
    "AuthenticationError",
    "CleaningMode",
    "Device",
    "CommandError",
    "IamCredentials",
    "RobotNotFoundError",
    "RobotStatus",
    "RowxplorerClient",
    "RowxplorerConnectionError",
    "RowxplorerError",
    "SebAuth",
    "SebAuthConfig",
    "SebMqttClient",
    "SebMqttConfig",
    "SebTokens",
    "fetch_profile",
    "list_devices",
    "__version__",
]
