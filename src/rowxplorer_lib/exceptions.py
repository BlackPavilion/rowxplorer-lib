"""Exception hierarchy for rowxplorer-lib."""
from __future__ import annotations


class RowxplorerError(Exception):
    """Base class for all rowxplorer-lib errors."""


class AuthenticationError(RowxplorerError):
    """Bad or missing credentials (Basic auth user_login / pltsk)."""


class RobotNotFoundError(RowxplorerError):
    """The robot could not be discovered or is not reachable."""


class ConnectionError(RowxplorerError):  # noqa: A001 - intentional shadow
    """Network / transport failure talking to the robot or the cloud."""


class CommandError(RowxplorerError):
    """The robot/cloud returned an error for a command.

    Attributes:
        error_code: robot ``error_code`` (if any).
        error_tag: robot ``error_tag`` (if any).
        error_message: robot ``error_message`` (if any).
    """

    def __init__(
        self,
        message: str,
        *,
        error_code: int | None = None,
        error_tag: str | None = None,
        error_message: str | None = None,
    ) -> None:
        super().__init__(message)
        self.error_code = error_code
        self.error_tag = error_tag
        self.error_message = error_message
