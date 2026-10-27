"""Command-line interface for rowxplorer-lib.

Controls the robot over the SEB cloud (OAuth + Cognito + MQTT over WSS).

Two kinds of commands:

- ``login`` — one-off: signs in with your SEB/Rowenta account and prints the
  long-lived ``refresh_token`` (the only secret you need to store).
- robot commands (``status``, ``clean-all``, …) — need ``--seb`` and the
  ``IOT_*`` environment variables.

Examples::

    # 1) get your refresh_token (one-off)
    rowxplorer-lib login --user you@example.com --password SECRET

    # 2) control the robot (reads IOT_* env vars)
    rowxplorer-lib --seb status
    rowxplorer-lib --seb clean-all
    rowxplorer-lib --seb go-home
    rowxplorer-lib --seb stop
"""
from __future__ import annotations

import argparse
import json
import os
import sys

from . import RowxplorerClient


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="rowxplorer-lib", description=__doc__)
    p.add_argument(
        "--seb",
        action="store_true",
        help="use the SEB cloud (OAuth + Cognito + MQTT WSS); reads IOT_* env vars",
    )
    p.add_argument("--user", help="SEB/Rowenta account email (for login)")
    p.add_argument("--password", help="SEB/Rowenta account password (for login)")
    p.add_argument(
        "--device",
        help="target a specific robot by name or UUID (multi-robot accounts)",
    )
    p.add_argument(
        "command",
        choices=[
            "login",
            "status",
            "devices",
            "robot-id",
            "clean-all",
            "clean-spot",
            "stop",
            "abort",
            "go-home",
            "explore",
            "continue",
            "localize",
            "set-power",
            "set-method",
            "raw-get",
            "raw-post",
        ],
    )
    p.add_argument(
        "args",
        nargs="*",
        help="extra args (value for set-power/set-method; endpoint for raw-get/raw-post)",
    )
    return p


def _login(args: argparse.Namespace) -> int:
    """Run the full OAuth login and print the long-lived refresh_token."""
    from . import SebAuth, SebAuthConfig

    user = args.user or os.environ.get("SEB_USER", "")
    password = args.password or os.environ.get("SEB_PASS", "")
    if not (user and password):
        print(
            "error: login needs --user and --password (or SEB_USER/SEB_PASS env vars)",
            file=sys.stderr,
        )
        return 2
    auth = SebAuth(SebAuthConfig(user=user, password=password))
    try:
        tokens = auth.login()
    except Exception as exc:  # noqa: BLE001 - CLI boundary
        print(f"error: {exc}", file=sys.stderr)
        return 1
    if not tokens.refresh_token:
        print("error: login did not return a refresh_token", file=sys.stderr)
        return 1
    print("Login OK. Store this refresh_token (the only long-lived secret):")
    print(tokens.refresh_token)
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.command == "login":
        return _login(args)

    if not args.seb:
        print("error: use --seb (the only enabled transport)", file=sys.stderr)
        return 2
    client = RowxplorerClient.seb(device=args.device)

    cmd = args.command
    try:
        if cmd == "status":
            result = client.status()
            print(json.dumps(result.raw, indent=2, ensure_ascii=False))
        elif cmd == "devices":
            devs = client.list_devices()
            print(json.dumps([{"name": d.name, "uuid": d.uuid, "thing_type": d.thing_type, "appliance": d.appliance, "source": d.source} for d in devs], indent=2, ensure_ascii=False))
        elif cmd == "robot-id":
            print(json.dumps(client.get("robot_id"), indent=2, ensure_ascii=False))
        elif cmd == "clean-all":
            print(json.dumps(client.clean_all(), indent=2))
        elif cmd == "clean-spot":
            print(json.dumps(client.clean_spot(), indent=2))
        elif cmd == "stop":
            print(json.dumps(client.stop(), indent=2))
        elif cmd == "abort":
            print(json.dumps(client.abort(), indent=2))
        elif cmd == "go-home":
            print(json.dumps(client.go_home(), indent=2))
        elif cmd == "explore":
            print(json.dumps(client.explore(), indent=2))
        elif cmd == "continue":
            print(json.dumps(client.continue_cleaning(), indent=2))
        elif cmd == "localize":
            print(json.dumps(client.localize(), indent=2))
        elif cmd == "set-power":
            if not args.args:
                print("error: set-power needs a value (e.g. NORMAL, STRONG)", file=sys.stderr)
                return 2
            print(json.dumps(client.set_power(args.args[0]), indent=2))
        elif cmd == "set-method":
            if not args.args:
                print(
                    "error: set-method needs a value (e.g. AUTO_CLEANING, SPIRAL)",
                    file=sys.stderr,
                )
                return 2
            print(json.dumps(client.set_method(args.args[0]), indent=2))
        elif cmd == "raw-get":
            ep = args.args[0] if args.args else "status"
            print(json.dumps(client.get(ep), indent=2, ensure_ascii=False))
        elif cmd == "raw-post":
            ep = args.args[0] if args.args else "stop"
            print(json.dumps(client.post(ep), indent=2, ensure_ascii=False))
        else:  # pragma: no cover
            return 2
    except Exception as exc:  # noqa: BLE001 - CLI boundary
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
